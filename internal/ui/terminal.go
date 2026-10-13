package ui

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/audit"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/config"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/exitcode"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/guard"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/sshclient"
)

const (
	termTicketTTL  = 45 * time.Second
	maxTermTickets = 32
	// maxLifeNotice is written to the terminal before the SSH client is closed.
	// The page matches this phrase and raises the banner and toast.
	maxLifeNotice = "\r\n会话已达到最长时限，连接已关闭。\r\n"
)

// termTicket is a one-time permit to open the unrestricted PTY.
// It is minted only after the localhost page proves it is the browser UI.
// A client-supplied source field is ignored and cannot mint this ticket.
type termTicket struct {
	sid   string
	alias string
	cols  int
	rows  int
	exp   time.Time
}

func (s *service) terminalOpen(w http.ResponseWriter, r *http.Request) {
	if !s.terminalBrowser(r, "fetch") {
		writeErr(w, http.StatusForbidden, "ui session required")
		return
	}
	var body struct {
		Alias  string `json:"alias"`
		Cols   int    `json:"cols"`
		Rows   int    `json:"rows"`
		Source string `json:"source"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&body); err != nil {
		writeFail(w, err)
		return
	}
	// body.Source is intentionally unused. Claiming source=ui does not skip policy
	// and does not authorize the PTY. terminalBrowser only identifies the page.
	_ = body.Source
	alias := strings.TrimSpace(body.Alias)
	_, h, eff, err := s.hostPlan(alias)
	if err != nil {
		writeFail(w, err)
		return
	}
	// Browser headers prove this is the localhost page. They are not a person,
	// and they do not skip env/group/host policy. Readonly, including prod,
	// cannot enforce its allow-list on a free shell.
	if !s.allowTerminal(w, h, eff, time.Now()) {
		return
	}
	sid := sessionID(r)
	ticket, err := s.mintTicket(sid, alias, clampDim(body.Cols, 80), clampDim(body.Rows, 24))
	if err != nil {
		writeFail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "ticket": ticket})
}

func (s *service) terminalWS(w http.ResponseWriter, r *http.Request) {
	if !s.terminalBrowser(r, "websocket") {
		writeErr(w, http.StatusForbidden, "ui session required")
		return
	}
	sid := sessionID(r)
	ticket, ok := s.takeTicket(sid, r.URL.Query().Get("ticket"))
	if !ok {
		writeErr(w, http.StatusForbidden, "ui session required")
		return
	}
	_, h, eff, err := s.hostPlan(ticket.alias)
	if err != nil {
		writeFail(w, err)
		return
	}
	if !s.allowTerminal(w, h, eff, time.Now()) {
		return
	}
	ws, err := acceptWebSocket(w, r)
	if err != nil {
		if errors.Is(err, errUpgrade) {
			writeErr(w, http.StatusBadRequest, "websocket upgrade required")
		}
		return
	}
	s.trackSocket(ws)
	defer s.forgetSocket(ws)
	defer ws.Close()
	s.bridgeTerminal(r, ws, h, ticket.cols, ticket.rows)
}

// terminalBrowser is the proof that this request came from the localhost page,
// not from the CLI or an agent HTTP client. A forged source header or JSON field
// is not consulted. Loopback is required even when the rest of the API is remote.
//
// kind fetch (the ticket POST) still requires same-origin Fetch Metadata and the
// CSRF token. kind websocket does not re-check Sec-Fetch-Site, Dest, or Mode.
// The one-time ticket was already minted by that POST, and browsers or embedded
// clients often omit Fetch Metadata on the upgrade. The upgrade still requires
// loopback, a non-empty Origin whose host equals Host and is allowed, and the
// session cookie that minted the ticket.
// workspaceHuman is the localhost page. A client-supplied source field is ignored.
// It is not a policy bypass. File changes, upload, and download always run
// capability checks, and those calls are audited with source=ui. Read-only
// probes skip per-command text policy only through workspaceProbeExempt.
// An interactive PTY is refused when the effective mode is readonly. Headers
// cannot authorize that shell.
func (s *service) workspaceHuman(r *http.Request) bool {
	return s.terminalBrowser(r, "fetch")
}

// workspaceProbeExempt reports whether a fixed read probe may skip per-command
// text policy. The exemption is the loopback page only. Binding the UI beyond
// loopback turns it off, so a forged browser proof cannot widen policy on an
// exposed listener. noDataOut, capability checks, and audit are never covered.
func (s *service) workspaceProbeExempt(r *http.Request) bool {
	if s.allowRemote {
		return false
	}
	return s.workspaceHuman(r)
}

func (s *service) allowTerminal(w http.ResponseWriter, h config.ResolvedHost, eff guard.Effective, started time.Time) bool {
	dec := guard.DecideTerminal(eff)
	if dec.Allowed {
		return true
	}
	text := decisionText(dec)
	s.writeAudit(w, h, audit.OpPolicyCheck, "pty", "", "", audit.StatusDenied, exitcode.Denied, text, text, true, started)
	writeJSON(w, http.StatusForbidden, map[string]any{"ok": false, "error": text, "status": "denied"})
	return false
}

func (s *service) terminalBrowser(r *http.Request, kind string) bool {
	if !remoteLoopback(r.RemoteAddr) {
		return false
	}
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		return false
	}
	ou, err := url.Parse(origin)
	if err != nil || ou.Host == "" || !strings.EqualFold(ou.Host, r.Host) || !hostAllowed(ou.Host) {
		return false
	}
	switch kind {
	case "fetch":
		if strings.ToLower(strings.TrimSpace(r.Header.Get("Sec-Fetch-Site"))) != "same-origin" {
			return false
		}
		dest := strings.ToLower(strings.TrimSpace(r.Header.Get("Sec-Fetch-Dest")))
		mode := strings.ToLower(strings.TrimSpace(r.Header.Get("Sec-Fetch-Mode")))
		return dest == "empty" && mode == "cors" && s.csrfOK(r)
	case "websocket":
		return sessionID(r) != ""
	default:
		return false
	}
}

func sessionID(r *http.Request) string {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return ""
	}
	return c.Value
}

func clampDim(n, def int) int {
	if n <= 0 {
		return def
	}
	if n < 2 {
		return 2
	}
	if n > 500 {
		return 500
	}
	return n
}

func (s *service) mintTicket(sid, alias string, cols, rows int) (string, error) {
	if sid == "" {
		return "", errNoUISession
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tickets == nil {
		s.tickets = map[string]termTicket{}
	}
	now := time.Now()
	for k, v := range s.tickets {
		if !now.Before(v.exp) {
			delete(s.tickets, k)
		}
	}
	if len(s.tickets) >= maxTermTickets {
		return "", errTooManyTerms
	}
	tok := newToken()
	s.tickets[tok] = termTicket{sid: sid, alias: alias, cols: cols, rows: rows, exp: now.Add(termTicketTTL)}
	return tok, nil
}

func (s *service) takeTicket(sid, tok string) (termTicket, bool) {
	tok = strings.TrimSpace(tok)
	if sid == "" || tok == "" {
		return termTicket{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tickets[tok]
	if !ok {
		return termTicket{}, false
	}
	if !time.Now().Before(t.exp) {
		delete(s.tickets, tok)
		return termTicket{}, false
	}
	if len(sid) != len(t.sid) || subtle.ConstantTimeCompare([]byte(sid), []byte(t.sid)) != 1 {
		return termTicket{}, false
	}
	delete(s.tickets, tok)
	return t, true
}

var (
	errNoUISession  = errString("ui session required")
	errTooManyTerms = errString("too many terminal sessions")
)

type errString string

func (e errString) Error() string { return string(e) }

func (s *service) trackTerm(alias string, ws *wsConn) {
	if s == nil || ws == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.terms == nil {
		s.terms = map[*wsConn]string{}
	}
	s.terms[ws] = alias
}

func (s *service) forgetTerm(ws *wsConn) {
	if s == nil || ws == nil {
		return
	}
	s.mu.Lock()
	delete(s.terms, ws)
	s.mu.Unlock()
}

// trackSocket records an upgraded WebSocket so process exit can close it.
// Hijacked connections are not closed by http.Server.Shutdown.
func (s *service) trackSocket(ws *wsConn) {
	if s == nil || ws == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sockets == nil {
		s.sockets = map[*wsConn]struct{}{}
	}
	s.sockets[ws] = struct{}{}
}

func (s *service) forgetSocket(ws *wsConn) {
	if s == nil || ws == nil {
		return
	}
	s.mu.Lock()
	delete(s.sockets, ws)
	s.mu.Unlock()
}

func (s *service) closeSockets() {
	if s == nil {
		return
	}
	s.mu.Lock()
	all := make([]*wsConn, 0, len(s.sockets))
	for ws := range s.sockets {
		all = append(all, ws)
	}
	s.mu.Unlock()
	for _, ws := range all {
		_ = ws.Close()
	}
}

// noteMaxLife runs before the pool closes the SSH client. The browser socket
// is still open here; the PTY bridge closes it only after the client dies.
func (s *service) noteMaxLife(alias, reason string) {
	if s == nil || reason != "max_life" {
		return
	}
	s.mu.Lock()
	var sinks []*wsConn
	for ws, name := range s.terms {
		if ws != nil && name == alias {
			sinks = append(sinks, ws)
		}
	}
	s.mu.Unlock()
	msg := []byte(maxLifeNotice)
	for _, ws := range sinks {
		_ = ws.Write(wsText, msg)
	}
}

func (s *service) bridgeTerminal(r *http.Request, ws *wsConn, h config.ResolvedHost, cols, rows int) {
	s.trackTerm(h.Alias, ws)
	defer s.forgetTerm(ws)
	fp := s.fingerprint(h)
	if err := s.pool.OpenConn(r.Context(), h.Alias, fp); err != nil {
		s.auditTerminal(ws, h, audit.StatusConnect, "open", err.Error(), time.Now(), 0, 0)
		writeTermFail(ws, err, execFailureStatus(r.Context(), err))
		return
	}
	var opened bool
	var started time.Time
	var inN, outN int64
	err := s.pool.Use(h.Alias, fp, func() error {
		raw, ok := s.pool.Client(h.Alias, fp)
		if !ok || raw == nil {
			return errString("session closed")
		}
		pty, err := sshclient.StartPTY(raw, cols, rows)
		if err != nil {
			return err
		}
		defer pty.Close()
		if err := writeTermState(ws, "ready", "", ""); err != nil {
			return err
		}
		opened = true
		s.auditTerminal(ws, h, audit.StatusOK, "open", "interactive terminal; command policy not applied", time.Now(), 0, 0)
		started = time.Now()
		inN, outN, err = bridgePTY(ws, pty)
		return err
	})
	if !opened {
		status := audit.StatusError
		if err == nil {
			err = errString("terminal did not start")
		}
		s.auditTerminal(ws, h, status, "open", err.Error(), time.Now(), 0, 0)
		writeTermFail(ws, err, "pty")
		return
	}
	status := audit.StatusOK
	reason := "close"
	if err != nil && !normalTermClose(err) {
		status = audit.StatusError
		reason = err.Error()
	}
	s.auditTerminal(ws, h, status, reason, "", started, inN, outN)
}

func (s *service) auditTerminal(ws *wsConn, h config.ResolvedHost, status, reason, summary string, started time.Time, inBytes, outBytes int64) {
	if summary == "" && (inBytes > 0 || outBytes > 0 || reason == "close") {
		summary = "interactive terminal closed; bytes_in=" + itoa(inBytes) + " bytes_out=" + itoa(outBytes)
	}
	rec := audit.Record{
		Op:            audit.OpTerminal,
		Host:          h.Alias,
		Group:         h.Group,
		Env:           h.EnvName,
		Command:       "pty",
		Status:        status,
		Reason:        reason,
		ResultSummary: summary,
		Actor:         "ui",
		Source:        audit.SourceUI,
		DurationMS:    time.Since(started).Milliseconds(),
	}
	if rec.DurationMS < 0 {
		rec.DurationMS = 0
	}
	if _, err := audit.Append(s.dir, rec); err != nil {
		_ = writeTermState(ws, "audit_warning", "audit", auditWarningText)
	}
}

// writeTermFail tells the browser why the PTY never started. The socket is
// already accepted, so a silent close looks like a healthy disconnect.
func writeTermFail(ws *wsConn, err error, category string) {
	if ws == nil || err == nil {
		return
	}
	msg := strings.TrimSpace(err.Error())
	msg = strings.ReplaceAll(msg, "\r\n", " ")
	msg = strings.ReplaceAll(msg, "\n", " ")
	msg = strings.ReplaceAll(msg, "\r", " ")
	_ = writeTermState(ws, "error", category, msg)
}

// Control messages use text frames; remote terminal output uses binary frames.
// A WebSocket upgrade alone does not mean SSH authentication or PTY startup succeeded.
func writeTermState(ws *wsConn, state, category, message string) error {
	payload, err := json.Marshal(map[string]string{"type": "terminal", "state": state, "category": category, "message": message})
	if err != nil {
		return err
	}
	return ws.Write(wsText, payload)
}

func itoa(n int64) string {
	if n < 0 {
		n = 0
	}
	return strconv.FormatInt(n, 10)
}

func normalTermClose(err error) bool {
	if err == nil || errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "websocket") && strings.Contains(msg, "close") || strings.Contains(msg, "closed") || strings.Contains(msg, "eof")
}

type resizeMsg struct {
	Type string `json:"type"`
	Cols int    `json:"cols"`
	Rows int    `json:"rows"`
}

func bridgePTY(ws *wsConn, pty *sshclient.PTY) (int64, int64, error) {
	stop := ws.armIdle(wsPingEvery, wsReadIdle, wsWriteWait)
	defer stop()
	var inN, outN atomic.Int64
	errCh := make(chan error, 2)
	go func() {
		buf := make([]byte, 32<<10)
		for {
			n, err := pty.Read(buf)
			if n > 0 {
				outN.Add(int64(n))
				if werr := ws.Write(wsBinary, buf[:n]); werr != nil {
					errCh <- werr
					return
				}
			}
			if err != nil {
				errCh <- err
				return
			}
		}
	}()
	go func() {
		for {
			op, payload, err := ws.ReadMessage()
			if err != nil {
				errCh <- err
				return
			}
			if op == wsText {
				if cols, rows, ok := parseResize(payload); ok {
					if err := pty.Resize(cols, rows); err != nil {
						errCh <- err
						return
					}
					continue
				}
			}
			if len(payload) == 0 {
				continue
			}
			inN.Add(int64(len(payload)))
			if _, err := pty.Write(payload); err != nil {
				errCh <- err
				return
			}
		}
	}()
	err := <-errCh
	_ = pty.Close()
	_ = ws.Close()
	select {
	case <-errCh:
	case <-time.After(2 * time.Second):
	}
	return inN.Load(), outN.Load(), err
}

func parseResize(p []byte) (int, int, bool) {
	var msg resizeMsg
	if json.Unmarshal(p, &msg) != nil || msg.Type != "resize" {
		return 0, 0, false
	}
	return clampDim(msg.Cols, 80), clampDim(msg.Rows, 24), true
}
