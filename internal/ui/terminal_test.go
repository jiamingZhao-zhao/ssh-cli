package ui

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/audit"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/sshtest"
)

func TestTerminalSkipsPolicyAndRejectsForgery(t *testing.T) {
	sshSrv, err := sshtest.Start("tester", "ui-secret", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		done := make(chan struct{})
		go func() {
			sshSrv.Close()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
	})
	host, port, err := net.SplitHostPort(sshSrv.Addr)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	h := Handler(dir, false)
	web := httptest.NewServer(h)
	t.Cleanup(web.Close)

	client := web.Client()
	csrf, cookie := uiSession(t, client, web.URL)
	post := func(path, body string, browser bool) *http.Response {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, web.URL+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-CSRF-Token", csrf)
		req.Header.Set("Cookie", cookie)
		if browser {
			browserFetch(req, web.URL)
		}
		res, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	mustOK := func(path, body string) {
		t.Helper()
		res := post(path, body, false)
		defer res.Body.Close()
		raw, _ := io.ReadAll(res.Body)
		if res.StatusCode != http.StatusOK {
			t.Fatalf("%s %d %s", path, res.StatusCode, raw)
		}
	}
	mustOK("/api/groups", `{"name":"app","env":"prod"}`)
	mustOK("/api/hosts", `{"alias":"box","group":"app","host":"`+host+`","port":`+port+`,"user":"tester","password":"ui-secret"}`)

	forged := post("/api/terminal/open", `{"alias":"box","source":"ui","cols":80,"rows":24}`, false)
	forgedBody, _ := io.ReadAll(forged.Body)
	forged.Body.Close()
	if forged.StatusCode != http.StatusForbidden {
		t.Fatalf("forged open %d %s", forged.StatusCode, forgedBody)
	}

	noCookie, err := http.NewRequest(http.MethodPost, web.URL+"/api/terminal/open", strings.NewReader(`{"alias":"box","source":"ui"}`))
	if err != nil {
		t.Fatal(err)
	}
	noCookie.Header.Set("Content-Type", "application/json")
	browserFetch(noCookie, web.URL)
	res, err := client.Do(noCookie)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("open without session %d", res.StatusCode)
	}

	denied := post("/api/exec", `{"alias":"box","command":"echo denied-by-policy","source":"ui","skipPolicy":true}`, false)
	deniedBody, _ := io.ReadAll(denied.Body)
	denied.Body.Close()
	if denied.StatusCode != http.StatusForbidden {
		t.Fatalf("ui exec should still deny echo on prod: %d %s", denied.StatusCode, deniedBody)
	}

	opened := post("/api/terminal/open", `{"alias":"box","cols":80,"rows":24,"source":"cli"}`, true)
	openBody, _ := io.ReadAll(opened.Body)
	opened.Body.Close()
	if opened.StatusCode != http.StatusOK {
		t.Fatalf("terminal open %d %s", opened.StatusCode, openBody)
	}
	var ticket struct {
		Ticket string `json:"ticket"`
	}
	if err := json.Unmarshal(openBody, &ticket); err != nil || ticket.Ticket == "" {
		t.Fatalf("ticket %v %s", err, openBody)
	}

	badHeader := browserSocket(web.URL, "ssh_cli_sid=not-the-browser-session")
	if _, err := dialWebSocket(web.URL+"/api/terminal/ws?ticket="+ticket.Ticket, badHeader); err == nil {
		t.Fatal("websocket accepted a cookie that did not mint the ticket")
	}

	ws, err := dialWebSocket(web.URL+"/api/terminal/ws?ticket="+ticket.Ticket, browserSocket(web.URL, cookie))
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	if err := ws.Write(wsBinary, []byte("echo ui-term-ok\n")); err != nil {
		t.Fatal(err)
	}
	_ = ws.c.SetReadDeadline(time.Now().Add(5 * time.Second))
	var got bytes.Buffer
	for !bytes.Contains(got.Bytes(), []byte("ui-term-ok")) {
		_, payload, err := ws.ReadMessage()
		if err != nil {
			t.Fatalf("pty output %v %q", err, got.String())
		}
		got.Write(payload)
	}
	_ = ws.Close()

	deadline := time.Now().Add(4 * time.Second)
	var recs []audit.Record
	for {
		recs = readAuditRecords(t, dir)
		if terminalClosed(recs) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("missing terminal close audit %#v", recs)
		}
		time.Sleep(40 * time.Millisecond)
	}
	var sawDeny, sawOpen, sawClose bool
	for _, rec := range recs {
		blob := rec.Command + "\n" + rec.ResultSummary + "\n" + rec.Reason
		if strings.Contains(blob, "ui-term-ok") {
			t.Fatalf("terminal keystroke logged: %#v", rec)
		}
		if rec.Op == audit.OpPolicyCheck && rec.Status == audit.StatusDenied && rec.Host == "box" {
			sawDeny = true
			if rec.Source != audit.SourceUI || !rec.DeniedByPolicy || !strings.Contains(rec.Command, "echo denied-by-policy") {
				t.Fatalf("denied exec %#v", rec)
			}
		}
		if rec.Op != audit.OpTerminal || rec.Host != "box" || rec.Source != audit.SourceUI || rec.Actor != "ui" {
			continue
		}
		if rec.Command != "pty" {
			t.Fatalf("terminal command %#v", rec)
		}
		switch rec.Reason {
		case "open":
			sawOpen = true
			if rec.Status != audit.StatusOK || !strings.Contains(rec.ResultSummary, "command policy not applied") {
				t.Fatalf("terminal open %#v", rec)
			}
		case "close":
			sawClose = true
			if rec.Status != audit.StatusOK || rec.DurationMS < 0 || !strings.Contains(rec.ResultSummary, "bytes_in=") || !strings.Contains(rec.ResultSummary, "bytes_out=") {
				t.Fatalf("terminal close %#v", rec)
			}
		}
	}
	if !sawDeny || !sawOpen || !sawClose {
		t.Fatalf("audit flags deny=%v open=%v close=%v %#v", sawDeny, sawOpen, sawClose, recs)
	}
}

func uiSession(t *testing.T, client *http.Client, base string) (string, string) {
	t.Helper()
	res, err := client.Get(base + "/api/session")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(res.Body)
		t.Fatalf("session %d %s", res.StatusCode, raw)
	}
	var body struct {
		CSRF string `json:"csrf"`
	}
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil || body.CSRF == "" {
		t.Fatal(err)
	}
	var cookie string
	for _, c := range res.Cookies() {
		if c.Name == sessionCookie && c.Value != "" {
			cookie = c.Name + "=" + c.Value
		}
	}
	if cookie == "" {
		t.Fatal("missing session cookie")
	}
	return body.CSRF, cookie
}

func browserFetch(req *http.Request, base string) {
	req.Header.Set("Origin", base)
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Mode", "cors")
}

func browserSocket(base, cookie string) http.Header {
	h := make(http.Header)
	h.Set("Origin", base)
	h.Set("Sec-Fetch-Site", "same-origin")
	h.Set("Sec-Fetch-Dest", "websocket")
	h.Set("Sec-Fetch-Mode", "websocket")
	if cookie != "" {
		h.Set("Cookie", cookie)
	}
	return h
}

func readAuditRecords(t *testing.T, dir string) []audit.Record {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(dir, "audit", "*.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	var out []audit.Record
	for _, name := range matches {
		b, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range bytes.Split(b, []byte("\n")) {
			line = bytes.TrimSpace(line)
			if len(line) == 0 {
				continue
			}
			var rec audit.Record
			if err := json.Unmarshal(line, &rec); err != nil {
				t.Fatal(err)
			}
			out = append(out, rec)
		}
	}
	return out
}

func TestTerminalBrowserFetchMetadataSplit(t *testing.T) {
	s := &service{sessions: map[string]string{"sid": "csrf-token"}}
	newReq := func(method string) *http.Request {
		t.Helper()
		req := httptest.NewRequest(method, "http://127.0.0.1:7788/api/terminal/ws", nil)
		req.RemoteAddr = "127.0.0.1:9"
		req.Host = "127.0.0.1:7788"
		req.Header.Set("Origin", "http://127.0.0.1:7788")
		req.AddCookie(&http.Cookie{Name: sessionCookie, Value: "sid"})
		return req
	}

	if !s.terminalBrowser(newReq(http.MethodGet), "websocket") {
		t.Fatal("websocket without Sec-Fetch metadata rejected")
	}

	noCookie := newReq(http.MethodGet)
	noCookie.Header.Del("Cookie")
	if s.terminalBrowser(noCookie, "websocket") {
		t.Fatal("websocket without session cookie accepted")
	}
	noOrigin := newReq(http.MethodGet)
	noOrigin.Header.Del("Origin")
	if s.terminalBrowser(noOrigin, "websocket") {
		t.Fatal("websocket without Origin accepted")
	}
	cross := newReq(http.MethodGet)
	cross.Header.Set("Origin", "http://evil.example")
	if s.terminalBrowser(cross, "websocket") {
		t.Fatal("websocket with foreign Origin accepted")
	}
	remote := newReq(http.MethodGet)
	remote.RemoteAddr = "203.0.113.8:9"
	if s.terminalBrowser(remote, "websocket") {
		t.Fatal("websocket from non-loopback accepted")
	}

	fetch := newReq(http.MethodPost)
	if s.terminalBrowser(fetch, "fetch") {
		t.Fatal("terminal open without Sec-Fetch metadata accepted")
	}
	fetch.Header.Set("Sec-Fetch-Site", "same-origin")
	fetch.Header.Set("Sec-Fetch-Dest", "empty")
	fetch.Header.Set("Sec-Fetch-Mode", "cors")
	fetch.Header.Set(csrfHeader, "csrf-token")
	if !s.terminalBrowser(fetch, "fetch") {
		t.Fatal("terminal open with browser fetch metadata rejected")
	}
	fetch.Header.Set("Sec-Fetch-Site", "cross-site")
	if s.terminalBrowser(fetch, "fetch") {
		t.Fatal("terminal open with cross-site Sec-Fetch-Site accepted")
	}
}

func TestTerminalWebSocketWithoutFetchMetadata(t *testing.T) {
	sshSrv, err := sshtest.Start("tester", "ui-secret", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		done := make(chan struct{})
		go func() {
			sshSrv.Close()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
	})
	host, port, err := net.SplitHostPort(sshSrv.Addr)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	h := Handler(dir, false)
	web := httptest.NewServer(h)
	t.Cleanup(web.Close)

	client := web.Client()
	csrf, cookie := uiSession(t, client, web.URL)
	post := func(path, body string, browser bool) *http.Response {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, web.URL+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-CSRF-Token", csrf)
		req.Header.Set("Cookie", cookie)
		if browser {
			browserFetch(req, web.URL)
		}
		res, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	mustOK := func(path, body string) {
		t.Helper()
		res := post(path, body, false)
		defer res.Body.Close()
		raw, _ := io.ReadAll(res.Body)
		if res.StatusCode != http.StatusOK {
			t.Fatalf("%s %d %s", path, res.StatusCode, raw)
		}
	}
	mustOK("/api/groups", `{"name":"app","env":"prod"}`)
	mustOK("/api/hosts", `{"alias":"box","group":"app","host":"`+host+`","port":`+port+`,"user":"tester","password":"ui-secret"}`)

	opened := post("/api/terminal/open", `{"alias":"box","cols":80,"rows":24}`, true)
	openBody, _ := io.ReadAll(opened.Body)
	opened.Body.Close()
	if opened.StatusCode != http.StatusOK {
		t.Fatalf("terminal open %d %s", opened.StatusCode, openBody)
	}
	var ticket struct {
		Ticket string `json:"ticket"`
	}
	if err := json.Unmarshal(openBody, &ticket); err != nil || ticket.Ticket == "" {
		t.Fatalf("ticket %v %s", err, openBody)
	}

	wsURL := web.URL + "/api/terminal/ws?ticket=" + ticket.Ticket
	originOnly := http.Header{}
	originOnly.Set("Origin", web.URL)
	if _, err := dialWebSocket(wsURL, originOnly); err == nil {
		t.Fatal("websocket without session cookie accepted")
	}
	cookieOnly := http.Header{}
	cookieOnly.Set("Cookie", cookie)
	if _, err := dialWebSocket(wsURL, cookieOnly); err == nil {
		t.Fatal("websocket without Origin accepted")
	}

	bare := http.Header{}
	bare.Set("Origin", web.URL)
	bare.Set("Cookie", cookie)
	for key := range bare {
		if strings.HasPrefix(key, "Sec-Fetch-") {
			t.Fatalf("upgrade header must omit fetch metadata, has %s", key)
		}
	}
	ws, err := dialWebSocket(wsURL, bare)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	if err := ws.Write(wsBinary, []byte("echo ui-term-nofetch\n")); err != nil {
		t.Fatal(err)
	}
	_ = ws.c.SetReadDeadline(time.Now().Add(5 * time.Second))
	var got bytes.Buffer
	for !bytes.Contains(got.Bytes(), []byte("ui-term-nofetch")) {
		_, payload, err := ws.ReadMessage()
		if err != nil {
			t.Fatalf("pty output %v %q", err, got.String())
		}
		got.Write(payload)
	}
}

func TestTerminalDialFailureWritesReason(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	h := Handler(dir, false)
	web := httptest.NewServer(h)
	t.Cleanup(web.Close)
	client := web.Client()
	csrf, cookie := uiSession(t, client, web.URL)
	post := func(path, body string, browser bool) *http.Response {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, web.URL+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-CSRF-Token", csrf)
		req.Header.Set("Cookie", cookie)
		if browser {
			browserFetch(req, web.URL)
		}
		res, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	mustOK := func(path, body string) {
		t.Helper()
		res := post(path, body, false)
		defer res.Body.Close()
		raw, _ := io.ReadAll(res.Body)
		if res.StatusCode != http.StatusOK {
			t.Fatalf("%s %d %s", path, res.StatusCode, raw)
		}
	}
	mustOK("/api/groups", `{"name":"app","env":"prod"}`)
	mustOK("/api/hosts", `{"alias":"down","group":"app","host":"`+host+`","port":`+port+`,"user":"tester","password":"ui-secret"}`)

	opened := post("/api/terminal/open", `{"alias":"down","cols":80,"rows":24}`, true)
	openBody, _ := io.ReadAll(opened.Body)
	opened.Body.Close()
	if opened.StatusCode != http.StatusOK {
		t.Fatalf("terminal open %d %s", opened.StatusCode, openBody)
	}
	var ticket struct {
		Ticket string `json:"ticket"`
	}
	if err := json.Unmarshal(openBody, &ticket); err != nil || ticket.Ticket == "" {
		t.Fatalf("ticket %v %s", err, openBody)
	}
	ws, err := dialWebSocket(web.URL+"/api/terminal/ws?ticket="+ticket.Ticket, browserSocket(web.URL, cookie))
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	_ = ws.c.SetReadDeadline(time.Now().Add(8 * time.Second))
	op, payload, err := ws.ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
	if op != wsText {
		t.Fatalf("opcode %d", op)
	}
	text := string(payload)
	if !strings.HasPrefix(text, "终端连接失败: ") || !strings.HasSuffix(text, "\r\n") || strings.Contains(text, "ui-secret") {
		t.Fatalf("failure frame %q", text)
	}
	reason := strings.TrimSuffix(strings.TrimPrefix(text, "终端连接失败: "), "\r\n")
	if reason == "" || strings.Contains(reason, "\n") {
		t.Fatalf("failure reason %q", text)
	}

	deadline := time.Now().Add(4 * time.Second)
	var recs []audit.Record
	for {
		recs = readAuditRecords(t, dir)
		if terminalConnectFailure(recs, reason) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("missing connect audit %#v frame %q", recs, text)
		}
		time.Sleep(40 * time.Millisecond)
	}
}

func TestTerminalUIDoesNotStickFalseBanner(t *testing.T) {
	dir := t.TempDir()
	h := Handler(dir, false)
	req := httptest.NewRequest(http.MethodGet, "/app.js", nil)
	req.RemoteAddr = "127.0.0.1:9"
	req.Host = "127.0.0.1"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("app.js %d", rr.Code)
	}
	script := rr.Body.String()
	msgAt := strings.Index(script, "ws.onmessage = (ev) => {")
	openAt := strings.Index(script, "ws.onopen = () => {")
	errAt := strings.Index(script, "ws.onerror = () => {")
	closeAt := strings.Index(script, "ws.onclose = (ev) => {")
	if msgAt < 0 || openAt < msgAt || errAt < openAt || closeAt < errAt {
		t.Fatal("mountTerm handlers out of order")
	}
	onmessage := script[msgAt:openAt]
	onopen := script[openAt:errAt]
	onerror := script[errAt:closeAt]
	end := closeAt + 500
	if end > len(script) {
		end = len(script)
	}
	onclose := script[closeAt:end]
	if !strings.Contains(onmessage, "entry.saw = true") || !strings.Contains(onmessage, `app.setError("terminal", "")`) {
		t.Fatalf("first message must clear the banner: %s", onmessage)
	}
	if strings.Contains(onopen, "setError") || strings.Contains(onopen, "entry.saw") {
		t.Fatalf("open must not mark success: %s", onopen)
	}
	if strings.Contains(onerror, "setError") || !strings.Contains(onerror, "entry.hadError = true") {
		t.Fatalf("error event must not raise the banner: %s", onerror)
	}
	if !strings.Contains(onclose, "!entry.saw") || !strings.Contains(onclose, `app.setError("terminal", "终端连接失败")`) || !strings.Contains(script, "终端连接已断开 (") {
		t.Fatalf("close copy: %s", onclose)
	}
}

func TestTerminalTabAliasIsNotNestedButton(t *testing.T) {
	dir := t.TempDir()
	h := Handler(dir, false)
	get := func(path string) string {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.RemoteAddr = "127.0.0.1:9"
		req.Host = "127.0.0.1"
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("%s %d", path, rr.Code)
		}
		return rr.Body.String()
	}
	body := get("/")
	start := strings.Index(body, `x-for="tab in termTabs"`)
	if start < 0 {
		t.Fatal("terminal tab template missing")
	}
	rest := body[start:]
	end := strings.Index(rest, "</template>")
	if end < 0 {
		t.Fatal("terminal tab template not closed")
	}
	chunk := rest[:end]
	for _, s := range []string{
		`class="term-tab"`,
		`:class="{ active: tab.id === termActive }"`,
		`x-text="tab.alias"`,
		`showPane(tab.id)`,
		`closeTab(tab.id)`,
		`class="term-tab-label"`,
		`class="term-tab-close"`,
		`关闭 `,
	} {
		if !strings.Contains(chunk, s) {
			t.Fatalf("tab chrome missing %s: %s", s, chunk)
		}
	}
	if strings.Contains(chunk, "btn") || strings.Contains(chunk, "text-white") {
		t.Fatalf("tab still uses .btn or text-white: %s", chunk)
	}
	for i := 0; i < len(chunk); {
		j := strings.Index(chunk[i:], "<button")
		if j < 0 {
			break
		}
		j += i
		k := strings.Index(chunk[j:], ">")
		if k < 0 {
			t.Fatal("unclosed button in terminal tab")
		}
		open := chunk[j : j+k]
		if strings.Contains(open, " btn") || strings.Contains(open, `class="btn`) {
			t.Fatalf("nested .btn paints a light face over the alias: %s", open)
		}
		i = j + k
	}
	style := get("/app.css")
	for _, s := range []string{".term-tab.active", ".term-tab button", ".term-tab-label", "background-color: transparent", "color: inherit", "#0052cc", "border-bottom-color"} {
		if !strings.Contains(style, s) {
			t.Fatalf("app.css missing %s", s)
		}
	}
}

func terminalConnectFailure(recs []audit.Record, reason string) bool {
	for _, rec := range recs {
		if rec.Op == audit.OpTerminal && rec.Host == "down" && rec.Status == audit.StatusConnect && rec.Reason == "open" && rec.ResultSummary == reason {
			return true
		}
	}
	return false
}

func terminalClosed(recs []audit.Record) bool {
	for _, rec := range recs {
		if rec.Op == audit.OpTerminal && rec.Reason == "close" {
			return true
		}
	}
	return false
}
