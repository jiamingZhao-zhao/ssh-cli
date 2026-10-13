package ui

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/audit"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/config"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/exitcode"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/guard"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/transfer"
)

func (s *service) listAPI(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	var body struct {
		Alias   string `json:"alias"`
		Path    string `json:"path"`
		Confirm string `json:"confirm"`
		Source  string `json:"source"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&body); err != nil {
		writeFail(w, err)
		return
	}
	_ = body.Source
	remotePath, err := transfer.CleanListPath(body.Path)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	_, h, eff, err := s.hostPlan(body.Alias)
	if err != nil {
		writeFail(w, err)
		return
	}
	// noDataOut always applies. The ls text check is skipped only for a
	// loopback page probe; --allow-non-loopback turns that exemption off.
	if eff.NoDataOut || !s.workspaceProbeExempt(r) {
		dec := listDecision(eff)
		if !dec.Allowed {
			text := decisionText(dec)
			s.writeAudit(w, h, audit.OpPolicyCheck, "ls", remotePath, "", audit.StatusDenied, exitcode.Denied, text, text, true, started)
			writeJSON(w, http.StatusForbidden, map[string]any{"ok": false, "error": text, "status": "denied"})
			return
		}
		if dec.NeedsConfirm && strings.TrimSpace(body.Confirm) != h.Alias {
			writeJSON(w, http.StatusConflict, map[string]any{
				"ok": false, "needsConfirm": true, "confirm": h.Alias, "error": "type the host alias to confirm",
			})
			return
		}
	}
	s.reconcile()
	fp := s.fingerprint(h)
	ctx := r.Context()
	if err := s.pool.OpenConn(ctx, h.Alias, fp); err != nil {
		s.writeAudit(w, h, audit.OpList, "ls", remotePath, "", audit.StatusError, 1, err.Error(), err.Error(), false, started)
		writeFail(w, err)
		return
	}
	var listing transfer.Listing
	err = s.pool.Use(h.Alias, fp, func() error {
		client, ok := s.pool.Client(h.Alias, fp)
		if !ok {
			return fmt.Errorf("session %s is not open", h.Alias)
		}
		var lerr error
		listing, lerr = transfer.List(client, remotePath)
		return lerr
	})
	if err != nil {
		s.writeAudit(w, h, audit.OpList, "ls", remotePath, "", audit.StatusError, 1, err.Error(), err.Error(), false, started)
		writeFail(w, err)
		return
	}
	if listing.Entries == nil {
		listing.Entries = []transfer.FileEntry{}
	}
	if listing.Crumbs == nil {
		listing.Crumbs = []transfer.Crumb{}
	}
	s.writeAudit(w, h, audit.OpList, "ls", listing.Path, "", audit.StatusOK, 0, fmt.Sprintf("path=%s entries=%d", listing.Path, len(listing.Entries)), "", false, started)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "alias": h.Alias, "path": listing.Path, "parent": listing.Parent,
		"home":   listing.Home,
		"crumbs": listing.Crumbs, "entries": listing.Entries, "truncated": listing.Truncated,
	})
}

func (s *service) fileChangeAPI(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	var body struct {
		Alias   string `json:"alias"`
		Op      string `json:"op"`
		Path    string `json:"path"`
		Name    string `json:"name"`
		Confirm string `json:"confirm"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&body); err != nil {
		writeFileChangeError(w, err, "not_started")
		return
	}
	op := strings.TrimSpace(body.Op)
	switch op {
	case "mkdir", "touch", "rename", "remove":
	default:
		writeFileChangeError(w, fmt.Errorf("未知操作"), "not_started")
		return
	}
	_, h, eff, err := s.hostPlan(body.Alias)
	if err != nil {
		writeFileChangeError(w, err, "not_started")
		return
	}
	lexical, err := lexicalFileTargets(op, body.Path, body.Name)
	if err != nil {
		writeFileChangeError(w, err, "not_started")
		return
	}
	// Absolute paths are checked before dialing. Relative paths and ~/ are
	// checked again after the remote home and symlinks are resolved.
	if !s.finishFileChange(w, h, eff, op, lexical, nil, body.Confirm, body.Path, started) {
		return
	}
	s.reconcile()
	fp := s.fingerprint(h)
	if err := s.pool.OpenConn(r.Context(), h.Alias, fp); err != nil {
		s.writeAudit(w, h, audit.OpFileChange, op, body.Path, "", audit.StatusError, 1, err.Error(), err.Error(), false, started)
		writeFileChangeError(w, err, "not_started")
		return
	}
	var changed string
	err = s.pool.Use(h.Alias, fp, func() error {
		client, ok := s.pool.Client(h.Alias, fp)
		if !ok {
			return fmt.Errorf("session %s is not open", h.Alias)
		}
		primary, cerr := transfer.ChangeChecked(client, op, body.Path, body.Name, eff.Protected, func(targets, protected []string) error {
			dec := guard.DecideFileChange(eff, op, targets, protected)
			if !dec.Allowed {
				return capabilityError(decisionText(dec))
			}
			if dec.NeedsConfirm && strings.TrimSpace(body.Confirm) != h.Alias {
				return errNeedConfirm{}
			}
			return nil
		})
		changed = primary
		return cerr
	})
	if err != nil {
		var denied capabilityError
		if errors.As(err, &denied) {
			s.writeAudit(w, h, audit.OpPolicyCheck, op, body.Path, changed, audit.StatusDenied, exitcode.Denied, denied.Error(), denied.Error(), true, started)
			writeJSON(w, http.StatusForbidden, map[string]any{"ok": false, "error": denied.Error(), "status": "denied", "outcome": "not_started"})
			return
		}
		var confirm errNeedConfirm
		if errors.As(err, &confirm) {
			writeJSON(w, http.StatusConflict, map[string]any{
				"ok": false, "needsConfirm": true, "confirm": h.Alias, "error": confirm.Error(), "outcome": "not_started",
			})
			return
		}
		s.writeAudit(w, h, audit.OpFileChange, op, body.Path, changed, audit.StatusError, 1, err.Error(), err.Error(), false, started)
		writeFileChangeError(w, err, "unknown")
		return
	}
	if changed == "" {
		changed = body.Path
	}
	s.writeAudit(w, h, audit.OpFileChange, op, body.Path, changed, audit.StatusOK, 0, op+" "+changed, "", false, started)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "path": changed, "outcome": "completed"})
}

func writeFileChangeError(w http.ResponseWriter, err error, outcome string) {
	writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error(), "outcome": outcome, "retrySafe": false})
}

type errNeedConfirm struct{}

func (errNeedConfirm) Error() string { return "type the host alias to confirm" }

func (s *service) finishFileChange(w http.ResponseWriter, h config.ResolvedHost, eff guard.Effective, op string, targets, protected []string, confirm, remote string, started time.Time) bool {
	dec := guard.DecideFileChange(eff, op, targets, protected)
	if !dec.Allowed {
		text := decisionText(dec)
		s.writeAudit(w, h, audit.OpPolicyCheck, op, remote, "", audit.StatusDenied, exitcode.Denied, text, text, true, started)
		writeJSON(w, http.StatusForbidden, map[string]any{"ok": false, "error": text, "status": "denied", "outcome": "not_started"})
		return false
	}
	if dec.NeedsConfirm && strings.TrimSpace(confirm) != h.Alias {
		writeJSON(w, http.StatusConflict, map[string]any{
			"ok": false, "needsConfirm": true, "confirm": h.Alias, "error": "type the host alias to confirm", "outcome": "not_started",
		})
		return false
	}
	return true
}

// lexicalFileTargets returns absolute paths that can be classified without a
// remote home. Relative paths and ~/ return no paths; the caller resolves them
// after connect. Name validation still runs.
func lexicalFileTargets(op, remote, name string) ([]string, error) {
	remote = strings.TrimSpace(remote)
	if op == "mkdir" || op == "touch" || op == "rename" {
		if _, err := transfer.EntryName(name); err != nil {
			return nil, err
		}
	}
	slash := strings.ReplaceAll(remote, "\\", "/")
	slash = transfer.RestoreRemotePath(slash)
	if slash == "" || slash == "." || slash == "~" || strings.HasPrefix(slash, "~/") || !strings.HasPrefix(slash, "/") {
		return nil, nil
	}
	src, dest, err := transfer.PlanPaths("/", op, slash, name)
	if err != nil {
		return nil, err
	}
	var out []string
	if src != "" {
		out = append(out, src)
	}
	if dest != "" && dest != src {
		out = append(out, dest)
	}
	return out, nil
}

func listDecision(eff guard.Effective) guard.Decision {
	dec := guard.Decide(eff, "ls")
	if eff.NoDataOut {
		dec.Allowed = false
		dec.NeedsConfirm = false
		dec.Findings = append(dec.Findings, guard.Finding{
			Layer: "env", Kind: "deny", Detail: "noDataOutflow forbids listing remote files",
		})
	}
	return dec
}
