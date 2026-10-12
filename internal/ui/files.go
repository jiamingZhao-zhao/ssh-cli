package ui

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/audit"
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
			s.writeAudit(h, audit.OpPolicyCheck, "ls", remotePath, "", audit.StatusDenied, exitcode.Denied, text, text, true, started)
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
	fp := h.Host.ConnFingerprint()
	ctx := r.Context()
	if err := s.pool.OpenConn(ctx, h.Alias, fp); err != nil {
		s.writeAudit(h, audit.OpList, "ls", remotePath, "", audit.StatusError, 1, err.Error(), err.Error(), false, started)
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
		s.writeAudit(h, audit.OpList, "ls", remotePath, "", audit.StatusError, 1, err.Error(), err.Error(), false, started)
		writeFail(w, err)
		return
	}
	if listing.Entries == nil {
		listing.Entries = []transfer.FileEntry{}
	}
	if listing.Crumbs == nil {
		listing.Crumbs = []transfer.Crumb{}
	}
	s.writeAudit(h, audit.OpList, "ls", listing.Path, "", audit.StatusOK, 0, fmt.Sprintf("path=%s entries=%d", listing.Path, len(listing.Entries)), "", false, started)
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
		writeFail(w, err)
		return
	}
	op := strings.TrimSpace(body.Op)
	switch op {
	case "mkdir", "touch", "rename", "remove":
	default:
		writeErr(w, http.StatusBadRequest, "未知操作")
		return
	}
	_, h, eff, err := s.hostPlan(body.Alias)
	if err != nil {
		writeFail(w, err)
		return
	}
	target := strings.TrimSpace(body.Path)
	if op == "mkdir" || op == "touch" || op == "rename" {
		base, nerr := transfer.EntryName(body.Name)
		if nerr != nil {
			writeFail(w, nerr)
			return
		}
		if op == "rename" {
			target = path.Join(path.Dir(target), base)
		} else if target != "" {
			target = path.Join(target, base)
		}
	}
	if !s.requireCapability(w, h, eff, "upload", target, body.Confirm, op, started) {
		return
	}
	s.reconcile()
	fp := h.Host.ConnFingerprint()
	if err := s.pool.OpenConn(r.Context(), h.Alias, fp); err != nil {
		s.writeAudit(h, audit.OpFileChange, op, body.Path, target, audit.StatusError, 1, err.Error(), err.Error(), false, started)
		writeFail(w, err)
		return
	}
	err = s.pool.Use(h.Alias, fp, func() error {
		client, ok := s.pool.Client(h.Alias, fp)
		if !ok {
			return fmt.Errorf("session %s is not open", h.Alias)
		}
		return transfer.Change(client, op, body.Path, body.Name)
	})
	if err != nil {
		s.writeAudit(h, audit.OpFileChange, op, body.Path, target, audit.StatusError, 1, err.Error(), err.Error(), false, started)
		writeFail(w, err)
		return
	}
	s.writeAudit(h, audit.OpFileChange, op, body.Path, target, audit.StatusOK, 0, op+" "+target, "", false, started)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
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
