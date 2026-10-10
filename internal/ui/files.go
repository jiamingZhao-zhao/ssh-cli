package ui

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/guard"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/transfer"
)

func (s *service) listAPI(w http.ResponseWriter, r *http.Request) {
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
	if !s.workspaceHuman(r) {
		dec := listDecision(eff)
		if !dec.Allowed {
			writeJSON(w, http.StatusForbidden, map[string]any{"ok": false, "error": decisionText(dec), "status": "denied"})
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
		writeFail(w, err)
		return
	}
	if listing.Entries == nil {
		listing.Entries = []transfer.FileEntry{}
	}
	if listing.Crumbs == nil {
		listing.Crumbs = []transfer.Crumb{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "alias": h.Alias, "path": listing.Path, "parent": listing.Parent,
		"crumbs": listing.Crumbs, "entries": listing.Entries, "truncated": listing.Truncated,
	})
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
