package ui

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/config"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/guard"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/history"
)

func (s *service) historyAPI(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Alias          string `json:"alias"`
		Lines          int    `json:"lines"`
		Confirm        string `json:"confirm"`
		AllowOutflow   bool   `json:"allowOutflow"`
		OutflowConfirm string `json:"outflowConfirm"`
		Source         string `json:"source"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&body); err != nil {
		writeFail(w, err)
		return
	}
	// body.Source is ignored. Claiming source=ui does not skip policy.
	_ = body.Source
	n, err := history.ClampLines(body.Lines)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	_, h, eff, err := s.hostPlan(body.Alias)
	if err != nil {
		writeFail(w, err)
		return
	}
	human := s.workspaceHuman(r)
	suppress := false
	if !human {
		dec := history.PolicyDecision(eff, n)
		if !dec.Allowed {
			writeJSON(w, http.StatusForbidden, map[string]any{"ok": false, "error": decisionText(dec), "status": "denied"})
			return
		}
		if dec.NeedsConfirm && strings.TrimSpace(body.Confirm) != h.Alias {
			writeJSON(w, http.StatusConflict, map[string]any{
				"ok": false, "needsConfirm": true, "confirm": h.Alias, "alias": h.Alias,
				"error": "type the host alias to confirm",
			})
			return
		}
		var needsOut bool
		suppress, needsOut = guard.ExecOutflow(eff.NoDataOut, body.AllowOutflow)
		if needsOut && body.OutflowConfirm != guard.OutflowPhrase {
			writeJSON(w, http.StatusConflict, map[string]any{
				"ok": false, "needsConfirm": true, "confirm": guard.OutflowPhrase, "confirmField": "outflowConfirm",
				"alias": h.Alias, "error": "type outflow to return history lines",
			})
			return
		}
	}
	s.reconcile()
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	res, runErr := history.Collect(ctx, func(ctx context.Context, command string) (string, string, int, error) {
		return s.poolRun(ctx, h, command, 12*time.Second)
	}, func(command string) error {
		if human {
			return nil
		}
		d := guard.Decide(eff, command)
		if !d.Allowed {
			return errString(decisionText(d))
		}
		return nil
	}, history.Options{Lines: n})
	if runErr != nil {
		writeFail(w, runErr)
		return
	}
	lines := res.Lines
	notes := append([]string(nil), res.Notes...)
	if suppress {
		lines = []string{}
		notes = append(notes, guard.OutflowDiscarded)
	}
	if lines == nil {
		lines = []string{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "alias": h.Alias, "found": res.Found && !suppress, "status": res.Status,
		"path": res.Path, "shell": res.Shell, "lines": lines, "truncated": res.Truncated && !suppress,
		"notes": notes, "error": res.Error, "suppressed": suppress,
	})
}

func (s *service) poolRun(ctx context.Context, h config.ResolvedHost, command string, timeout time.Duration) (string, string, int, error) {
	if timeout <= 0 {
		timeout = 12 * time.Second
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var stdout, stderr limitBuf
	stdout.n, stderr.n = 1<<20, 64<<10
	code, err := s.pool.Exec(runCtx, h.Alias, h.Host.ConnFingerprint(), command, &stdout, &stderr)
	return stdout.String(), stderr.String(), code, err
}
