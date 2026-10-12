package ui

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/audit"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/config"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/exitcode"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/guard"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/metrics"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/sshclient"
)

func (s *service) probeRun(ctx context.Context, h config.ResolvedHost, command string) (string, string, int, error) {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	fp := s.fingerprint(h)
	if err := s.pool.OpenConn(ctx, h.Alias, fp); err != nil {
		return "", "", 0, err
	}
	var stdout, stderr limitBuf
	stdout.n, stderr.n = 1<<20, 64<<10
	code := 0
	err := s.pool.Use(h.Alias, fp, func() error {
		conn, ok := s.pool.Client(h.Alias, fp)
		if !ok {
			return errString("session closed")
		}
		var err error
		code, err = sshclient.RunChannel(ctx, conn, command, &stdout, &stderr, nil)
		return err
	})
	if ctx.Err() != nil {
		return "", "", code, ctx.Err()
	}
	return stdout.String(), stderr.String(), code, err
}

func (s *service) metricsAPI(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	var body struct {
		Alias  string `json:"alias"`
		Source string `json:"source"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&body); err != nil {
		writeFail(w, err)
		return
	}
	_ = body.Source
	_, h, eff, err := s.hostPlan(body.Alias)
	if err != nil {
		writeFail(w, err)
		return
	}
	if eff.NoDataOut {
		s.writeAudit(h, audit.OpMetrics, "metrics", "", "", audit.StatusDenied, exitcode.Denied, "noDataOutflow forbids metrics", "noDataOutflow forbids metrics", true, started)
		writeErr(w, http.StatusForbidden, "此环境禁止带回数据，概况不可用。")
		return
	}
	human := s.workspaceProbeExempt(r)
	s.reconcile()
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	snap, runErr := metrics.Collect(ctx, func(ctx context.Context, command string) (string, int, error) {
		stdout, _, code, err := s.probeRun(ctx, h, command)
		return stdout, code, err
	}, func(command string) error {
		if human {
			return nil
		}
		d := guard.Decide(eff, command)
		if !d.Allowed {
			return errString(decisionText(d))
		}
		return nil
	}, metrics.Options{Pause: 200 * time.Millisecond})
	if runErr != nil {
		s.writeAudit(h, audit.OpMetrics, "metrics", "", "", audit.StatusError, 1, runErr.Error(), runErr.Error(), false, started)
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"ok": false, "alias": h.Alias, "error": runErr.Error(), "connected": false,
			"address": h.Host.Host, "port": h.Host.PortOrDefault(), "user": h.Host.User,
			"procs": []any{}, "disks": []any{}, "notes": []string{},
		})
		return
	}
	s.writeAudit(h, audit.OpMetrics, "metrics", "", "", audit.StatusOK, 0, "metrics", "", false, started)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "alias": h.Alias, "connected": true,
		"address": h.Host.Host, "port": h.Host.PortOrDefault(), "user": h.Host.User,
		"group": h.Group, "env": h.EnvName,
		"hostname": snap.Hostname, "uptime": snap.Uptime, "load": snap.Load,
		"cpuPercent": snap.CPU, "mem": snap.Mem, "swap": snap.Swap,
		"procs": snap.Procs, "disks": snap.Disks,
		"netRx": snap.NetRx, "netTx": snap.NetTx, "netRxRate": snap.NetRxRate, "netTxRate": snap.NetTxRate,
		"notes": snap.Notes,
	})
}

func (s *service) procDetailAPI(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Alias  string `json:"alias"`
		PID    string `json:"pid"`
		Source string `json:"source"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&body); err != nil {
		writeFail(w, err)
		return
	}
	_ = body.Source
	argsCmd, cwdCmd, err := metrics.ProcCommands(body.PID)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	_, h, eff, err := s.hostPlan(body.Alias)
	if err != nil {
		writeFail(w, err)
		return
	}
	probe := s.workspaceProbeExempt(r)
	started := time.Now()
	if eff.NoDataOut {
		s.writeAudit(h, audit.OpMetrics, "proc", "", body.PID, audit.StatusDenied, exitcode.Denied, "noDataOutflow forbids process details", "noDataOutflow forbids process details", true, started)
		writeErr(w, http.StatusForbidden, "此环境禁止带回数据，进程详情不可用。")
		return
	}
	if !probe {
		for _, command := range []string{argsCmd, cwdCmd} {
			d := guard.Decide(eff, command)
			if !d.Allowed {
				text := decisionText(d)
				s.writeAudit(h, audit.OpPolicyCheck, "proc", "", strings.TrimSpace(body.PID), audit.StatusDenied, exitcode.Denied, text, text, true, started)
				writeJSON(w, http.StatusForbidden, map[string]any{"ok": false, "error": text, "status": "denied"})
				return
			}
		}
	}
	s.reconcile()
	ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
	defer cancel()
	run := func(command string) (string, string, error) {
		stdout, stderr, code, runErr := s.probeRun(ctx, h, command)
		if runErr != nil {
			return "", "", runErr
		}
		if code != 0 {
			note := strings.TrimSpace(stderr)
			if note == "" {
				note = strings.TrimSpace(stdout)
			}
			if note == "" {
				note = "unavailable"
			}
			return stdout, note, nil
		}
		return stdout, "", nil
	}
	pid := strings.TrimSpace(body.PID)
	argsOut, argsNote, err := run(argsCmd)
	if err != nil {
		s.writeAudit(h, audit.OpMetrics, "proc", "", pid, audit.StatusError, 1, err.Error(), err.Error(), false, started)
		writeFail(w, err)
		return
	}
	cwdOut, cwdNote, err := run(cwdCmd)
	if err != nil {
		s.writeAudit(h, audit.OpMetrics, "proc", "", pid, audit.StatusError, 1, err.Error(), err.Error(), false, started)
		writeFail(w, err)
		return
	}
	args := strings.TrimSpace(argsOut)
	cwd := metrics.ParseCwd(cwdOut)
	note := ""
	if cwd == "" {
		note = cwdNote
		if note == "" {
			note = "读不到工作目录"
		}
	}
	s.writeAudit(h, audit.OpMetrics, "proc", "", pid, audit.StatusOK, 0, "proc pid="+pid, "", false, started)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "alias": h.Alias, "pid": strings.TrimSpace(body.PID),
		"args": args, "cwd": cwd, "note": note, "argsNote": argsNote,
	})
}
