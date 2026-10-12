package ui

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/guard"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/metrics"
)

func (s *service) metricsAPI(w http.ResponseWriter, r *http.Request) {
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
	human := s.workspaceHuman(r)
	s.reconcile()
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	snap, runErr := metrics.Collect(ctx, func(ctx context.Context, command string) (string, int, error) {
		stdout, _, code, err := s.poolRun(ctx, h, command, 8*time.Second)
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
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"ok": false, "alias": h.Alias, "error": runErr.Error(), "connected": false,
			"address": h.Host.Host, "port": h.Host.PortOrDefault(), "user": h.Host.User,
			"procs": []any{}, "disks": []any{}, "notes": []string{},
		})
		return
	}
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
	human := s.workspaceHuman(r)
	s.reconcile()
	ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
	defer cancel()
	run := func(command string) (string, string, error) {
		if !human {
			d := guard.Decide(eff, command)
			if !d.Allowed {
				return "", "", errString(decisionText(d))
			}
		}
		stdout, stderr, code, runErr := s.poolRun(ctx, h, command, 8*time.Second)
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
	argsOut, argsNote, err := run(argsCmd)
	if err != nil {
		writeFail(w, err)
		return
	}
	cwdOut, cwdNote, err := run(cwdCmd)
	if err != nil {
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
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "alias": h.Alias, "pid": strings.TrimSpace(body.PID),
		"args": args, "cwd": cwd, "note": note, "argsNote": argsNote,
	})
}
