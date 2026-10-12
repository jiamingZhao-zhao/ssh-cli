package ui

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/config"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/guard"
)

func planDigest(cfg *config.Config, body execIn) string {
	body.OperationID, body.PlanDigest, body.Confirm, body.OutflowConfirm, body.Confirms = "", "", "", "", nil
	b, _ := json.Marshal(struct {
		Config  *config.Config
		Request execIn
	}{cfg, body})
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func (s *service) checkPlan(w http.ResponseWriter, body execIn) bool {
	if body.PlanDigest == "" {
		return true
	}
	cfg, err := config.Load(s.dir)
	if err != nil {
		writeFail(w, err)
		return false
	}
	if planDigest(cfg, body) != body.PlanDigest {
		writeJSON(w, 409, map[string]any{"ok": false, "planChanged": true, "error": "主机、策略或执行内容已变化，请重新预检。"})
		return false
	}
	return true
}

func (s *service) execPreviewAPI(w http.ResponseWriter, r *http.Request) {
	var body execIn
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		writeFail(w, err)
		return
	}
	aliases := uniqueAliases(body.Aliases)
	if len(aliases) == 0 && body.Alias != "" {
		aliases = []string{strings.TrimSpace(body.Alias)}
	}
	if len(aliases) == 0 || len(aliases) > maxBatchHosts || strings.TrimSpace(body.Command) == "" {
		writeErr(w, 400, "请选择 1–16 台主机并填写命令。")
		return
	}
	if body.Timeout != "" {
		d, err := time.ParseDuration(body.Timeout)
		if err != nil || d <= 0 || d > 5*time.Minute {
			writeErr(w, 400, "invalid timeout")
			return
		}
	}
	cfg, err := config.Load(s.dir)
	if err != nil {
		writeFail(w, err)
		return
	}
	hosts := make([]config.ResolvedHost, 0, len(aliases))
	envs := []string{}
	for _, alias := range aliases {
		h, ok := cfg.Find(alias)
		if !ok {
			writeErr(w, 400, "unknown host "+alias)
			return
		}
		hosts = append(hosts, h)
		envs = append(envs, h.EnvName)
	}
	crossDenied := guard.CrossEnv(envs) && !body.AllowCrossEnv
	force := len(hosts) > 1 && guard.IncludesProd(envs)
	rows := []map[string]any{}
	denied := 0
	for _, h := range hosts {
		eff, err := guard.Resolve(cfg, h, force)
		if err != nil {
			writeFail(w, err)
			return
		}
		dec := guard.Decide(eff, body.Command)
		allowed := dec.Allowed && !crossDenied
		if !allowed {
			denied++
		}
		_, outflowConfirm := guard.ExecOutflow(eff.NoDataOut, body.AllowOutflow)
		reason := ""
		if !dec.Allowed || dec.NeedsConfirm {
			reason = decisionText(dec)
		}
		if crossDenied {
			reason = "selection spans multiple environments"
		}
		rows = append(rows, map[string]any{"alias": h.Alias, "env": h.EnvName, "address": fmt.Sprintf("%s:%d", h.Host.Host, h.Host.PortOrDefault()), "user": h.Host.User, "mode": eff.Mode, "allowed": allowed, "needsConfirm": dec.NeedsConfirm, "outflowConfirm": outflowConfirm, "outputSuppressed": eff.NoDataOut && !body.AllowOutflow, "reason": reason, "findings": dec.Findings})
	}
	writeJSON(w, 200, map[string]any{"ok": true, "command": body.Command, "hosts": rows, "denied": denied, "canExecute": !crossDenied && (denied == 0 || (body.SkipDenied && denied < len(hosts))), "crossEnvDenied": crossDenied, "forceReadonly": force, "planDigest": planDigest(cfg, body), "notice": "预检不会连接或执行命令；执行时仍重新检查策略。"})
}
