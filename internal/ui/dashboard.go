package ui

import (
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/audit"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/config"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/guard"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/policyhmac"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/session"
)

const (
	maxBatchHosts  = 16
	maxParallel    = 4
	auditExportCap = 2000
	dashRecent     = 8
	dashScan       = 40
)

func (s *service) dashboardAPI(w http.ResponseWriter, r *http.Request) {
	cfg, err := config.Load(s.dir)
	if err != nil {
		writeFail(w, err)
		return
	}
	hosts := 0
	for _, h := range cfg.Index() {
		if h.Host != nil {
			hosts++
		}
	}
	groups := 0
	for _, g := range cfg.Groups {
		if g != nil {
			groups++
		}
	}
	recent := newest(s.dir, audit.Filter{}, dashScan)
	failures := make([]audit.Record, 0)
	commands := make([]audit.Record, 0)
	for _, rec := range recent {
		if rec.Status != audit.StatusOK {
			if len(failures) < dashRecent {
				failures = append(failures, rec)
			}
		}
		if len(commands) < dashRecent {
			commands = append(commands, rec)
		}
	}
	stats, err := audit.Stat(s.dir)
	if err != nil {
		writeFail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "hosts": hosts, "groups": groups, "envs": len(cfg.Envs),
		"sessions": len(s.pool.List()), "recent": commands, "failures": failures,
		"audit": stats, "hmac": s.integrity(),
	})
}

func (s *service) hostDetailAPI(w http.ResponseWriter, r *http.Request) {
	alias := strings.TrimSpace(r.URL.Query().Get("alias"))
	if alias == "" {
		writeErr(w, http.StatusBadRequest, "alias is required")
		return
	}
	cfg, h, eff, err := s.hostPlan(alias)
	if err != nil {
		writeFail(w, err)
		return
	}
	view := map[string]any{
		"alias": h.Alias, "group": h.Group, "env": h.EnvName,
		"host": h.Host.Host, "port": h.Host.PortOrDefault(), "user": h.Host.User,
		"auth": authOf(h.Host), "tags": h.Host.Tags, "policy": h.Host.Policy,
		"default": cfg.Default == h.Alias,
	}
	fillRulesJSON(view, h.Host.Allow, h.Host.Deny, h.Host.Confirm)
	if h.GroupDef != nil {
		view["groupLabel"] = h.GroupDef.Label
		view["groupPolicy"] = h.GroupDef.Policy
	}
	if h.Env != nil {
		view["envLabel"] = h.Env.Label
		view["envColor"] = h.Env.Color
		view["maxMode"] = string(h.Env.MaxMode)
	}
	caps := eff.Caps()
	policy := map[string]any{
		"mode": string(eff.Mode), "modeClamped": eff.Clamped,
		"allowUniversal": eff.AllowAll, "allowEmpty": eff.AllowEmpty,
		"allow": eff.Allow, "deny": eff.Deny, "confirm": eff.Confirm,
		"capabilities": caps, "protectedPaths": eff.Protected, "warnings": eff.Warnings,
		"noDataOutflow": eff.NoDataOut,
	}
	var live []any
	for _, item := range s.pool.List() {
		if item.Alias == h.Alias {
			live = append(live, item)
		}
	}
	if live == nil {
		live = []any{}
	}
	recs := newest(s.dir, audit.Filter{Hosts: []string{h.Alias}}, 10)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "host": view, "policy": policy, "sessions": live, "audit": recs,
	})
}

func fillRulesJSON(view map[string]any, allow *[]string, deny, confirm []string) {
	if allow != nil {
		view["allowSet"] = true
		view["allow"] = append([]string(nil), (*allow)...)
	} else {
		view["allowSet"] = false
	}
	if len(deny) > 0 {
		view["deny"] = append([]string(nil), deny...)
	}
	if len(confirm) > 0 {
		view["confirm"] = append([]string(nil), confirm...)
	}
}

func (s *service) opsAPI(w http.ResponseWriter, r *http.Request) {
	stats, err := audit.Stat(s.dir)
	if err != nil {
		writeFail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "hmac": s.integrity(), "audit": stats,
		"cleanup": "only entries older than 30 days",
	})
}

func (s *service) integrity() map[string]any {
	view := map[string]any{"policySigned": false, "macPresent": false, "status": "unsigned"}
	cfg, rerr := config.ReadUnverified(s.dir)
	if cfg != nil {
		view["policySigned"] = cfg.PolicySigned
	}
	if _, err := os.Stat(policyhmac.MacPath(s.dir)); err == nil {
		view["macPresent"] = true
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		view["status"] = "error"
		view["error"] = err.Error()
		return view
	}
	if rerr != nil {
		view["status"] = "error"
		view["error"] = rerr.Error()
		return view
	}
	if err := policyhmac.Verify(s.dir, cfg); err != nil {
		switch {
		case errors.Is(err, policyhmac.ErrNeedsResign):
			view["status"] = "needs-resign"
		case errors.Is(err, policyhmac.ErrMissingMac):
			view["status"] = "missing"
		default:
			view["status"] = "mismatch"
		}
		view["error"] = err.Error()
		return view
	}
	if cfg != nil && (cfg.PolicySigned || view["macPresent"] == true) {
		view["status"] = "ok"
	}
	return view
}

func (s *service) settingsAPI(w http.ResponseWriter, r *http.Request) {
	cfg, err := config.Load(s.dir)
	if err != nil {
		writeFail(w, err)
		return
	}
	idle, maxLife := s.pool.Windows()
	rawIdle, rawMax := "", ""
	if cfg.Session != nil {
		rawIdle, rawMax = cfg.Session.Idle, cfg.Session.MaxLife
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true,
		"session": map[string]any{
			"idle": idle.String(), "maxLife": maxLife.String(),
			"idleConfig": rawIdle, "maxLifeConfig": rawMax,
		},
		"hmac": s.integrity(),
	})
}

func (s *service) settingsUpdateAPI(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Idle    *string `json:"idle"`
		MaxLife *string `json:"maxLife"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		writeFail(w, err)
		return
	}
	if body.Idle == nil && body.MaxLife == nil {
		writeErr(w, http.StatusBadRequest, "idle or maxLife is required")
		return
	}
	if body.Idle != nil {
		if _, err := session.ParseWindow(*body.Idle, session.DefaultIdle); err != nil {
			writeFail(w, err)
			return
		}
	}
	if body.MaxLife != nil {
		if _, err := session.ParseWindow(*body.MaxLife, session.DefaultMaxLife); err != nil {
			writeFail(w, err)
			return
		}
	}
	err := config.Update(s.dir, func(cfg *config.Config) error {
		if cfg.Session == nil {
			cfg.Session = &config.SessionDefaults{}
		}
		if body.Idle != nil {
			cfg.Session.Idle = strings.TrimSpace(*body.Idle)
		}
		if body.MaxLife != nil {
			cfg.Session.MaxLife = strings.TrimSpace(*body.MaxLife)
		}
		return nil
	})
	if err != nil {
		writeFail(w, err)
		return
	}
	cfg, err := config.Load(s.dir)
	if err != nil {
		writeFail(w, err)
		return
	}
	idleRaw, maxRaw := "", ""
	if cfg.Session != nil {
		idleRaw, maxRaw = cfg.Session.Idle, cfg.Session.MaxLife
	}
	idle, err := session.ParseWindow(idleRaw, session.DefaultIdle)
	if err != nil {
		writeFail(w, err)
		return
	}
	maxLife, err := session.ParseWindow(maxRaw, session.DefaultMaxLife)
	if err != nil {
		writeFail(w, err)
		return
	}
	if err := s.pool.SetWindows(idle, maxLife); err != nil {
		writeFail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "idle": idle.String(), "maxLife": maxLife.String()})
}

func (s *service) auditExportAPI(w http.ResponseWriter, r *http.Request) {
	f, err := filterFromQuery(r)
	if err != nil {
		writeFail(w, err)
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="audit.csv"`)
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"time", "status", "op", "host", "group", "env", "exit_code", "high_risk", "denied_by_policy", "command", "src", "dst", "reason", "actor"})
	n := 0
	errCap := errors.New("export cap")
	err = audit.List(s.dir, f, func(rec audit.Record) error {
		if n >= auditExportCap {
			return errCap
		}
		n++
		exit := ""
		if rec.ExitCode != nil {
			exit = strconv.Itoa(*rec.ExitCode)
		}
		return cw.Write([]string{
			rec.Time, rec.Status, rec.Op, rec.Host, rec.Group, rec.Env, exit,
			strconv.FormatBool(rec.HighRisk), strconv.FormatBool(rec.DeniedByPolicy),
			rec.Command, rec.Src, rec.Dst, rec.Reason, rec.Actor,
		})
	})
	if err != nil && !errors.Is(err, errCap) {
		return
	}
	cw.Flush()
}

func (s *service) batchExecAPI(w http.ResponseWriter, r *http.Request) {
	var body execIn
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		writeFail(w, err)
		return
	}
	aliases := uniqueAliases(body.Aliases)
	if len(aliases) == 0 {
		writeErr(w, http.StatusBadRequest, "aliases is required")
		return
	}
	if len(aliases) > maxBatchHosts {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf("at most %d hosts", maxBatchHosts))
		return
	}
	if strings.TrimSpace(body.Command) == "" {
		writeErr(w, http.StatusBadRequest, "command is required")
		return
	}
	cfg, err := config.Load(s.dir)
	if err != nil {
		writeFail(w, err)
		return
	}
	var hosts []config.ResolvedHost
	var envs []string
	for _, alias := range aliases {
		h, ok := cfg.Find(alias)
		if !ok {
			writeErr(w, http.StatusBadRequest, "unknown host "+alias)
			return
		}
		hosts = append(hosts, h)
		envs = append(envs, h.EnvName)
	}
	if guard.CrossEnv(envs) && !body.AllowCrossEnv {
		writeJSON(w, http.StatusForbidden, map[string]any{
			"ok": false, "error": "selection spans multiple environments; pass allowCrossEnv",
		})
		return
	}
	force := len(hosts) > 1 && guard.IncludesProd(envs)
	var denied []map[string]any
	var needConfirm []string
	var needOutflow bool
	var run []config.ResolvedHost
	for _, h := range hosts {
		eff, err := guard.Resolve(cfg, h, force)
		if err != nil {
			writeFail(w, err)
			return
		}
		dec := guard.Decide(eff, body.Command)
		if !dec.Allowed {
			why := decisionText(dec)
			s.writeAudit(h, audit.OpPolicyCheck, body.Command, "", "", audit.StatusDenied, 0, why, why, true, time.Now())
			denied = append(denied, map[string]any{"alias": h.Alias, "ok": false, "error": why, "status": audit.StatusDenied})
			continue
		}
		phrase := strings.TrimSpace(body.Confirm)
		if body.Confirms != nil {
			if v := strings.TrimSpace(body.Confirms[h.Alias]); v != "" {
				phrase = v
			}
		}
		if dec.NeedsConfirm && phrase != h.Alias {
			needConfirm = append(needConfirm, h.Alias)
			continue
		}
		if _, needs := guard.ExecOutflow(eff.NoDataOut, body.AllowOutflow); needs && body.OutflowConfirm != guard.OutflowPhrase {
			needOutflow = true
			continue
		}
		run = append(run, h)
	}
	if len(needConfirm) > 0 || needOutflow {
		payload := map[string]any{
			"ok": false, "needsConfirm": true, "aliases": needConfirm,
			"error": "type each host alias to confirm",
		}
		if needOutflow {
			payload["confirm"] = guard.OutflowPhrase
			payload["confirmField"] = "outflowConfirm"
			payload["error"] = "type outflow to return command output"
		}
		writeJSON(w, http.StatusConflict, payload)
		return
	}
	if len(denied) > 0 && !body.SkipDenied {
		writeJSON(w, http.StatusForbidden, map[string]any{
			"ok": false, "error": fmt.Sprintf("batch aborted, %d host(s) denied", len(denied)), "results": denied,
		})
		return
	}
	if len(run) == 0 {
		writeJSON(w, http.StatusForbidden, map[string]any{
			"ok": false, "error": "every selected host was denied", "results": denied,
		})
		return
	}
	parallel := body.Parallel
	if parallel < 1 {
		parallel = 1
	}
	if parallel > maxParallel {
		parallel = maxParallel
	}
	results := make([]map[string]any, len(run))
	sem := make(chan struct{}, parallel)
	var wg sync.WaitGroup
	for i, h := range run {
		wg.Add(1)
		go func(i int, h config.ResolvedHost) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			hit := s.execOne(r.Context(), execIn{
				Alias: h.Alias, Command: body.Command, Timeout: body.Timeout,
				Confirm: body.Confirm, Confirms: body.Confirms, AllowOutflow: body.AllowOutflow,
				OutflowConfirm: body.OutflowConfirm,
			}, force)
			if hit.payload == nil {
				hit.payload = map[string]any{"ok": false, "alias": h.Alias}
			}
			hit.payload["httpStatus"] = hit.status
			results[i] = hit.payload
		}(i, h)
	}
	wg.Wait()
	if denied != nil {
		results = append(denied, results...)
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "parallel": parallel, "results": results})
}

func uniqueAliases(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, alias := range in {
		alias = strings.TrimSpace(alias)
		if alias == "" || seen[alias] {
			continue
		}
		seen[alias] = true
		out = append(out, alias)
	}
	sort.Strings(out)
	return out
}

func newest(dir string, f audit.Filter, limit int) []audit.Record {
	recs, err := audit.ListNewest(dir, f, limit)
	if err != nil || recs == nil {
		return []audit.Record{}
	}
	return recs
}
