// Package ui is the optional localhost HTTP UI. It is not imported by exec,
// upload, download, or the audit log. Leaving it stopped does not change those paths.
package ui

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/audit"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/config"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/guard"
)

//go:embed web/*
var webFS embed.FS

// Handler serves the embedded page and the local JSON API.
// When allowRemote is false, requests whose RemoteAddr is not loopback are rejected.
func Handler(dir string, allowRemote bool) http.Handler {
	s := &service{dir: dir, allowRemote: allowRemote}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/catalog", s.catalog)
	mux.HandleFunc("GET /api/audit", s.auditList)
	mux.HandleFunc("POST /api/hosts", s.addHost)
	mux.HandleFunc("POST /api/hosts/update", s.updateHost)
	mux.HandleFunc("POST /api/hosts/remove", s.removeHost)
	mux.HandleFunc("POST /api/groups", s.addGroup)
	mux.HandleFunc("POST /api/groups/update", s.updateGroup)
	mux.HandleFunc("POST /api/groups/remove", s.removeGroup)
	mux.HandleFunc("POST /api/groups/tags", s.groupTags)
	mux.HandleFunc("POST /api/policies", s.addPolicy)
	mux.HandleFunc("POST /api/policies/update", s.updatePolicy)
	mux.HandleFunc("POST /api/policies/remove", s.removePolicy)
	mux.HandleFunc("POST /api/envs", s.addEnv)
	mux.HandleFunc("POST /api/envs/update", s.updateEnv)
	mux.HandleFunc("POST /api/envs/remove", s.removeEnv)
	sub, err := fs.Sub(webFS, "web")
	if err != nil {
		panic(err)
	}
	files := http.FileServer(http.FS(sub))
	mux.Handle("GET /", files)
	return s.guard(mux)
}

// Serve listens until ctx is cancelled, then shuts the server down.
func Serve(ctx context.Context, addr, dir string, allowRemote bool) error {
	if ctx == nil {
		ctx = context.Background()
	}
	srv := &http.Server{
		Addr:              addr,
		Handler:           Handler(dir, allowRemote),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe() }()
	select {
	case <-ctx.Done():
		shut, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(shut)
		return nil
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

type service struct {
	dir         string
	allowRemote bool
}

func (s *service) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		if !s.allowRemote && !remoteLoopback(r.RemoteAddr) {
			http.Error(w, "localhost only", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func remoteLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (s *service) catalog(w http.ResponseWriter, r *http.Request) {
	cfg, err := config.Load(s.dir)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	type envView struct {
		Name          string `json:"name"`
		Label         string `json:"label,omitempty"`
		Color         string `json:"color,omitempty"`
		MaxMode       string `json:"maxMode"`
		DefaultPolicy string `json:"defaultPolicy,omitempty"`
		Builtin       bool   `json:"builtin,omitempty"`
	}
	type groupView struct {
		Name           string   `json:"name"`
		Env            string   `json:"env"`
		Hosts          int      `json:"hosts"`
		Policy         string   `json:"policy,omitempty"`
		Allow          []string `json:"allow,omitempty"`
		AllowSet       bool     `json:"allowSet"`
		Deny           []string `json:"deny,omitempty"`
		Confirm        []string `json:"confirm,omitempty"`
		ProtectedPaths []string `json:"protectedPaths,omitempty"`
	}
	type hostView struct {
		Alias    string   `json:"alias"`
		Group    string   `json:"group"`
		Env      string   `json:"env"`
		Host     string   `json:"host"`
		Port     int      `json:"port"`
		User     string   `json:"user"`
		Auth     string   `json:"auth"`
		Tags     []string `json:"tags,omitempty"`
		Policy   string   `json:"policy,omitempty"`
		Allow    []string `json:"allow,omitempty"`
		AllowSet bool     `json:"allowSet"`
		Deny     []string `json:"deny,omitempty"`
		Confirm  []string `json:"confirm,omitempty"`
		Default  bool     `json:"default,omitempty"`
	}
	var envs []envView
	for name, e := range cfg.Envs {
		if e == nil {
			continue
		}
		envs = append(envs, envView{
			Name: name, Label: e.Label, Color: e.Color,
			MaxMode: string(e.MaxMode), DefaultPolicy: e.DefaultPolicy,
			Builtin: config.IsBuiltinEnv(name),
		})
	}
	var groups []groupView
	for name, g := range cfg.Groups {
		if g == nil {
			continue
		}
		view := groupView{Name: name, Env: g.Env, Hosts: len(g.Hosts), Policy: g.Policy}
		fillRules(&view.Allow, &view.AllowSet, &view.Deny, &view.Confirm, g.Allow, g.Deny, g.Confirm)
		view.ProtectedPaths = append([]string(nil), g.ProtectedPaths...)
		groups = append(groups, view)
	}
	var hosts []hostView
	for alias, h := range cfg.Index() {
		if h.Host == nil {
			continue
		}
		view := hostView{
			Alias: alias, Group: h.Group, Env: h.EnvName,
			Host: h.Host.Host, Port: h.Host.PortOrDefault(), User: h.Host.User,
			Auth: authOf(h.Host), Tags: h.Host.Tags, Policy: h.Host.Policy,
			Default: cfg.Default == alias,
		}
		fillRules(&view.Allow, &view.AllowSet, &view.Deny, &view.Confirm, h.Host.Allow, h.Host.Deny, h.Host.Confirm)
		hosts = append(hosts, view)
	}
	policies := policyCatalog(cfg)
	if envs == nil {
		envs = []envView{}
	}
	if groups == nil {
		groups = []groupView{}
	}
	if hosts == nil {
		hosts = []hostView{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"envs": envs, "groups": groups, "hosts": hosts, "policies": policies})
}

type policyView struct {
	Name       string   `json:"name"`
	Builtin    bool     `json:"builtin"`
	Overridden bool     `json:"overridden,omitempty"`
	Mode       string   `json:"mode,omitempty"`
	Allow      []string `json:"allow,omitempty"`
	AllowSet   bool     `json:"allowSet"`
	Deny       []string `json:"deny,omitempty"`
	Confirm    []string `json:"confirm,omitempty"`
}

func fillRules(allow *[]string, allowSet *bool, deny, confirm *[]string, srcAllow *[]string, srcDeny, srcConfirm []string) {
	if srcAllow != nil {
		*allowSet = true
		*allow = append([]string(nil), (*srcAllow)...)
	}
	if len(srcDeny) > 0 {
		*deny = append([]string(nil), srcDeny...)
	}
	if len(srcConfirm) > 0 {
		*confirm = append([]string(nil), srcConfirm...)
	}
}

func policyCatalog(cfg *config.Config) []policyView {
	var out []policyView
	seen := map[string]bool{}
	for _, name := range guard.BuiltinNames() {
		seen[name] = true
		if cfg.Policies != nil {
			if p, ok := cfg.Policies[name]; ok && p != nil {
				out = append(out, policyViewFrom(name, p, true, true))
				continue
			}
		}
		if p, ok := guard.BuiltinPolicy(name); ok {
			out = append(out, policyViewFrom(name, p, true, false))
		}
	}
	var custom []string
	for name, p := range cfg.Policies {
		if p == nil || seen[name] {
			continue
		}
		custom = append(custom, name)
	}
	sort.Strings(custom)
	for _, name := range custom {
		out = append(out, policyViewFrom(name, cfg.Policies[name], false, false))
	}
	if out == nil {
		out = []policyView{}
	}
	return out
}

func policyViewFrom(name string, p *config.Policy, builtin, overridden bool) policyView {
	view := policyView{Name: name, Builtin: builtin, Overridden: overridden}
	if p == nil {
		return view
	}
	view.Mode = string(p.Mode)
	fillRules(&view.Allow, &view.AllowSet, &view.Deny, &view.Confirm, p.Allow, p.Deny, p.Confirm)
	return view
}

func (s *service) auditList(w http.ResponseWriter, r *http.Request) {
	f, err := filterFromQuery(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	recs, err := audit.ListNewest(s.dir, f, 200)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if recs == nil {
		recs = []audit.Record{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"records": recs})
}

func (s *service) addHost(w http.ResponseWriter, r *http.Request) {
	draft, err := draftFromRequest(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := AddHost(s.dir, draft); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *service) updateHost(w http.ResponseWriter, r *http.Request) {
	draft, err := draftFromRequest(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := UpdateHost(s.dir, draft); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *service) removeHost(w http.ResponseWriter, r *http.Request) {
	draft, err := draftFromRequest(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := RemoveHost(s.dir, draft.Alias); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func filterFromQuery(r *http.Request) (audit.Filter, error) {
	q := r.URL.Query()
	f := audit.Filter{
		Hosts:  splitCSV(q.Get("host")),
		Groups: splitCSV(q.Get("group")),
		Env:    strings.TrimSpace(q.Get("env")),
		Status: strings.TrimSpace(q.Get("status")),
	}
	if f.Status != "" && !audit.ValidStatus(f.Status) {
		return audit.Filter{}, fmt.Errorf("invalid status")
	}
	if s := strings.TrimSpace(q.Get("since")); s != "" {
		t, err := audit.ParseBound(s, false)
		if err != nil {
			return audit.Filter{}, err
		}
		f.Since, f.HasSince = t, true
	}
	if s := strings.TrimSpace(q.Get("until")); s != "" {
		t, err := audit.ParseBound(s, true)
		if err != nil {
			return audit.Filter{}, err
		}
		f.Until, f.HasUntil = t, true
	}
	return f, nil
}

func draftFromRequest(r *http.Request) (HostDraft, error) {
	raw, err := readRaw(r)
	if err != nil {
		return HostDraft{}, err
	}
	return draftFromMap(raw)
}

func draftFromMap(raw map[string]json.RawMessage) (HostDraft, error) {
	var d HostDraft
	if v, ok := raw["alias"]; ok {
		_ = json.Unmarshal(v, &d.Alias)
	}
	if v, ok := raw["group"]; ok {
		d.HasGroup = true
		_ = json.Unmarshal(v, &d.Group)
	}
	if v, ok := raw["host"]; ok {
		d.HasAddress = true
		_ = json.Unmarshal(v, &d.Address)
	}
	if v, ok := raw["port"]; ok {
		d.HasPort = true
		var n int
		if err := json.Unmarshal(v, &n); err != nil {
			var s string
			if err2 := json.Unmarshal(v, &s); err2 != nil {
				return HostDraft{}, fmt.Errorf("invalid port")
			}
			parsed, err3 := strconv.Atoi(strings.TrimSpace(s))
			if err3 != nil {
				return HostDraft{}, fmt.Errorf("invalid port")
			}
			n = parsed
		}
		d.Port = &n
	}
	if v, ok := raw["user"]; ok {
		d.HasUser = true
		_ = json.Unmarshal(v, &d.User)
	}
	if v, ok := raw["password"]; ok {
		d.HasPassword = true
		if err := json.Unmarshal(v, &d.Password); err != nil {
			return HostDraft{}, fmt.Errorf("invalid password")
		}
	}
	if v, ok := raw["identity"]; ok {
		d.HasIdentity = true
		_ = json.Unmarshal(v, &d.Identity)
	}
	if v, ok := raw["policy"]; ok {
		d.HasPolicy = true
		_ = json.Unmarshal(v, &d.Policy)
	}
	if v, ok := raw["tags"]; ok {
		d.HasTags = true
		var list []string
		if err := json.Unmarshal(v, &list); err == nil {
			d.Tags = list
		} else {
			var s string
			if err := json.Unmarshal(v, &s); err != nil {
				return HostDraft{}, fmt.Errorf("invalid tags")
			}
			d.Tags = splitCSV(s)
		}
	}
	if err := fillRuleFields(raw, &d.Allow, &d.Deny, &d.Confirm, &d.HasAllow, &d.HasDeny, &d.HasConfirm); err != nil {
		return HostDraft{}, err
	}
	if v, ok := raw["setDefault"]; ok {
		d.SetDefault = truthy(v)
	}
	if v, ok := raw["clearTags"]; ok {
		d.ClearTags = truthy(v)
	}
	return d, nil
}

func truthy(v json.RawMessage) bool {
	var b bool
	if json.Unmarshal(v, &b) == nil {
		return b
	}
	var s string
	if json.Unmarshal(v, &s) == nil {
		switch strings.ToLower(strings.TrimSpace(s)) {
		case "1", "true", "on", "yes":
			return true
		}
	}
	return false
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func authOf(h *config.Host) string {
	if h == nil {
		return "unset"
	}
	if h.Auth != "" {
		return h.Auth
	}
	if h.Identity != "" {
		return "key"
	}
	if h.PasswordRef != "" {
		return "password"
	}
	return "unset"
}

func (s *service) addGroup(w http.ResponseWriter, r *http.Request) {
	raw, err := readRaw(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	draft, err := groupFromMap(raw)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := AddGroup(s.dir, draft); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *service) updateGroup(w http.ResponseWriter, r *http.Request) {
	raw, err := readRaw(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	draft, err := groupFromMap(raw)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := UpdateGroup(s.dir, draft); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *service) removeGroup(w http.ResponseWriter, r *http.Request) {
	raw, err := readRaw(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	name, err := nameFromMap(raw)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := RemoveGroup(s.dir, name); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *service) groupTags(w http.ResponseWriter, r *http.Request) {
	raw, err := readRaw(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	group, add, remove, err := tagEditFromMap(raw)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := ApplyGroupTags(s.dir, group, add, remove); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *service) addPolicy(w http.ResponseWriter, r *http.Request) {
	s.writePolicy(w, r, AddPolicy)
}

func (s *service) updatePolicy(w http.ResponseWriter, r *http.Request) {
	s.writePolicy(w, r, UpdatePolicy)
}

func (s *service) writePolicy(w http.ResponseWriter, r *http.Request, fn func(string, PolicyDraft) error) {
	raw, err := readRaw(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	draft, err := policyFromMap(raw)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := fn(s.dir, draft); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *service) removePolicy(w http.ResponseWriter, r *http.Request) {
	raw, err := readRaw(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	name, err := nameFromMap(raw)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := RemovePolicy(s.dir, name); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *service) addEnv(w http.ResponseWriter, r *http.Request) {
	raw, err := readRaw(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	draft, err := envFromMap(raw)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if !draft.HasMaxMode {
		writeErr(w, http.StatusBadRequest, "maxMode must be readonly, standard, or admin")
		return
	}
	if err := AddEnv(s.dir, draft); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *service) updateEnv(w http.ResponseWriter, r *http.Request) {
	raw, err := readRaw(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	draft, err := envFromMap(raw)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := UpdateEnv(s.dir, draft); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *service) removeEnv(w http.ResponseWriter, r *http.Request) {
	raw, err := readRaw(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	name, err := nameFromMap(raw)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := RemoveEnv(s.dir, name); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]any{"ok": false, "error": msg})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}
