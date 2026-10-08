// Package ui is the optional localhost HTTP UI. It is not imported by exec,
// upload, download, or the audit log. Leaving it stopped does not change those paths.
package ui

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/audit"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/catalog"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/config"
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
	mux.HandleFunc("GET /api/known-hosts", s.knownHosts)
	mux.HandleFunc("POST /api/hosts", s.addHost)
	mux.HandleFunc("POST /api/hosts/update", s.updateHost)
	mux.HandleFunc("POST /api/hosts/remove", s.removeHost)
	mux.HandleFunc("POST /api/envs", s.addEnv)
	mux.HandleFunc("POST /api/envs/update", s.updateEnv)
	mux.HandleFunc("POST /api/envs/remove", s.removeEnv)
	mux.HandleFunc("POST /api/groups", s.addGroup)
	mux.HandleFunc("POST /api/groups/update", s.updateGroup)
	mux.HandleFunc("POST /api/groups/remove", s.removeGroup)
	mux.HandleFunc("POST /api/groups/set-env", s.setGroupEnv)
	mux.HandleFunc("POST /api/policies", s.addPolicy)
	mux.HandleFunc("POST /api/policies/update", s.updatePolicy)
	mux.HandleFunc("POST /api/policies/remove", s.removePolicy)
	mux.HandleFunc("POST /api/known-hosts/remove", s.removeKnownHost)
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
		NoDataOutflow bool   `json:"noDataOutflow,omitempty"`
	}
	type groupView struct {
		Name   string   `json:"name"`
		Env    string   `json:"env"`
		Policy string   `json:"policy,omitempty"`
		Hosts  int      `json:"hosts"`
		Paths  []string `json:"protectedPaths,omitempty"`
	}
	type hostView struct {
		Alias    string   `json:"alias"`
		Group    string   `json:"group"`
		Env      string   `json:"env"`
		Host     string   `json:"host"`
		Port     int      `json:"port"`
		User     string   `json:"user"`
		Auth     string   `json:"auth"`
		Identity string   `json:"identity,omitempty"`
		Policy   string   `json:"policy,omitempty"`
		Tags     []string `json:"tags,omitempty"`
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
			NoDataOutflow: e.NoDataOutflow,
		})
	}
	var groups []groupView
	for name, g := range cfg.Groups {
		if g == nil {
			continue
		}
		groups = append(groups, groupView{
			Name: name, Env: g.Env, Policy: g.Policy, Hosts: len(g.Hosts), Paths: g.ProtectedPaths,
		})
	}
	var hosts []hostView
	for alias, h := range cfg.Index() {
		if h.Host == nil {
			continue
		}
		hosts = append(hosts, hostView{
			Alias: alias, Group: h.Group, Env: h.EnvName,
			Host: h.Host.Host, Port: h.Host.PortOrDefault(), User: h.Host.User,
			Auth: authOf(h.Host), Identity: h.Host.Identity, Policy: h.Host.Policy,
			Tags: h.Host.Tags, Default: cfg.Default == alias,
		})
	}
	if envs == nil {
		envs = []envView{}
	}
	if groups == nil {
		groups = []groupView{}
	}
	if hosts == nil {
		hosts = []hostView{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"envs": envs, "groups": groups, "hosts": hosts, "policies": catalog.ListPolicies(cfg),
	})
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
	if err := catalog.AddHost(s.dir, draft, catalog.Options{}); err != nil {
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
	if err := catalog.UpdateHost(s.dir, draft, catalog.Options{}); err != nil {
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
	if err := catalog.RemoveHost(s.dir, draft.Alias, catalog.Options{}); err != nil {
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

func draftFromRequest(r *http.Request) (catalog.HostDraft, error) {
	if r.URL.Query().Has("password") || strings.Contains(r.URL.RawQuery, "password=") {
		return catalog.HostDraft{}, fmt.Errorf("password must be sent in the request body")
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return catalog.HostDraft{}, err
	}
	ct := r.Header.Get("Content-Type")
	if strings.Contains(ct, "json") || (len(body) > 0 && body[0] == '{') {
		var raw map[string]json.RawMessage
		if err := json.Unmarshal(body, &raw); err != nil {
			return catalog.HostDraft{}, fmt.Errorf("invalid JSON body")
		}
		return draftFromMap(raw)
	}
	r.Body = io.NopCloser(strings.NewReader(string(body)))
	if err := r.ParseForm(); err != nil {
		return catalog.HostDraft{}, err
	}
	raw := map[string]json.RawMessage{}
	for k, vals := range r.PostForm {
		if len(vals) == 0 {
			continue
		}
		b, err := json.Marshal(vals[0])
		if err != nil {
			return catalog.HostDraft{}, err
		}
		raw[k] = b
	}
	return draftFromMap(raw)
}

func draftFromMap(raw map[string]json.RawMessage) (catalog.HostDraft, error) {
	var d catalog.HostDraft
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
				return catalog.HostDraft{}, fmt.Errorf("invalid port")
			}
			parsed, err3 := strconv.Atoi(strings.TrimSpace(s))
			if err3 != nil {
				return catalog.HostDraft{}, fmt.Errorf("invalid port")
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
			return catalog.HostDraft{}, fmt.Errorf("invalid password")
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
				return catalog.HostDraft{}, fmt.Errorf("invalid tags")
			}
			d.Tags = splitCSV(s)
		}
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
