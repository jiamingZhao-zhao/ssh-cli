package ui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/config"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/guard"
)

func TestManageGroupsTagsAndPolicy(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "hosts.yaml"), []byte(`
version: 1
tasks:
  deploy:
    user: deploy
envs:
  prod:
    label: 生产
    color: red
    maxMode: readonly
    defaultPolicy: readonly
    breakGlass:
      enabled: true
      maxTtl: 30m
    noDataOutflow: true
groups:
  app-prod:
    env: prod
    hosts: {}
`), 0o600); err != nil {
		t.Fatal(err)
	}
	h := Handler(dir, false)
	password := "s3cret-ui"

	page := httptest.NewRequest(http.MethodGet, "/", nil)
	page.RemoteAddr = "127.0.0.1:9"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, page)
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), "标签只写在主机上") || !strings.Contains(rr.Body.String(), "危险命令") {
		t.Fatalf("index %d %s", rr.Code, rr.Body.String())
	}

	remote := httptest.NewRequest(http.MethodPost, "/api/groups", strings.NewReader(`{"name":"x","env":"prod"}`))
	remote.RemoteAddr = "192.0.2.10:9"
	remote.Header.Set("Content-Type", "application/json")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, remote)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("remote group %d %s", rr.Code, rr.Body.String())
	}

	q := postJSON(t, h, "/api/policies?password="+password, `{"name":"no-wget"}`)
	if q.Code != http.StatusBadRequest || strings.Contains(q.Body.String(), password) {
		t.Fatalf("query password %d %s", q.Code, q.Body.String())
	}

	env := postJSON(t, h, "/api/envs", `{"name":"test","label":"测试","maxMode":"admin","defaultPolicy":"admin"}`)
	if env.Code == 200 || !strings.Contains(env.Body.String(), "built-in") {
		t.Fatalf("builtin env add %d %s", env.Code, env.Body.String())
	}
	locked := postJSON(t, h, "/api/envs/update", `{"name":"prod","maxMode":"admin","defaultPolicy":"admin","label":"放开"}`)
	if locked.Code == 200 || !strings.Contains(locked.Body.String(), "built-in") {
		t.Fatalf("builtin env update %d %s", locked.Code, locked.Body.String())
	}
	rmEnv := postJSON(t, h, "/api/envs/remove", `{"name":"preprod"}`)
	if rmEnv.Code == 200 || !strings.Contains(rmEnv.Body.String(), "built-in") {
		t.Fatalf("builtin env remove %d %s", rmEnv.Code, rmEnv.Body.String())
	}
	custom := postJSON(t, h, "/api/envs", `{"name":"lab","label":"实验","color":"green","maxMode":"admin","defaultPolicy":"standard"}`)
	if custom.Code != 200 {
		t.Fatalf("custom env %d %s", custom.Code, custom.Body.String())
	}
	customEdit := postJSON(t, h, "/api/envs/update", `{"name":"lab","label":"实验二","color":"yellow","maxMode":"standard","defaultPolicy":"standard"}`)
	if customEdit.Code != 200 {
		t.Fatalf("custom env edit %d %s", customEdit.Code, customEdit.Body.String())
	}
	grp := postJSON(t, h, "/api/groups", `{
		"name":"app-test","env":"test","policy":"standard",
		"allow":[],"deny":["wget"],"confirm":["systemctl restart"],
		"protectedPaths":["/root/app"]
	}`)
	if grp.Code != 200 {
		t.Fatalf("group %d %s", grp.Code, grp.Body.String())
	}
	host := postJSON(t, h, "/api/hosts", `{
		"alias":"main","group":"app-test","host":"192.0.2.10","user":"viewer",
		"password":"`+password+`","tags":["web"],"deny":["curl"]
	}`)
	if host.Code != 200 || strings.Contains(host.Body.String(), password) {
		t.Fatalf("host %d %s", host.Code, host.Body.String())
	}
	tagged := postJSON(t, h, "/api/groups/tags", `{"group":"app-test","add":["app"]}`)
	if tagged.Code != 200 {
		t.Fatalf("tags %d %s", tagged.Code, tagged.Body.String())
	}
	pol := postJSON(t, h, "/api/policies", `{
		"name":"no-prune","mode":"standard",
		"deny":["docker system prune -a"],"confirm":["docker rm"]
	}`)
	if pol.Code != 200 {
		t.Fatalf("policy %d %s", pol.Code, pol.Body.String())
	}
	upd := postJSON(t, h, "/api/groups/update", `{"name":"app-test","policy":"no-prune"}`)
	if upd.Code != 200 {
		t.Fatalf("attach %d %s", upd.Code, upd.Body.String())
	}
	customGone := postJSON(t, h, "/api/envs/remove", `{"name":"lab"}`)
	if customGone.Code != 200 {
		t.Fatalf("custom env remove %d %s", customGone.Code, customGone.Body.String())
	}

	busy := postJSON(t, h, "/api/groups/remove", `{"name":"app-test"}`)
	if busy.Code == 200 || !strings.Contains(busy.Body.String(), "host") {
		t.Fatalf("remove busy group %d %s", busy.Code, busy.Body.String())
	}
	used := postJSON(t, h, "/api/policies/remove", `{"name":"no-prune"}`)
	if used.Code == 200 || !strings.Contains(used.Body.String(), "used") {
		t.Fatalf("remove used policy %d %s", used.Code, used.Body.String())
	}
	emptyTags := postJSON(t, h, "/api/groups/tags", `{"group":"app-prod","add":["app"]}`)
	if emptyTags.Code == 200 || !strings.Contains(emptyTags.Body.String(), "hosts") {
		t.Fatalf("tags on empty group %d %s", emptyTags.Code, emptyTags.Body.String())
	}

	catReq := httptest.NewRequest(http.MethodGet, "/api/catalog", nil)
	catReq.RemoteAddr = "127.0.0.1:9"
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, catReq)
	if strings.Contains(rr.Body.String(), password) {
		t.Fatal("catalog leaked password")
	}
	var cat struct {
		Hosts []struct {
			Alias string   `json:"alias"`
			Tags  []string `json:"tags"`
			Deny  []string `json:"deny"`
		} `json:"hosts"`
		Groups []struct {
			Name     string   `json:"name"`
			Policy   string   `json:"policy"`
			AllowSet bool     `json:"allowSet"`
			Deny     []string `json:"deny"`
		} `json:"groups"`
		Policies []struct {
			Name       string `json:"name"`
			Builtin    bool   `json:"builtin"`
			Overridden bool   `json:"overridden"`
		} `json:"policies"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &cat); err != nil {
		t.Fatal(err)
	}
	var sawHost bool
	for _, host := range cat.Hosts {
		if host.Alias != "main" {
			continue
		}
		sawHost = true
		if !containsAll(host.Tags, "app", "web") || !containsAll(host.Deny, "curl") {
			t.Fatalf("host view %+v", host)
		}
	}
	if !sawHost {
		t.Fatal("missing host")
	}
	var sawGroup bool
	for _, g := range cat.Groups {
		if g.Name != "app-test" {
			continue
		}
		sawGroup = true
		if g.Policy != "no-prune" || !g.AllowSet || !containsAll(g.Deny, "wget") {
			t.Fatalf("group view %+v", g)
		}
	}
	if !sawGroup {
		t.Fatal("missing group")
	}
	for _, p := range cat.Policies {
		if p.Name == "readonly" && (!p.Builtin || p.Overridden) {
			t.Fatalf("readonly policy %+v", p)
		}
		if p.Name == "no-prune" && (p.Builtin || p.Overridden) {
			t.Fatalf("custom policy %+v", p)
		}
	}

	cfg, err := config.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := cfg.Tasks["deploy"]; !ok {
		t.Fatal("tasks dropped")
	}
	if cfg.Envs["prod"].BreakGlass == nil || cfg.Envs["prod"].BreakGlass.MaxTTL != "30m" || !cfg.Envs["prod"].NoDataOutflow {
		t.Fatalf("env metadata changed: %+v", cfg.Envs["prod"])
	}
	if cfg.Envs["prod"].MaxMode != config.ModeReadonly || cfg.Envs["preprod"] == nil || cfg.Envs["preprod"].Color != "orange" {
		t.Fatalf("builtins drifted: prod=%+v preprod=%+v", cfg.Envs["prod"], cfg.Envs["preprod"])
	}
	if _, ok := cfg.Envs["lab"]; ok {
		t.Fatal("removed custom env is still present")
	}
	g := cfg.Groups["app-test"]
	if g.Allow == nil || len(*g.Allow) != 0 || g.ProtectedPaths[0] != "/root/app" {
		t.Fatalf("group rules %+v", g)
	}
	found, ok := cfg.Find("main")
	if !ok {
		t.Fatal("host missing")
	}
	eff, err := guard.Resolve(cfg, found, false)
	if err != nil {
		t.Fatal(err)
	}
	if !eff.AllowEmpty || !containsAll(eff.Deny, "wget", "curl", "docker system prune -a") {
		t.Fatalf("effective %+v", eff)
	}

	raw, err := os.ReadFile(filepath.Join(dir, "hosts.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), password) {
		t.Fatal("password stored in hosts.yaml")
	}
	var doc map[string]any
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	groups := doc["groups"].(map[string]any)
	stored := groups["app-test"].(map[string]any)
	if _, ok := stored["tags"]; ok {
		t.Fatal("group stored a tags field")
	}

	over := postJSON(t, h, "/api/policies", `{"name":"readonly","mode":"readonly","allow":["ls"],"deny":["wget"]}`)
	if over.Code != 200 {
		t.Fatalf("override %d %s", over.Code, over.Body.String())
	}
	cfg, err = config.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	ro := cfg.Policies["readonly"]
	if ro == nil || ro.Allow == nil || len(*ro.Allow) != 1 || (*ro.Allow)[0] != "ls" {
		t.Fatalf("override allow %+v", ro)
	}
	if ro.Capabilities == nil || ro.Capabilities.Upload == nil || *ro.Capabilities.Upload {
		t.Fatalf("override dropped builtin capabilities %+v", ro.Capabilities)
	}
	restore := postJSON(t, h, "/api/policies/remove", `{"name":"readonly"}`)
	if restore.Code != 200 {
		t.Fatalf("restore %d %s", restore.Code, restore.Body.String())
	}
	cfg, err = config.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := cfg.Policies["readonly"]; ok {
		t.Fatal("builtin override still stored")
	}
}

func postJSON(t *testing.T, h http.Handler, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.RemoteAddr = "127.0.0.1:9"
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func containsAll(have []string, want ...string) bool {
	set := map[string]bool{}
	for _, s := range have {
		set[s] = true
	}
	for _, s := range want {
		if !set[s] {
			return false
		}
	}
	return true
}
