package config

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
)

func TestRoundTripAndAtomicWrite(t *testing.T) {
	dir := t.TempDir()
	allow := []string{"ls", "cat"}
	cfg := &Config{
		Version: 1,
		Default: "main",
		Policies: map[string]*Policy{
			"readonly": {Mode: ModeReadonly, Allow: &allow},
		},
		Envs: map[string]*Env{
			"prod": {
				Label: "生产", Color: "red", MaxMode: ModeReadonly, DefaultPolicy: "readonly",
				BreakGlass:    &BreakGlass{Enabled: true, MaxTTL: "30m"},
				NoDataOutflow: true,
			},
		},
		Groups: map[string]*Group{
			"app-prod": {
				Env:            "prod",
				ProtectedPaths: []string{"/root/app"},
				Hosts: map[string]*Host{
					"main": {Host: "192.0.2.10", User: "viewer", Auth: "password", PasswordRef: "app-prod.main", Tags: []string{"app"}},
					"web":  {Host: "192.0.2.11", User: "viewer", Auth: "key", Identity: "~/.ssh/id_ed25519", Tags: []string{"web"}},
				},
			},
		},
		Tasks: map[string]any{
			"deploy": map[string]any{"user": "deploy"},
		},
	}
	if err := Save(dir, cfg); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, FileName))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o, want 600", info.Mode().Perm())
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if len(e.Name()) >= 5 && e.Name()[:5] == ".tmp-" {
			t.Fatalf("temp file left behind: %s", e.Name())
		}
	}
	got, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got.Envs["prod"].Label != "生产" || got.Envs["prod"].MaxMode != ModeReadonly {
		t.Fatalf("env round trip: %+v", got.Envs["prod"])
	}
	if !got.Envs["prod"].NoDataOutflow || got.Envs["prod"].BreakGlass.MaxTTL != "30m" {
		t.Fatalf("breakGlass not preserved: %+v", got.Envs["prod"])
	}
	if got.Groups["app-prod"].Hosts["web"].Identity != "~/.ssh/id_ed25519" {
		t.Fatalf("web host clobbered: %+v", got.Groups["app-prod"].Hosts["web"])
	}
	if _, ok := got.Tasks["deploy"]; !ok {
		t.Fatal("tasks were dropped")
	}

	if err := Update(dir, func(c *Config) error {
		c.Groups["app-prod"].Hosts["main"].Port = 2222
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	got, err = Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	main := got.Groups["app-prod"].Hosts["main"]
	web := got.Groups["app-prod"].Hosts["web"]
	if main.Port != 2222 || main.User != "viewer" || main.PasswordRef != "app-prod.main" {
		t.Fatalf("main edit clobbered fields: %+v", main)
	}
	if web.Host != "192.0.2.11" || web.Auth != "key" {
		t.Fatalf("edit clobbered sibling host: %+v", web)
	}
	if _, ok := got.Tasks["deploy"]; !ok {
		t.Fatal("edit dropped tasks")
	}
}

func TestRejectHostEnv(t *testing.T) {
	dir := t.TempDir()
	body := []byte(`
version: 1
envs:
  prod: {label: 生产, maxMode: readonly}
groups:
  g:
    env: prod
    hosts:
      main:
        host: 192.0.2.10
        user: root
        env: dev
`)
	if err := os.WriteFile(filepath.Join(dir, FileName), body, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Load(dir)
	if err == nil {
		t.Fatal("expected host env to be rejected")
	}
}

func TestConcurrentUpdatesDoNotClobber(t *testing.T) {
	dir := t.TempDir()
	base := &Config{
		Version: 1,
		Envs:    map[string]*Env{"dev": {MaxMode: ModeAdmin}},
		Groups:  map[string]*Group{"g": {Env: "dev", Hosts: map[string]*Host{}}},
	}
	if err := Save(dir, base); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errCh := make(chan error, 2)
	for _, alias := range []string{"a", "b"} {
		alias := alias
		wg.Add(1)
		go func() {
			defer wg.Done()
			errCh <- Update(dir, func(c *Config) error {
				if c.Groups["g"].Hosts == nil {
					c.Groups["g"].Hosts = map[string]*Host{}
				}
				c.Groups["g"].Hosts[alias] = &Host{Host: "192.0.2.10", User: "root"}
				return nil
			})
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatal(err)
		}
	}
	got, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := got.Groups["g"].Hosts["a"]; !ok {
		t.Fatal("host a missing")
	}
	if _, ok := got.Groups["g"].Hosts["b"]; !ok {
		t.Fatal("host b missing")
	}
}

func TestSelect(t *testing.T) {
	cfg := &Config{
		Version: 1,
		Default: "main",
		Envs: map[string]*Env{
			"prod": {MaxMode: ModeReadonly},
			"test": {MaxMode: ModeStandard},
		},
		Groups: map[string]*Group{
			"gp": {Env: "prod", Hosts: map[string]*Host{
				"main": {Host: "192.0.2.10", User: "viewer", Tags: []string{"app"}},
			}},
			"gt": {Env: "test", Hosts: map[string]*Host{
				"t1": {Host: "192.0.2.20", User: "root", Tags: []string{"app", "db"}},
			}},
		},
	}
	got, err := cfg.Select(Selector{})
	if err != nil || len(got) != 1 || got[0].Alias != "main" || got[0].EnvName != "prod" {
		t.Fatalf("default: %+v %v", got, err)
	}
	got, err = cfg.Select(Selector{Tags: []string{"app"}})
	if err != nil || len(got) != 2 {
		t.Fatalf("tag union: %+v %v", got, err)
	}
	got, err = cfg.Select(Selector{Groups: []string{"gt"}, Env: "test"})
	if err != nil || len(got) != 1 || got[0].Alias != "t1" {
		t.Fatalf("group+env: %+v %v", got, err)
	}
	if _, err := cfg.Select(Selector{Hosts: []string{"missing"}}); err == nil {
		t.Fatal("expected missing host error")
	}
}

func TestBuiltinEnvsEnsuredOnLoad(t *testing.T) {
	dir := t.TempDir()
	cfg, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, FileName)); !os.IsNotExist(err) {
		t.Fatal("load of a missing file should not create hosts.yaml")
	}
	assertBuiltinEnvs(t, cfg)

	body := []byte(`
version: 1
envs:
  prod:
    label: 放开
    color: green
    maxMode: admin
    defaultPolicy: admin
    breakGlass: {enabled: true, maxTtl: 30m}
    noDataOutflow: true
  lab:
    label: 实验
    maxMode: admin
groups:
  hunan-prod:
    env: prod
    hosts: {}
`)
	if err := os.WriteFile(filepath.Join(dir, FileName), body, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err = Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	assertBuiltinEnvs(t, cfg)
	prod := cfg.Envs["prod"]
	if prod.BreakGlass == nil || prod.BreakGlass.MaxTTL != "30m" || !prod.NoDataOutflow {
		t.Fatalf("extra env fields dropped: %+v", prod)
	}
	if cfg.Envs["lab"] == nil || cfg.Envs["lab"].Label != "实验" {
		t.Fatal("custom env was dropped")
	}
	if _, ok := cfg.Groups["hunan-prod"]; !ok {
		t.Fatal("group missing")
	}
}

func assertBuiltinEnvs(t *testing.T, cfg *Config) {
	t.Helper()
	want := map[string]Env{
		"dev":     {Label: "开发", Color: "green", MaxMode: ModeAdmin, DefaultPolicy: "standard"},
		"test":    {Label: "测试", Color: "yellow", MaxMode: ModeStandard, DefaultPolicy: "standard"},
		"preprod": {Label: "预生产", Color: "orange", MaxMode: ModeStandard, DefaultPolicy: "standard"},
		"prod":    {Label: "生产", Color: "red", MaxMode: ModeReadonly, DefaultPolicy: "readonly"},
	}
	for name, canon := range want {
		got := cfg.Envs[name]
		if got == nil || got.Label != canon.Label || got.Color != canon.Color || got.MaxMode != canon.MaxMode || got.DefaultPolicy != canon.DefaultPolicy {
			t.Fatalf("env %s = %+v, want %+v", name, got, canon)
		}
	}
}

func TestResolveDirEnv(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SSH_CLI_HOME", dir)
	got, err := ResolveDir("")
	if err != nil || got != dir {
		t.Fatalf("got %q err %v", got, err)
	}
	got, err = ResolveDir("/override")
	if err != nil || got != "/override" {
		t.Fatalf("flag override: %q %v", got, err)
	}
}

func TestViaChainRules(t *testing.T) {
	host := func(addr, via string) *Host {
		return &Host{Host: addr, User: "ops", Auth: "password", PasswordRef: "g.x", Via: via}
	}
	cfg := &Config{
		Version: 1,
		Envs:    map[string]*Env{"dev": {MaxMode: ModeStandard}},
		Groups: map[string]*Group{
			"g": {Env: "dev", Hosts: map[string]*Host{
				"jump": host("192.0.2.1", ""),
				"box":  host("192.0.2.2", "jump"),
			}},
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	direct := cfg.Groups["g"].Hosts["jump"].ConnFingerprint()
	jumped := cfg.Groups["g"].Hosts["box"].ConnFingerprint()
	cfg.Groups["g"].Hosts["box"].Via = ""
	if cfg.Groups["g"].Hosts["box"].ConnFingerprint() == jumped {
		t.Fatal("clearing via must change the connection fingerprint")
	}
	cfg.Groups["g"].Hosts["box"].Via = "jump"
	if cfg.Groups["g"].Hosts["box"].ConnFingerprint() == direct {
		t.Fatal("via must change the connection fingerprint")
	}
	box, ok := cfg.Find("box")
	if !ok {
		t.Fatal("missing box")
	}
	chain, err := cfg.ViaChainFrom(box)
	if err != nil {
		t.Fatal(err)
	}
	if len(chain) != 2 || chain[0].Alias != "jump" || chain[1].Alias != "box" {
		t.Fatalf("chain %#v", chain)
	}
	jump, ok := cfg.Find("jump")
	if !ok {
		t.Fatal("missing jump")
	}
	alone, err := cfg.ViaChainFrom(jump)
	if err != nil || len(alone) != 1 || alone[0].Alias != "jump" {
		t.Fatalf("direct chain %#v %v", alone, err)
	}

	cfg.Groups["g"].Hosts["jump"].Via = "box"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "cycle") {
		t.Fatalf("cycle: %v", err)
	}
	cfg.Groups["g"].Hosts["jump"].Via = ""
	cfg.Groups["g"].Hosts["box"].Via = "missing"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("missing: %v", err)
	}
	cfg.Groups["g"].Hosts["box"].Via = "box"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "invalid jump") {
		t.Fatalf("self: %v", err)
	}

	long := &Config{
		Version: 1,
		Envs:    map[string]*Env{"dev": {MaxMode: ModeStandard}},
		Groups:  map[string]*Group{"g": {Env: "dev", Hosts: map[string]*Host{}}},
	}
	for i := 0; i < MaxViaHops; i++ {
		name := string(rune('a' + i))
		via := ""
		if i > 0 {
			via = string(rune('a' + i - 1))
		}
		long.Groups["g"].Hosts[name] = host("192.0.2."+strconv.Itoa(i+1), via)
	}
	if err := long.Validate(); err != nil {
		t.Fatalf("chain of %d: %v", MaxViaHops, err)
	}
	extra := string(rune('a' + MaxViaHops))
	long.Groups["g"].Hosts[extra] = host("192.0.2.40", string(rune('a'+MaxViaHops-1)))
	if err := long.Validate(); err == nil || !strings.Contains(err.Error(), "longer than") {
		t.Fatalf("overlong: %v", err)
	}
}
