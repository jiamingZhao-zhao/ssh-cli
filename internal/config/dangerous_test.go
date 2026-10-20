package config

import (
	"strings"
	"testing"
)

func TestDangerousCommandConfigDefaults(t *testing.T) {
	dir := t.TempDir()
	cfg, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Dangerous != nil {
		t.Fatalf("fresh config must not store an active dangerous-command list: %+v", cfg.Dangerous)
	}
	scope, scopeDefault := (*DangerousCommands)(nil).Scope()
	if !scopeDefault || len(scope) != 1 || scope[0] != "prod" {
		t.Fatalf("nil scope: %v %v", scope, scopeDefault)
	}

	bad := &Config{Version: 1, Dangerous: &DangerousCommands{Enabled: true, Rules: []string{"reboot"}}}
	if err := bad.Normalize(); err == nil || !strings.Contains(err.Error(), "unknown rule") {
		t.Fatalf("unknown rule: %v", err)
	}
	missing := &Config{Version: 1, Dangerous: &DangerousCommands{Envs: []string{"staging"}, Rules: []string{DangerRMRoot}}}
	if err := missing.Normalize(); err == nil || !strings.Contains(err.Error(), "unknown env") {
		t.Fatalf("unknown env: %v", err)
	}

	ok := &Config{Version: 1, Dangerous: &DangerousCommands{Rules: []string{DangerMkfs, DangerMkfs}}}
	if err := ok.Normalize(); err != nil {
		t.Fatal(err)
	}
	if ok.Dangerous == nil || ok.Dangerous.Enabled || len(ok.Dangerous.Rules) != 1 {
		t.Fatalf("stored list stays off: %+v", ok.Dangerous)
	}
	ok.Dangerous.Enabled = true
	rules, _, on := ok.Dangerous.Enforcement("prod")
	if !on || !rules[DangerMkfs] {
		t.Fatalf("prod enforcement: %+v %v", rules, on)
	}
	if _, _, on := ok.Dangerous.Enforcement("dev"); on {
		t.Fatal("dev is not in the default scope")
	}
}
