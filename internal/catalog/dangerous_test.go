package catalog

import (
	"errors"
	"testing"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/config"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/confirmgate"
)

func TestSetDangerousOptInAndShrink(t *testing.T) {
	dir := t.TempDir()
	on := true
	if err := SetDangerous(dir, DangerousDraft{Enable: &on, AllRules: true}); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Dangerous == nil || !cfg.Dangerous.Enabled || len(cfg.Dangerous.Rules) != len(config.DangerousRuleIDs()) {
		t.Fatalf("enabled catalog: %+v", cfg.Dangerous)
	}
	if _, _, on := cfg.Dangerous.Enforcement("prod"); !on {
		t.Fatal("prod should enforce the full catalog")
	}
	if _, _, on := cfg.Dangerous.Enforcement("test"); on {
		t.Fatal("test is outside the default scope")
	}

	off := false
	err = SetDangerous(dir, DangerousDraft{Enable: &off})
	var gate *confirmgate.Error
	if !errors.As(err, &gate) || gate.Phrase != "dangerous" {
		t.Fatalf("shrink: %v", err)
	}
	if err := SetDangerous(dir, DangerousDraft{Enable: &off, HumanConfirm: "dangerous"}); err != nil {
		t.Fatal(err)
	}
	cfg, err = config.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Dangerous == nil || cfg.Dangerous.Enabled || len(cfg.Dangerous.Rules) != len(config.DangerousRuleIDs()) {
		t.Fatalf("disabled keeps the list: %+v", cfg.Dangerous)
	}
	if _, _, on := cfg.Dangerous.Enforcement("prod"); on {
		t.Fatal("disabled catalog must not enforce")
	}

	if err := SetDangerous(dir, DangerousDraft{Enable: &on, HasEnvs: true, Envs: []string{"dev", "test"}}); err != nil {
		t.Fatal(err)
	}
	cfg, err = config.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, on := cfg.Dangerous.Enforcement("dev"); !on {
		t.Fatal("named non-prod env should enforce after it is configured")
	}
	if _, _, on := cfg.Dangerous.Enforcement("prod"); on {
		t.Fatal("prod drops out of scope when the user replaces the env list")
	}
}
