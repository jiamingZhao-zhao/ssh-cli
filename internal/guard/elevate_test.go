package guard

import (
	"github.com/jiamingZhao-zhao/ssh-cli/internal/config"
	"testing"
)

func TestElevationKeepsExplicitRestrictions(t *testing.T) {
	cfg := &config.Config{Version: 1, Groups: map[string]*config.Group{"g": {Env: "prod", Hosts: map[string]*config.Host{"a": {Host: "127.0.0.1", User: "u"}}}}}
	if err := cfg.Normalize(); err != nil {
		t.Fatal(err)
	}
	h, _ := cfg.Find("a")
	if _, err := ResolveElevated(cfg, h); err == nil {
		t.Fatal("elevated without opt-in")
	}
	h.Env.BreakGlass = &config.BreakGlass{Enabled: true, MaxTTL: "15m"}
	h.Env.NoDataOutflow = true
	eff, err := ResolveElevated(cfg, h)
	if err != nil {
		t.Fatal(err)
	}
	if eff.Mode != config.ModeStandard || !eff.NoDataOut || !Decide(eff, "touch /tmp/x").Allowed {
		t.Fatalf("elevation failed: %+v", eff)
	}
	if h.Env.MaxMode != config.ModeReadonly {
		t.Fatal("mutated saved environment")
	}
	h.Host.Deny = []string{"touch"}
	eff, err = ResolveElevated(cfg, h)
	if err != nil {
		t.Fatal(err)
	}
	if Decide(eff, "touch /tmp/x").Allowed {
		t.Fatal("bypassed explicit host deny")
	}
	h.Host.Deny = nil
	h.GroupDef.Policy = "readonly"
	eff, err = ResolveElevated(cfg, h)
	if err != nil {
		t.Fatal(err)
	}
	if Decide(eff, "touch /tmp/x").Allowed {
		t.Fatal("bypassed explicit group readonly")
	}
}
