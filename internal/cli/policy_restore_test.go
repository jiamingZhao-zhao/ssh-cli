package cli

import (
	"bytes"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/config"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/guard"
	"strings"
	"testing"
)

func TestBuiltinPolicyCLIConfirmation(t *testing.T) {
	old := ttyCheck
	ttyCheck = func() bool { return false }
	defer func() { ttyCheck = old }()
	dir := t.TempDir()
	if err := config.Save(dir, &config.Config{Version: 1}); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) (int, string) {
		var out, err bytes.Buffer
		code := Execute(append([]string{"--config", dir}, args...), strings.NewReader(""), &out, &err)
		return code, out.String() + err.String()
	}
	if c, s := run("policy", "edit", "readonly", "--mode", "readonly"); c != 0 {
		t.Fatal(c, s)
	}
	cfg, _ := config.Load(dir)
	if cfg.Policies["readonly"] != nil {
		t.Fatal("CLI froze unchanged builtin")
	}
	p, _ := guard.BuiltinPolicy("readonly")
	p.Deny = []string{"docker logs"}
	p.ProtectedPaths = []string{"/srv"}
	if err := config.Update(dir, func(c *config.Config) error { c.Policies = map[string]*config.Policy{"readonly": p}; return nil }); err != nil {
		t.Fatal(err)
	}
	if c, s := run("policy", "list", "--json"); c != 0 || !strings.Contains(s, `"builtinDifference"`) || !strings.Contains(s, `"restoreWidens": true`) {
		t.Fatal(c, s)
	}
	for _, args := range [][]string{{"policy", "remove", "readonly", "--json"}, {"policy", "remove", "readonly", "--yes", "--json"}} {
		if c, s := run(args...); c != 253 {
			t.Fatalf("noninteractive restore: %d %s", c, s)
		}
		cfg, _ = config.Load(dir)
		if cfg.Policies["readonly"] == nil || len(cfg.Policies["readonly"].Deny) != 1 {
			t.Fatal("restore bypassed confirmation")
		}
	}
}
