package cli

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/audit"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/config"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/guard"
)

func TestAgentProfileRefusesInteractiveConfirmation(t *testing.T) {
	ttyCheck = func() bool { return true }
	t.Cleanup(func() { ttyCheck = defaultTTY })
	e := &config.Env{MaxMode: config.ModeStandard, DefaultPolicy: "standard"}
	g := &config.Group{Env: "test"}
	h := config.ResolvedHost{Alias: "a", Group: "g", EnvName: "test", Env: e, GroupDef: g, Host: &config.Host{Host: "192.0.2.1", User: "u"}}
	cfg := &config.Config{Version: 1, Envs: map[string]*config.Env{"test": e}, Groups: map[string]*config.Group{"g": g}}
	a := &App{AgentProfile: true, Dir: t.TempDir(), Err: io.Discard}
	_, err := a.plan(cfg, []config.ResolvedHost{h}, a.auditMeta(audit.OpExec, "systemctl restart nginx", "", ""), func(eff guard.Effective) guard.Decision { return guard.Decide(eff, "systemctl restart nginx") })
	if err == nil || !strings.Contains(err.Error(), "requires confirmation") {
		t.Fatalf("expected human confirmation without prompting: %v", err)
	}
}

func TestAgentFlagsAndErrors(t *testing.T) {
	dir := t.TempDir()
	var out, errout bytes.Buffer
	code := Execute([]string{"--config", dir, "--agent-mode", "exec", "--timeout", "-1s", "--", "ls"}, strings.NewReader(""), &out, &errout)
	if code != 250 || !strings.Contains(out.String(), `"kind":"invalid_arguments"`) {
		t.Fatalf("invalid timeout: %d %s %s", code, out.String(), errout.String())
	}
	out.Reset()
	errout.Reset()
	code = Execute([]string{"--config", dir, "keys", "--max-output-bytes", "1"}, strings.NewReader(""), &out, &errout)
	if code != 250 || strings.Contains(errout.String(), "output limits support") {
		t.Fatalf("keys should accept output limits and report a missing target: %d %s", code, errout.String())
	}
}
