package cli

import (
	"io"
	"strings"
	"testing"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/audit"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/config"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/guard"
)

func TestPlanConfirmationExplainsRule(t *testing.T) {
	ttyCheck = func() bool { return false }
	t.Cleanup(func() { ttyCheck = defaultTTY })
	env := &config.Env{MaxMode: config.ModeStandard, DefaultPolicy: "standard"}
	group := &config.Group{Env: "test"}
	h := config.ResolvedHost{Alias: "fixture", Group: "testing", EnvName: "test", Env: env, GroupDef: group, Host: &config.Host{Host: "192.0.2.10", User: "test"}}
	cfg := &config.Config{Version: 1, Envs: map[string]*config.Env{"test": env}, Groups: map[string]*config.Group{"testing": group}}
	a := &App{Dir: t.TempDir(), Err: io.Discard}
	const restart = "systemctl restart nginx"
	_, err := a.plan(cfg, []config.ResolvedHost{h}, a.auditMeta(audit.OpExec, restart, "", ""), func(e guard.Effective) guard.Decision { return guard.Decide(e, restart) })
	if err == nil || !strings.Contains(err.Error(), `env: matches confirm pattern "systemctl restart"`) {
		t.Fatalf("confirmation reason missing: %v", err)
	}
	const script = "bash /data/web/dc/wms.sh restart"
	planned, err := a.plan(cfg, []config.ResolvedHost{h}, a.auditMeta(audit.OpExec, script, "", ""), func(e guard.Effective) guard.Decision { return guard.Decide(e, script) })
	if err != nil || len(planned) != 1 || planned[0].dec.NeedsConfirm {
		t.Fatalf("static script requires a TTY: %v %+v", err, planned)
	}
}
