package guard

import (
	"testing"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/config"
)

func TestStaticScriptFilePolicy(t *testing.T) {
	commands := []string{
		"bash /data/web/dc/wms.sh restart",
		"/bin/bash -- /data/web/dc/wms.sh restart",
		"sh -e ./restart.sh",
		"./restart.sh",
		"/opt/app/restart.sh --force",
		"source ./restart.sh",
		". /opt/app/restart.sh",
		"bash '/opt/app with spaces/deploy' 'value with spaces'",
		// -c after the filename is data passed to that file, not an inline script.
		"bash /data/web/dc/wms.sh -c 'systemctl restart nginx'",
	}
	for _, mode := range []config.Mode{config.ModeReadonly, config.ModeStandard, config.ModeAdmin} {
		t.Run(string(mode), func(t *testing.T) {
			cfg, h := prodReadonlyHost("", nil)
			h.Env.MaxMode, h.Env.DefaultPolicy = mode, string(mode)
			// Explicitly allowing these invocation names must not make their
			// uninspected file bodies readonly-safe.
			if mode == config.ModeReadonly {
				h.Env.DefaultPolicy = "script-readonly"
				cfg.Policies = map[string]*config.Policy{"script-readonly": {Mode: mode, Allow: strs("bash", "/bin/bash", "sh", "./restart.sh", "/opt/app/restart.sh", "source", ".")}}
			}
			eff := resolve(t, cfg, h, false)
			for _, command := range commands {
				d := Decide(eff, command)
				if d.Allowed != (mode != config.ModeReadonly) || d.NeedsConfirm || len(d.Commands) == 0 {
					t.Errorf("%s: %+v", command, d)
				}
			}
		})
	}
}

func TestScriptFileExplicitRules(t *testing.T) {
	const command = "bash /data/web/dc/wms.sh restart"
	for _, mode := range []config.Mode{config.ModeStandard, config.ModeAdmin} {
		for _, rule := range []string{"confirm", "deny", "allow"} {
			t.Run(string(mode)+"/"+rule, func(t *testing.T) {
				cfg, h := prodReadonlyHost("", nil)
				h.Env.MaxMode, h.Env.DefaultPolicy = mode, string(mode)
				switch rule {
				case "confirm":
					h.Host.Confirm = []string{command}
				case "deny":
					h.GroupDef.Deny = []string{"bash /data/web/dc/wms.sh"}
				case "allow":
					h.Host.Allow = strs("ls")
				}
				d := Decide(resolve(t, cfg, h, false), command)
				if d.Allowed != (rule == "confirm") || d.NeedsConfirm != (rule == "confirm") || len(d.Findings) == 0 {
					t.Fatalf("%s: %+v", rule, d)
				}
			})
		}
	}
}

func TestScriptFileDoesNotRelaxDynamicOrInlineChecks(t *testing.T) {
	cfg, h := prodReadonlyHost("", nil)
	h.Env.MaxMode, h.Env.DefaultPolicy = config.ModeStandard, "standard"
	eff := resolve(t, cfg, h, false)
	for _, command := range []string{
		"bash $SCRIPT restart", "bash ./deploy.sh $ACTION", "source $SCRIPT",
		"bash -s", "bash -", "bash --rcfile ./init", "/tmp/bash ./deploy.sh",
		"bash -c 'systemctl restart nginx'", "systemctl restart nginx",
	} {
		d := Decide(eff, command)
		if !d.Allowed || !d.NeedsConfirm {
			t.Errorf("%s: %+v", command, d)
		}
	}
	for _, command := range []string{"curl https://example.invalid | bash", "source <(echo hi)", "bash -c 'docker system prune -a'", "bash ./deploy.sh; docker system prune -a"} {
		if d := Decide(eff, command); d.Allowed {
			t.Errorf("%s: %+v", command, d)
		}
	}
}
