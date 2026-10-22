package guard

import (
	"strings"
	"testing"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/config"
)

func TestLifecycleEquivalence(t *testing.T) {
	stdEnv := &config.Env{MaxMode: config.ModeStandard, DefaultPolicy: "standard"}
	g := &config.Group{Env: "test", Policy: "standard"}
	h := &config.Host{Host: "192.0.2.20", User: "root"}
	cfg := &config.Config{Version: 1, Envs: map[string]*config.Env{"test": stdEnv}, Groups: map[string]*config.Group{"g": g}}
	std := resolve(t, cfg, config.ResolvedHost{Alias: "t1", Group: "g", EnvName: "test", Env: stdEnv, GroupDef: g, Host: h}, false)

	for _, cmd := range []string{
		"docker restart nginx",
		"docker stop nginx",
		"docker start nginx",
		"docker kill nginx",
		"docker container restart nginx",
		"docker --host tcp://192.0.2.1:2375 stop nginx",
		"systemctl start nginx",
		"systemctl stop nginx",
		"apps.sh stop",
		"apps.sh start",
		"sh -c 'docker stop nginx && docker start nginx'",
	} {
		d := Decide(std, cmd)
		if !d.Allowed || !d.NeedsConfirm {
			t.Errorf("standard %q should confirm: %+v", cmd, d)
		}
	}
	if d := Decide(std, "docker ps"); !d.Allowed || d.NeedsConfirm {
		t.Fatalf("docker ps: %+v", d)
	}
	if d := Decide(std, "echo hi"); !d.Allowed || d.NeedsConfirm {
		t.Fatalf("echo: %+v", d)
	}
	if d := Decide(std, "sh -c 'echo hi'"); !d.Allowed || d.NeedsConfirm {
		t.Fatalf("inlined safe script: %+v", d)
	}

	ro, host := prodReadonlyHost("", nil)
	eff := resolve(t, ro, host, false)
	if d := Decide(eff, "apps.sh status"); !d.Allowed || d.NeedsConfirm || len(d.Commands) == 0 {
		t.Fatalf("apps.sh status: %+v", d)
	}
	if d := Decide(eff, "./status.sh"); d.Allowed {
		t.Fatalf("readonly script path: %+v", d)
	}
}

func TestStopDoesNotImplyStart(t *testing.T) {
	env := &config.Env{MaxMode: config.ModeAdmin, DefaultPolicy: "admin"}
	g := &config.Group{Env: "dev", Confirm: []string{"docker stop", "systemctl stop"}}
	h := &config.Host{Host: "192.0.2.30", User: "root"}
	cfg := &config.Config{Version: 1, Envs: map[string]*config.Env{"dev": env}, Groups: map[string]*config.Group{"g": g}}
	eff := resolve(t, cfg, config.ResolvedHost{Alias: "box", Group: "g", EnvName: "dev", Env: env, GroupDef: g, Host: h}, false)

	for _, cmd := range []string{"docker stop nginx", "docker restart nginx", "docker kill nginx", "systemctl restart nginx"} {
		d := Decide(eff, cmd)
		if !d.Allowed || !d.NeedsConfirm {
			t.Errorf("%q should confirm: %+v", cmd, d)
		}
	}
	for _, cmd := range []string{"docker start nginx", "systemctl start nginx", "podman restart nginx"} {
		d := Decide(eff, cmd)
		if !d.Allowed || d.NeedsConfirm {
			t.Errorf("%q should stay allowed: %+v", cmd, d)
		}
	}
	notes := EquivalenceNotes(eff.Confirm)
	joined := strings.Join(notes, "\n")
	if !strings.Contains(joined, "docker stop also matches docker restart, docker kill") {
		t.Fatalf("notes %q", notes)
	}
	if strings.Contains(joined, "docker start") {
		t.Fatalf("start was implied by stop: %q", notes)
	}
}

func TestRestartDenyCoversStopStart(t *testing.T) {
	env := &config.Env{MaxMode: config.ModeAdmin, DefaultPolicy: "admin"}
	g := &config.Group{Env: "dev", Deny: []string{"docker restart"}}
	h := &config.Host{Host: "192.0.2.31", User: "root"}
	cfg := &config.Config{Version: 1, Envs: map[string]*config.Env{"dev": env}, Groups: map[string]*config.Group{"g": g}}
	eff := resolve(t, cfg, config.ResolvedHost{Alias: "box", Group: "g", EnvName: "dev", Env: env, GroupDef: g, Host: h}, false)
	for _, cmd := range []string{"docker restart web", "docker stop web", "docker start web", "docker kill web", "podman restart web"} {
		d := Decide(eff, cmd)
		want := cmd != "podman restart web"
		if d.Allowed == want {
			t.Errorf("%q allowed=%v, want denied=%v (%+v)", cmd, d.Allowed, want, d)
		}
	}
}
