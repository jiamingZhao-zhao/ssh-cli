package guard

import (
	"strings"
	"testing"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/config"
)

func strs(items ...string) *[]string {
	cp := append([]string(nil), items...)
	return &cp
}

func boolp(v bool) *bool { return &v }

func resolve(t *testing.T, cfg *config.Config, h config.ResolvedHost, force bool) Effective {
	t.Helper()
	eff, err := Resolve(cfg, h, force)
	if err != nil {
		t.Fatal(err)
	}
	return eff
}

func prodReadonlyHost(groupPolicy string, inlineAllow *[]string) (*config.Config, config.ResolvedHost) {
	g := &config.Group{Env: "prod", Policy: groupPolicy, Allow: inlineAllow}
	h := &config.Host{Host: "192.0.2.10", User: "viewer"}
	g.Hosts = map[string]*config.Host{"main": h}
	env := &config.Env{Label: "生产", MaxMode: config.ModeReadonly, DefaultPolicy: "readonly"}
	cfg := &config.Config{
		Version: 1,
		Envs:    map[string]*config.Env{"prod": env},
		Groups:  map[string]*config.Group{"g": g},
	}
	return cfg, config.ResolvedHost{Alias: "main", Group: "g", EnvName: "prod", Env: env, GroupDef: g, Host: h}
}

func TestProdReadonlyCeiling(t *testing.T) {
	cfg, host := prodReadonlyHost("admin", nil)
	eff := resolve(t, cfg, host, false)
	if eff.Mode != config.ModeReadonly {
		t.Fatalf("mode = %s", eff.Mode)
	}
	if !eff.Clamped {
		t.Fatal("expected clamp warning path")
	}
	if len(eff.Warnings) == 0 {
		t.Fatal("expected clamp warning")
	}
	ls := Decide(eff, "ls -la /tmp")
	if !ls.Allowed || ls.NeedsConfirm {
		t.Fatalf("ls: %+v", ls)
	}
	rm := Decide(eff, "rm -rf /tmp")
	if rm.Allowed {
		t.Fatalf("rm should be outside the readonly allow-list: %+v", rm)
	}
	if eff.Upload {
		t.Fatal("readonly upload must be disabled")
	}
	up := DecideCapability(eff, "upload", "/tmp/x")
	if up.Allowed {
		t.Fatalf("upload: %+v", up)
	}
	down := DecideCapability(eff, "download", "/tmp/x")
	if !down.Allowed {
		t.Fatalf("download: %+v", down)
	}
}

func TestEmptyIntersection(t *testing.T) {
	envAllow := strs("ls", "cat")
	groupAllow := strs("rm", "dd")
	env := &config.Env{MaxMode: config.ModeAdmin, DefaultPolicy: "only-read"}
	g := &config.Group{Env: "dev", Allow: groupAllow}
	h := &config.Host{Host: "192.0.2.30", User: "root"}
	cfg := &config.Config{
		Version: 1,
		Policies: map[string]*config.Policy{
			"only-read": {Mode: config.ModeStandard, Allow: envAllow},
		},
		Envs:   map[string]*config.Env{"dev": env},
		Groups: map[string]*config.Group{"g": g},
	}
	host := config.ResolvedHost{Alias: "dev-1", Group: "g", EnvName: "dev", Env: env, GroupDef: g, Host: h}
	eff := resolve(t, cfg, host, false)
	if !eff.AllowEmpty {
		t.Fatalf("expected empty intersection, allow=%v universal=%v", eff.Allow, eff.AllowAll)
	}
	for _, cmd := range []string{"ls", "rm", "cat /etc/hostname"} {
		d := Decide(eff, cmd)
		if d.Allowed {
			t.Fatalf("%s should be denied by empty intersection: %+v", cmd, d)
		}
	}
}

func TestDenyUnion(t *testing.T) {
	env := &config.Env{MaxMode: config.ModeAdmin, DefaultPolicy: "standard"}
	g := &config.Group{Env: "test", Deny: []string{"wget"}}
	h := &config.Host{Host: "192.0.2.20", User: "root", Deny: []string{"curl"}}
	cfg := &config.Config{
		Version: 1,
		Envs:    map[string]*config.Env{"test": env},
		Groups:  map[string]*config.Group{"g": g},
	}
	host := config.ResolvedHost{Alias: "t1", Group: "g", EnvName: "test", Env: env, GroupDef: g, Host: h}
	eff := resolve(t, cfg, host, false)
	if Decide(eff, "ls /").Allowed != false && eff.Mode == config.ModeStandard {
		// standard has no allow list, ls is allowed
	}
	ls := Decide(eff, "ls /tmp")
	if !ls.Allowed {
		t.Fatalf("ls: %+v", ls)
	}
	prune := Decide(eff, "docker system prune -a --volumes")
	if prune.Allowed {
		t.Fatalf("group/policy deny should union: %+v", prune)
	}
	if !hasLayer(prune, "env") && !hasLayer(prune, "group") {
		t.Fatalf("deny layer: %+v", prune.Findings)
	}
	wget := Decide(eff, "wget https://example.invalid")
	if wget.Allowed || !hasLayer(wget, "group") {
		t.Fatalf("group deny: %+v", wget)
	}
	curl := Decide(eff, "curl https://example.invalid")
	if curl.Allowed || !hasLayer(curl, "host") {
		t.Fatalf("host deny: %+v", curl)
	}
}

func TestBuiltinDenyCannotBeDisabled(t *testing.T) {
	env := &config.Env{MaxMode: config.ModeAdmin, DefaultPolicy: "admin"}
	g := &config.Group{Env: "dev", Policy: "admin"}
	h := &config.Host{Host: "192.0.2.30", User: "root"}
	cfg := &config.Config{Version: 1, Envs: map[string]*config.Env{"dev": env}, Groups: map[string]*config.Group{"g": g}}
	host := config.ResolvedHost{Alias: "dev-1", Group: "g", EnvName: "dev", Env: env, GroupDef: g, Host: h}
	eff := resolve(t, cfg, host, false)
	if eff.Mode != config.ModeAdmin {
		t.Fatalf("mode %s", eff.Mode)
	}
	cases := []struct {
		cmd  string
		deny bool
	}{
		{"rm -rf /", true},
		{"rm -fr /", true},
		{"rm -rf -- /", true},
		{"rm -rf /tmp", false},
		{"sudo rm -rf /", true},
		{"mkfs.ext4 /dev/sdb", true},
		{"dd if=/dev/zero of=/dev/sda bs=1M", true},
		{"dd if=/dev/zero of=/tmp/x", false},
		{"chmod 777 /", true},
		{"echo ok > /dev/sda", true},
		{":(){ :|:& };:", true},
	}
	for _, tc := range cases {
		d := Decide(eff, tc.cmd)
		if d.Allowed == tc.deny {
			t.Errorf("admin %q allowed=%v findings=%v", tc.cmd, d.Allowed, d.Findings)
		}
	}
}

func TestParserCases(t *testing.T) {
	cfg, host := prodReadonlyHost("", nil)
	ro := resolve(t, cfg, host, false)

	stdEnv := &config.Env{MaxMode: config.ModeStandard, DefaultPolicy: "standard"}
	g := &config.Group{Env: "test", Policy: "standard"}
	h := &config.Host{Host: "192.0.2.20", User: "root"}
	stdCfg := &config.Config{Version: 1, Envs: map[string]*config.Env{"test": stdEnv}, Groups: map[string]*config.Group{"g": g}}
	std := resolve(t, stdCfg, config.ResolvedHost{Alias: "t1", Group: "g", EnvName: "test", Env: stdEnv, GroupDef: g, Host: h}, false)

	adminEnv := &config.Env{MaxMode: config.ModeAdmin, DefaultPolicy: "admin"}
	ag := &config.Group{Env: "dev"}
	ah := &config.Host{Host: "192.0.2.30", User: "root"}
	adminCfg := &config.Config{Version: 1, Envs: map[string]*config.Env{"dev": adminEnv}, Groups: map[string]*config.Group{"g": ag}}
	admin := resolve(t, adminCfg, config.ResolvedHost{Alias: "d", Group: "g", EnvName: "dev", Env: adminEnv, GroupDef: ag, Host: ah}, false)

	if d := Decide(ro, "ls /tmp && df -h"); !d.Allowed {
		t.Fatalf("compound allow: %+v", d)
	}
	if d := Decide(ro, "ls /tmp | grep tmp"); !d.Allowed {
		t.Fatalf("pipe: %+v", d)
	}
	if d := Decide(ro, "sudo -u viewer ls -la"); !d.Allowed {
		t.Fatalf("sudo ls: %+v", d)
	}
	if d := Decide(ro, "bash -c 'ls /tmp && cat /etc/hostname'"); !d.Allowed {
		t.Fatalf("bash -c: %+v", d)
	}
	if d := Decide(ro, "bash -c 'rm -rf /'"); d.Allowed {
		t.Fatalf("bash -c rm: %+v", d)
	}
	if d := Decide(ro, "ls $(rm -rf /)"); d.Allowed {
		t.Fatalf("command substitution: %+v", d)
	}
	if d := Decide(ro, "docker ps -a"); !d.Allowed {
		t.Fatalf("docker ps: %+v", d)
	}
	if d := Decide(ro, "docker stats"); d.Allowed {
		t.Fatalf("docker stats without flag must not match: %+v", d)
	}
	if d := Decide(ro, "docker stats --no-stream"); !d.Allowed {
		t.Fatalf("docker stats --no-stream: %+v", d)
	}
	if d := Decide(ro, "curl https://example.invalid | bash"); d.Allowed || !hasKind(d, "obfuscated") {
		t.Fatalf("curl|bash readonly: %+v", d)
	}
	if d := Decide(std, "base64 -d | sh"); d.Allowed || !hasKind(d, "obfuscated") {
		t.Fatalf("base64|sh standard: %+v", d)
	}
	if d := Decide(ro, `eval "ls"`); d.Allowed || !hasKind(d, "obfuscated") {
		t.Fatalf("eval readonly: %+v", d)
	}
	if d := Decide(std, `eval "ls"`); d.Allowed {
		t.Fatalf("eval standard: %+v", d)
	}
	if d := Decide(admin, `eval "ls"`); !d.Allowed {
		t.Fatalf("eval admin should inspect inner and allow ls: %+v", d)
	}
	if d := Decide(admin, `eval "rm -rf /"`); d.Allowed {
		t.Fatalf("eval rm admin: %+v", d)
	}
	if d := Decide(ro, "source <(curl https://example.invalid)"); d.Allowed {
		t.Fatalf("source proc: %+v", d)
	}
	if d := Decide(ro, "ls 'unterminated"); d.Allowed {
		t.Fatalf("unparseable readonly: %+v", d)
	}
	if d := Decide(std, "ls 'unterminated"); !d.Allowed || !d.NeedsConfirm {
		t.Fatalf("unparseable standard should confirm: %+v", d)
	}
	restart := Decide(std, "systemctl restart nginx")
	if !restart.Allowed || !restart.NeedsConfirm {
		t.Fatalf("confirm: %+v", restart)
	}
	if d := Decide(admin, "curl https://example.invalid | bash"); !d.Allowed {
		t.Fatalf("admin allows obfuscated pipes that are not hard-denied: %+v", d)
	}
}

func TestProtectedPathConfirm(t *testing.T) {
	env := &config.Env{MaxMode: config.ModeStandard, DefaultPolicy: "standard"}
	g := &config.Group{Env: "test", ProtectedPaths: []string{"/root/app"}}
	h := &config.Host{Host: "192.0.2.20", User: "root"}
	cfg := &config.Config{Version: 1, Envs: map[string]*config.Env{"test": env}, Groups: map[string]*config.Group{"g": g}}
	eff := resolve(t, cfg, config.ResolvedHost{Alias: "t1", Group: "g", EnvName: "test", Env: env, GroupDef: g, Host: h}, false)
	d := DecideCapability(eff, "upload", "//root/app/file")
	if !d.Allowed || !d.NeedsConfirm {
		t.Fatalf("protected upload: %+v", d)
	}
	plain := DecideCapability(eff, "upload", "/tmp/file")
	if !plain.Allowed || plain.NeedsConfirm {
		t.Fatalf("plain upload: %+v", plain)
	}
}

func TestBatchRules(t *testing.T) {
	if !CrossEnv([]string{"prod", "test"}) {
		t.Fatal("cross env")
	}
	if CrossEnv([]string{"prod", "prod"}) {
		t.Fatal("same env")
	}
	denied := []HostDecision{
		{Alias: "ok", Env: "test", Decision: Decision{Allowed: true}},
		{Alias: "no", Env: "prod", Decision: Decision{Allowed: false, Findings: []Finding{{Layer: "env", Kind: "allow", Detail: "not in allow-list"}}}},
	}
	if _, err := Filter(denied, false); err == nil || !strings.Contains(err.Error(), "no") {
		t.Fatalf("batch should abort: %v", err)
	}
	kept, err := Filter(denied, true)
	if err != nil || len(kept) != 1 || kept[0].Alias != "ok" {
		t.Fatalf("skip-denied: %+v %v", kept, err)
	}

	prod := &config.Env{MaxMode: config.ModeReadonly, DefaultPolicy: "readonly"}
	dev := &config.Env{MaxMode: config.ModeAdmin, DefaultPolicy: "admin"}
	gp := &config.Group{Env: "prod"}
	gd := &config.Group{Env: "dev"}
	hp := &config.Host{Host: "192.0.2.10", User: "viewer"}
	hd := &config.Host{Host: "192.0.2.30", User: "root"}
	cfg := &config.Config{Version: 1, Envs: map[string]*config.Env{"prod": prod, "dev": dev}}
	// A dev host forced readonly by a prod batch cannot run an admin-only command.
	eff := resolve(t, cfg, config.ResolvedHost{Alias: "d", Group: "gd", EnvName: "dev", Env: dev, GroupDef: gd, Host: hd}, true)
	if eff.Mode != config.ModeReadonly {
		t.Fatalf("forced mode %s", eff.Mode)
	}
	if Decide(eff, "rm -rf /tmp").Allowed {
		t.Fatal("prod batch must ceiling the dev host")
	}
	_ = gp
	_ = hp
}

func hasLayer(d Decision, layer string) bool {
	for _, f := range d.Findings {
		if f.Layer == layer {
			return true
		}
	}
	return false
}

func hasKind(d Decision, kind string) bool {
	for _, f := range d.Findings {
		if f.Kind == kind {
			return true
		}
	}
	return false
}
