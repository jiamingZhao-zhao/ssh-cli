package guard

import (
	"strings"
	"testing"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/config"
)

func devAdminHost(d *config.DangerousCommands) (*config.Config, config.ResolvedHost) {
	env := &config.Env{MaxMode: config.ModeAdmin, DefaultPolicy: "admin"}
	g := &config.Group{Env: "dev", Policy: "admin"}
	h := &config.Host{Host: "192.0.2.30", User: "root"}
	cfg := &config.Config{
		Version:   1,
		Envs:      map[string]*config.Env{"dev": env, "prod": {MaxMode: config.ModeReadonly, DefaultPolicy: "readonly"}},
		Groups:    map[string]*config.Group{"g": g},
		Dangerous: d,
	}
	return cfg, config.ResolvedHost{Alias: "dev-1", Group: "g", EnvName: "dev", Env: env, GroupDef: g, Host: h}
}

func testStandardHost(envName string, d *config.DangerousCommands) (*config.Config, config.ResolvedHost) {
	env := &config.Env{MaxMode: config.ModeStandard, DefaultPolicy: "standard"}
	if envName == "prod" {
		env = &config.Env{MaxMode: config.ModeReadonly, DefaultPolicy: "readonly"}
	}
	g := &config.Group{Env: envName}
	h := &config.Host{Host: "192.0.2.40", User: "root"}
	cfg := &config.Config{
		Version:   1,
		Envs:      map[string]*config.Env{envName: env},
		Groups:    map[string]*config.Group{"g": g},
		Dangerous: d,
	}
	return cfg, config.ResolvedHost{Alias: "h", Group: "g", EnvName: envName, Env: env, GroupDef: g, Host: h}
}

func TestDangerousCatalogDefaults(t *testing.T) {
	cfg, host := devAdminHost(nil)
	eff := resolve(t, cfg, host, false)
	report := DescribeDangerous(cfg, "dev")
	if report.Enabled || report.EnforcedHere || !report.ScopeDefault || len(report.Catalog) == 0 {
		t.Fatalf("fresh catalog report: %+v", report)
	}
	for _, item := range report.Catalog {
		if item.Selected || item.Active || item.ID == "" || item.Summary == "" {
			t.Fatalf("catalog item should be present and inactive: %+v", item)
		}
	}
	cases := []string{
		"rm -rf /",
		"rm -fr /",
		"rm -rf -- /",
		"sudo rm -rf /",
		"mkfs.ext4 /dev/sdb",
		"dd if=/dev/zero of=/dev/sda bs=1M",
		"chmod 777 /",
		"chown root /",
		"echo ok > /dev/sda",
		":(){ :|:& };:",
	}
	for _, cmd := range cases {
		d := Decide(eff, cmd)
		if !d.Allowed || d.NeedsConfirm || hasKind(d, "deny") {
			t.Errorf("dev %q should not be blocked by the inactive catalog: %+v", cmd, d)
		}
		if !hasKind(d, "catalog") {
			t.Errorf("dev %q should explain the inactive catalog match: %+v", cmd, d.Findings)
		}
	}
	plain := Decide(eff, "rm -rf /tmp")
	if !plain.Allowed || hasKind(plain, "catalog") {
		t.Fatalf("rm of a non-root path is not a catalog rule: %+v", plain)
	}
	safeDD := Decide(eff, "dd if=/dev/zero of=/tmp/x")
	if !safeDD.Allowed || hasKind(safeDD, "catalog") {
		t.Fatalf("dd to a file is not a catalog rule: %+v", safeDD)
	}

	prodCfg, prodHost := prodReadonlyHost("", nil)
	prod := resolve(t, prodCfg, prodHost, false)
	prodReport := DescribeDangerous(prodCfg, "prod")
	if prodReport.EnforcedHere || prodReport.Enabled {
		t.Fatalf("prod catalog should be inactive: %+v", prodReport)
	}
	rm := Decide(prod, "rm -rf /")
	if rm.Allowed || hasLayer(rm, "dangerous") && hasKind(rm, "deny") {
		t.Fatalf("prod rm is denied by the readonly ceiling, not an active catalog rule: %+v", rm)
	}
	if !hasKind(rm, "catalog") || !strings.Contains(findingDetail(rm, "catalog"), "enforcement is off") {
		t.Fatalf("prod explain should say the catalog is off: %+v", rm.Findings)
	}
	redirect := Decide(prod, "echo ok > /dev/sda")
	if redirect.Allowed || !hasLayer(redirect, "mode") {
		t.Fatalf("prod disk redirect stays denied by readonly mode: %+v", redirect)
	}
	ls := Decide(prod, "ls /")
	if !ls.Allowed || hasKind(ls, "catalog") {
		t.Fatalf("prod ls: %+v", ls)
	}
}

func TestDangerousCatalogOptIn(t *testing.T) {
	all := &config.DangerousCommands{Enabled: true, Rules: config.DangerousRuleIDs()}
	devCfg, devHost := devAdminHost(all)
	dev := resolve(t, devCfg, devHost, false)
	devReport := DescribeDangerous(devCfg, "dev")
	if devReport.EnforcedHere || devReport.InScope {
		t.Fatalf("default scope is prod, so dev stays outside: %+v", devReport)
	}
	if d := Decide(dev, "rm -rf /"); !d.Allowed || !strings.Contains(findingDetail(d, "catalog"), "outside the dangerous-command scope") {
		t.Fatalf("dev with prod-only scope: %+v", d)
	}
	if d := Decide(dev, "/bin/rm -rf /"); !d.Allowed {
		t.Fatalf("basename rm on dev: %+v", d)
	}

	prodCfg, prodHost := prodReadonlyHost("", nil)
	prodCfg.Dangerous = all
	prod := resolve(t, prodCfg, prodHost, false)
	prodReport := DescribeDangerous(prodCfg, "prod")
	if !prodReport.EnforcedHere || len(prodReport.Active) != len(config.DangerousRuleIDs()) {
		t.Fatalf("prod should enforce the selected catalog: %+v", prodReport)
	}
	for _, item := range prodReport.Catalog {
		if !item.Selected || !item.Active {
			t.Fatalf("prod catalog item: %+v", item)
		}
	}
	rm := Decide(prod, "sudo rm -rf /")
	if rm.Allowed || !hasLayer(rm, "dangerous") || !hasKind(rm, "deny") {
		t.Fatalf("prod selected rm-root: %+v", rm)
	}
	if d := Decide(prod, "rm -rf /tmp"); d.Allowed {
		t.Fatalf("prod still ceilings non-catalog rm: %+v", d)
	}

	scoped := &config.DangerousCommands{Enabled: true, Envs: []string{"dev"}, Rules: []string{config.DangerRMRoot}}
	scopedCfg, scopedHost := devAdminHost(scoped)
	scopedEff := resolve(t, scopedCfg, scopedHost, false)
	if d := Decide(scopedEff, "/bin/rm -rf /"); d.Allowed || !strings.Contains(findingDetail(d, "deny"), "rm-root") {
		t.Fatalf("selected rm-root on dev: %+v", d)
	}
	if d := Decide(scopedEff, "rm -rf /tmp"); !d.Allowed {
		t.Fatalf("non-root rm: %+v", d)
	}
	if d := Decide(scopedEff, "mkfs.ext4 /dev/sdb"); !d.Allowed || !strings.Contains(findingDetail(d, "catalog"), "not selected") {
		t.Fatalf("unselected mkfs on an enabled dev scope: %+v", d)
	}

	enabledOnly := &config.DangerousCommands{Enabled: true}
	onlyCfg, onlyHost := devAdminHost(enabledOnly)
	if d := Decide(resolve(t, onlyCfg, onlyHost, false), "rm -rf /"); !d.Allowed {
		t.Fatalf("enable with no rules does not block dev: %+v", d)
	}
}

func TestDangerousEnabledWithoutRulesDoesNotReplaceProdCeiling(t *testing.T) {
	cfg, host := prodReadonlyHost("", nil)
	cfg.Dangerous = &config.DangerousCommands{Enabled: true}
	eff := resolve(t, cfg, host, false)
	report := DescribeDangerous(cfg, "prod")
	if report.EnforcedHere || len(report.Active) != 0 {
		t.Fatalf("enabled with an empty list is not enforced: %+v", report)
	}
	d := Decide(eff, "rm -rf /")
	if d.Allowed || hasKind(d, "deny") && hasLayer(d, "dangerous") {
		t.Fatalf("prod ceiling remains, catalog rule is not active: %+v", d)
	}
	if !strings.Contains(findingDetail(d, "catalog"), "not selected") {
		t.Fatalf("prod note: %+v", d.Findings)
	}
}

func TestDangerousExtraPattern(t *testing.T) {
	cfg, host := devAdminHost(&config.DangerousCommands{Enabled: true, Deny: []string{"shutdown"}})
	dev := resolve(t, cfg, host, false)
	if d := Decide(dev, "shutdown -h now"); !d.Allowed || !strings.Contains(findingDetail(d, "catalog"), "outside the dangerous-command scope") {
		t.Fatalf("extra pattern stays off dev by default: %+v", d)
	}
	cfg.Dangerous.Envs = []string{"dev"}
	dev = resolve(t, cfg, host, false)
	if d := Decide(dev, "shutdown -h now"); d.Allowed || !strings.Contains(findingDetail(d, "deny"), "shutdown") {
		t.Fatalf("extra pattern on dev: %+v", d)
	}
	if d := Decide(dev, "uptime"); !d.Allowed {
		t.Fatalf("uptime: %+v", d)
	}
}

func TestNonProdStandardDoesNotBlockCatalog(t *testing.T) {
	cfg, host := testStandardHost("test", nil)
	eff := resolve(t, cfg, host, false)
	if d := Decide(eff, "mkfs.ext4 /dev/sdb"); !d.Allowed {
		t.Fatalf("test env: %+v", d)
	}
	if d := Decide(eff, "systemctl restart nginx"); !d.Allowed || !d.NeedsConfirm {
		t.Fatalf("confirm gate remains: %+v", d)
	}
	if d := Decide(eff, "docker system prune -a"); d.Allowed {
		t.Fatalf("named standard deny remains: %+v", d)
	}
}

func findingDetail(d Decision, kind string) string {
	var parts []string
	for _, f := range d.Findings {
		if f.Kind == kind {
			parts = append(parts, f.Detail)
		}
	}
	return strings.Join(parts, "; ")
}
