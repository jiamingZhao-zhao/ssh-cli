package cli

import (
	"strings"
	"testing"
)

func TestDangerousCommandDefaults(t *testing.T) {
	ttyCheck = func() bool { return false }
	t.Cleanup(func() { ttyCheck = defaultTTY })
	dir := t.TempDir()
	run := func(args ...string) (int, string, string) {
		t.Helper()
		var out, errb strings.Builder
		code := Execute(append([]string{"--config", dir}, args...), strings.NewReader(""), &out, &errb)
		return code, out.String(), errb.String()
	}
	must := func(args ...string) string {
		t.Helper()
		code, out, errb := run(args...)
		if code != 0 {
			t.Fatalf("%v: %d\n%s\n%s", args, code, out, errb)
		}
		return out
	}
	show := must("policy", "dangerous")
	if !strings.Contains(show, "enabled false") || !strings.Contains(show, "enforcement off until enabled") || !strings.Contains(show, "rm-root") || !strings.Contains(show, "[suggested]") {
		t.Fatalf("fresh catalog:\n%s", show)
	}
	must("group", "add", "app-prod", "--env", "prod")
	must("group", "add", "sandbox", "--env", "dev", "--policy", "admin")
	must("host", "add", "main", "--group", "app-prod", "--host", "192.0.2.10", "--user", "viewer", "--identity", "key", "--set-default")
	must("host", "add", "box", "--group", "sandbox", "--host", "192.0.2.30", "--user", "root", "--identity", "key")

	text := must("policy", "show", "-H", "box")
	if !strings.Contains(text, "enforced-here=false") || !strings.Contains(text, "dangerous-catalog rm-root [inactive]") || !strings.Contains(text, "scope=prod (default)") {
		t.Fatalf("dev show:\n%s", text)
	}
	js := must("policy", "show", "-H", "main", "--json")
	if !strings.Contains(js, `"enforcedHere": false`) || !strings.Contains(js, `"id": "rm-root"`) || !strings.Contains(js, `"active": false`) {
		t.Fatalf("prod json:\n%s", js)
	}
	code, out, errb := run("policy", "explain", "-H", "box", "--", "rm", "-rf", "/")
	if code != 0 || !strings.Contains(out, "ALLOW") || !strings.Contains(out, "enforcement is off") {
		t.Fatalf("dev explain %d\n%s\n%s", code, out, errb)
	}
	code, out, errb = run("policy", "explain", "-H", "main", "--", "rm", "-rf", "/")
	if code != 253 || !strings.Contains(out, "DENY") || !strings.Contains(out, "enforcement is off") || strings.Contains(out, "catalog rm-root:") {
		t.Fatalf("prod explain %d\n%s\n%s", code, out, errb)
	}
	if !strings.Contains(out, "readonly") && !strings.Contains(out, "allow") {
		t.Fatalf("prod denial should cite the ceiling:\n%s", out)
	}

	must("policy", "dangerous", "set", "--enable", "--rule", "rm-root")
	code, out, errb = run("policy", "explain", "-H", "box", "--", "rm", "-rf", "/")
	if code != 0 || !strings.Contains(out, "ALLOW") || !strings.Contains(out, "outside the dangerous-command scope") {
		t.Fatalf("dev still outside scope %d\n%s\n%s", code, out, errb)
	}
	code, out, errb = run("policy", "explain", "-H", "main", "--", "rm", "-rf", "/")
	if code != 253 || !strings.Contains(out, "catalog rm-root:") || !strings.Contains(out, "dangerous deny") {
		t.Fatalf("prod selected rule %d\n%s\n%s", code, out, errb)
	}
	shown := must("policy", "show", "-H", "main")
	if !strings.Contains(shown, "enforced-here=true") || !strings.Contains(shown, "dangerous-catalog rm-root [active]") || !strings.Contains(shown, "dangerous-catalog mkfs [inactive]") {
		t.Fatalf("prod show after opt-in:\n%s", shown)
	}

	must("policy", "dangerous", "set", "--env", "prod", "--env", "dev")
	code, out, errb = run("policy", "explain", "-H", "box", "--", "rm", "-rf", "/")
	if code != 253 || !strings.Contains(out, "catalog rm-root:") {
		t.Fatalf("dev opted in %d\n%s\n%s", code, out, errb)
	}
	code, out, errb = run("policy", "explain", "-H", "box", "--", "mkfs.ext4", "/dev/sdb")
	if code != 0 || !strings.Contains(out, "not selected") {
		t.Fatalf("unselected mkfs %d\n%s\n%s", code, out, errb)
	}
	code, _, errb = run("policy", "dangerous", "set", "--disable")
	if code != 253 || !strings.Contains(errb, "dangerous") {
		t.Fatalf("shrink without confirmation: %d %s", code, errb)
	}
}
