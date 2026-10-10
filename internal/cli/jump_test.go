package cli

import (
	"net"
	"strings"
	"testing"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/sshtest"
)

func TestJumpExecSessionIsDestination(t *testing.T) {
	ttyCheck = func() bool { return false }
	t.Cleanup(func() { ttyCheck = defaultTTY })

	jump, err := sshtest.Start("jumper", "jump-secret", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(jump.Close)
	dest, err := sshtest.Start("destuser", "dest-secret", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(dest.Close)
	jHost, jPort, err := net.SplitHostPort(jump.Addr)
	if err != nil {
		t.Fatal(err)
	}
	dHost, dPort, err := net.SplitHostPort(dest.Addr)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	runIn := func(stdin string, args ...string) (int, string, string) {
		t.Helper()
		var out, errb strings.Builder
		code := Execute(append([]string{"--config", dir}, args...), strings.NewReader(stdin), &out, &errb)
		return code, out.String(), errb.String()
	}
	run := func(args ...string) (int, string, string) {
		t.Helper()
		return runIn("", args...)
	}
	mustOK := func(args ...string) {
		t.Helper()
		code, out, errb := run(args...)
		if code != 0 {
			t.Fatalf("%v: %d\n%s\n%s", args, code, out, errb)
		}
	}
	mustOK("group", "add", "sandbox", "--env", "dev")
	code, _, errb := runIn("jump-secret\n", "host", "add", "jump", "--group", "sandbox", "--host", jHost, "--port", jPort, "--user", "jumper", "--password-stdin")
	if code != 0 {
		t.Fatalf("add jump %d %s", code, errb)
	}
	code, _, errb = runIn("dest-secret\n", "host", "add", "box", "--group", "sandbox", "--host", dHost, "--port", dPort, "--user", "destuser", "--password-stdin", "--via", "jump")
	if code != 0 {
		t.Fatalf("add box %d %s", code, errb)
	}
	code, out, errb := run("host", "list", "--json")
	if code != 0 || !strings.Contains(out, `"via": "jump"`) {
		t.Fatalf("list %d\n%s\n%s", code, out, errb)
	}

	code, out, errb = run("exec", "-H", "jump", "--", "echo", "direct-ok")
	if code != 0 || !strings.Contains(out, "direct-ok") {
		t.Fatalf("direct exec %d\n%s\n%s", code, out, errb)
	}
	if jump.Sessions() != 1 {
		t.Fatalf("direct dial sessions %d", jump.Sessions())
	}

	code, out, errb = run("exec", "-H", "box", "--", "echo", "dest-ok")
	if code != 0 || !strings.Contains(out, "dest-ok") {
		t.Fatalf("jump exec %d\n%s\n%s", code, out, errb)
	}
	if jump.Sessions() != 1 || dest.Sessions() != 1 {
		t.Fatalf("after jump exec jump=%d dest=%d", jump.Sessions(), dest.Sessions())
	}
	raw := readAuditDir(t, dir)
	if !strings.Contains(raw, `"op":"exec"`) || !strings.Contains(raw, `"host":"box"`) || !strings.Contains(raw, `"source":"cli"`) {
		t.Fatalf("audit\n%s", raw)
	}

	code, _, errb = run("host", "edit", "jump", "--via", "box")
	if code == 0 || !strings.Contains(errb, "cycle") {
		t.Fatalf("cycle edit %d %s", code, errb)
	}
	code, _, errb = runIn("x\n", "host", "add", "ghost", "--group", "sandbox", "--host", "192.0.2.9", "--user", "ops", "--password-stdin", "--via", "missing")
	if code == 0 || !strings.Contains(errb, "does not exist") {
		t.Fatalf("missing via %d %s", code, errb)
	}
	code, _, errb = run("host", "remove", "jump")
	if code == 0 || !strings.Contains(errb, "jump host") {
		t.Fatalf("remove jump %d %s", code, errb)
	}
	mustOK("host", "edit", "box", "--clear-via")
	code, out, errb = run("host", "list", "--json")
	if code != 0 || strings.Contains(out, `"via"`) {
		t.Fatalf("cleared via\n%s\n%s", out, errb)
	}
	code, out, errb = run("exec", "-H", "box", "--", "echo", "direct-box")
	if code != 0 || !strings.Contains(out, "direct-box") || dest.Sessions() != 2 {
		t.Fatalf("direct after clear %d sessions=%d\n%s\n%s", code, dest.Sessions(), out, errb)
	}
}
