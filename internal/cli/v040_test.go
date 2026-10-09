package cli

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/audit"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/sshtest"
)

func TestConfigExportRoundTripAndCleanup(t *testing.T) {
	ttyCheck = func() bool { return false }
	t.Cleanup(func() { ttyCheck = defaultTTY })
	dir := t.TempDir()
	run := func(args ...string) (int, string, string) {
		t.Helper()
		var out, errb strings.Builder
		code := Execute(append([]string{"--config", dir}, args...), strings.NewReader(""), &out, &errb)
		return code, out.String(), errb.String()
	}
	code, _, errb := run("group", "add", "sandbox", "--env", "dev", "--label", "显示名")
	if code != 0 {
		t.Fatal(errb)
	}
	code, _, errb = run("host", "add", "box", "--group", "sandbox", "--host", "192.0.2.10", "--user", "ops", "--identity", "~/.ssh/id_ed25519")
	if code != 0 {
		t.Fatal(errb)
	}
	code, out, errb := run("config", "export")
	if code != 0 {
		t.Fatalf("export %d %s", code, errb)
	}
	if strings.Contains(out, "password:") || !strings.Contains(out, "passwordRef:") && !strings.Contains(out, "identity:") {
		t.Fatalf("bundle\n%s", out)
	}
	if !strings.Contains(out, "id_ed25519") || !strings.Contains(out, "kind: ssh-cli-config") {
		t.Fatalf("bundle\n%s", out)
	}
	bundle := filepath.Join(dir, "bundle.yaml")
	if err := os.WriteFile(bundle, []byte(out), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, errb = run("config", "import", bundle)
	if code != 0 {
		t.Fatal(errb)
	}
	old := time.Now().Add(-40 * 24 * time.Hour)
	if _, err := audit.Append(dir, audit.Record{Op: audit.OpExec, Host: "box", Status: audit.StatusOK, Command: "old", Time: old.Format(time.RFC3339Nano)}); err != nil {
		t.Fatal(err)
	}
	if _, err := audit.Append(dir, audit.Record{Op: audit.OpExec, Host: "box", Status: audit.StatusOK, Command: "new"}); err != nil {
		t.Fatal(err)
	}
	code, out, errb = run("audit", "cleanup")
	if code != 0 {
		t.Fatalf("cleanup %d %s %s", code, out, errb)
	}
	if !strings.Contains(out, "removed=") {
		t.Fatal(out)
	}
	code, out, errb = run("--json", "audit", "list", "--op", "exec", "--page", "1", "--page-size", "10")
	if code != 0 {
		t.Fatal(errb)
	}
	if strings.Contains(out, "old") || !strings.Contains(out, "new") {
		t.Fatalf("page %s", out)
	}
}

func TestRelayCLI(t *testing.T) {
	ttyCheck = func() bool { return false }
	t.Cleanup(func() { ttyCheck = defaultTTY })
	srv, err := sshtest.Start("tester", "relay-secret", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	host, port, err := net.SplitHostPort(srv.Addr)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	run := func(stdin string, args ...string) (int, string, string) {
		t.Helper()
		var out, errb strings.Builder
		code := Execute(append([]string{"--config", dir}, args...), strings.NewReader(stdin), &out, &errb)
		return code, out.String(), errb.String()
	}
	if code, _, errb := run("", "group", "add", "sandbox", "--env", "dev"); code != 0 {
		t.Fatal(errb)
	}
	if code, _, errb := run("relay-secret\n", "host", "add", "left", "--group", "sandbox", "--host", host, "--port", port, "--user", "tester", "--password-stdin"); code != 0 {
		t.Fatal(errb)
	}
	if code, _, errb := run("relay-secret\n", "host", "add", "right", "--group", "sandbox", "--host", host, "--port", port, "--user", "tester", "--password-stdin"); code != 0 {
		t.Fatal(errb)
	}
	from := filepath.Join(t.TempDir(), "from.txt")
	to := filepath.Join(t.TempDir(), "to.txt")
	if err := os.WriteFile(from, []byte("via-relay"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, errb := run("", "relay", "--from", "left:"+from, "--to", "right:"+to)
	if code != 0 {
		t.Fatalf("relay %d\n%s\n%s", code, out, errb)
	}
	got, err := os.ReadFile(to)
	if err != nil || string(got) != "via-relay" {
		t.Fatalf("file %q %v", got, err)
	}
	if !strings.Contains(out, "sha256") {
		t.Fatal(out)
	}
	code, _, errb = run("", "relay", "--from", "left:"+from, "--to", "right:"+to, "-H", "left")
	if code == 0 {
		t.Fatal("relay should refuse -H")
	}
}
