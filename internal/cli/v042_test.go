package cli

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/audit"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/sshtest"
)

func TestConfigImportRecreateNeedsConfirm(t *testing.T) {
	ttyCheck = func() bool { return false }
	t.Cleanup(func() { ttyCheck = defaultTTY })
	dir := t.TempDir()
	run := func(args ...string) (int, string, string) {
		t.Helper()
		var out, errb strings.Builder
		code := Execute(append([]string{"--config", dir}, args...), strings.NewReader("s3cret-import\n"), &out, &errb)
		return code, out.String(), errb.String()
	}
	must := func(args ...string) {
		t.Helper()
		code, out, errb := run(args...)
		if code != 0 {
			t.Fatalf("%v: %d\n%s\n%s", args, code, out, errb)
		}
	}
	must("group", "add", "app", "--env", "prod")
	must("host", "add", "main", "--group", "app", "--host", "192.0.2.10", "--user", "ops", "--password-stdin")
	writeBundle := func(name, body string) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	keep := writeBundle("keep.yaml", `
kind: ssh-cli-config
version: 1
groups:
  app:
    env: prod
    hosts:
      main:
        host: 192.0.2.10
        port: 22
        user: ops
        auth: password
        passwordRef: app.main
      spare:
        host: 198.51.100.8
        user: ops
        auth: key
        identity: ~/.ssh/id_spare
`)
	must("config", "import", keep)
	gone := writeBundle("gone.yaml", `
kind: ssh-cli-config
version: 1
groups:
  app:
    env: prod
    hosts:
      spare:
        host: 198.51.100.8
        user: ops
        auth: key
        identity: ~/.ssh/id_spare
`)
	must("config", "import", gone)
	back := writeBundle("back.yaml", `
kind: ssh-cli-config
version: 1
groups:
  app:
    env: prod
    hosts:
      spare:
        host: 198.51.100.8
        user: ops
        auth: key
        identity: ~/.ssh/id_spare
      main:
        host: 203.0.113.5
        user: ops
        auth: password
        passwordRef: app.main
`)
	code, _, errb := run("config", "import", back)
	if code != 253 || !strings.Contains(errb, "main") {
		t.Fatalf("recreate %d %s", code, errb)
	}
	auditText := readAuditDir(t, dir)
	if !strings.Contains(auditText, "reuses passwordRef") || !strings.Contains(auditText, "removed main") {
		t.Fatalf("audit\n%s", auditText)
	}
}

func TestNoDataOutflowDiscardsExec(t *testing.T) {
	ttyCheck = func() bool { return false }
	t.Cleanup(func() { ttyCheck = defaultTTY })
	srv, err := sshtest.Start("tester", "s3cret-out", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	host, port, err := net.SplitHostPort(srv.Addr)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	run := func(args ...string) (int, string, string) {
		t.Helper()
		var out, errb strings.Builder
		code := Execute(append([]string{"--config", dir}, args...), strings.NewReader("s3cret-out\n"), &out, &errb)
		return code, out.String(), errb.String()
	}
	must := func(args ...string) {
		t.Helper()
		code, out, errb := run(args...)
		if code != 0 {
			t.Fatalf("%v: %d\n%s\n%s", args, code, out, errb)
		}
	}
	must("env", "add", "locked", "--max-mode", "standard", "--default-policy", "standard", "--no-data-outflow")
	must("group", "add", "g", "--env", "locked")
	must("host", "add", "box", "--group", "g", "--host", host, "--port", port, "--user", "tester", "--password-stdin")
	code, out, errb := run("exec", "-H", "box", "--", "echo", "secret-marker")
	if code != 0 || strings.Contains(out, "secret-marker") || !strings.Contains(errb, "noDataOutflow: command output discarded") {
		t.Fatalf("discard %d\n%s\n%s", code, out, errb)
	}
	if execAuditKept(t, dir, "secret-marker") {
		t.Fatal("audit kept exec stdout")
	}
	code, out, errb = run("exec", "-H", "box", "--allow-outflow", "--", "echo", "secret-marker")
	if code != 253 || strings.Contains(out, "secret-marker") {
		t.Fatalf("unconfirmed outflow %d\n%s\n%s", code, out, errb)
	}
	ttyCheck = func() bool { return true }
	code, out, errb = run("--yes", "--json", "exec", "-H", "box", "--allow-outflow", "--", "echo", "secret-marker")
	if code != 0 || !strings.Contains(out, "secret-marker") {
		t.Fatalf("allowed outflow %d\n%s\n%s", code, out, errb)
	}
}

// execAuditKept reports whether an exec audit record stored marker outside the command field.
func execAuditKept(t *testing.T, dir, marker string) bool {
	t.Helper()
	for _, line := range strings.Split(readAuditDir(t, dir), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var rec audit.Record
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatal(err)
		}
		if rec.Op != audit.OpExec {
			continue
		}
		if strings.Contains(rec.ResultSummary, marker) || strings.Contains(rec.Reason, marker) {
			return true
		}
	}
	return false
}
