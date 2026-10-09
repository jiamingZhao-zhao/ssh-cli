package cli

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/sshtest"
)

func TestSessionRunKeepsDirectory(t *testing.T) {
	ttyCheck = func() bool { return false }
	t.Cleanup(func() { ttyCheck = defaultTTY })
	srv, err := sshtest.Start("tester", "s3cret-session", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	host, port, err := net.SplitHostPort(srv.Addr)
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
	code, _, errb := runIn("", "group", "add", "sandbox", "--env", "dev")
	if code != 0 {
		t.Fatal(errb)
	}
	code, _, errb = runIn("s3cret-session\n", "host", "add", "box", "--group", "sandbox", "--host", host, "--port", port, "--user", "tester", "--password-stdin")
	if code != 0 {
		t.Fatal(errb)
	}
	code, out, errb := runIn("", "session", "run", "-H", "box", "--command", "cd /tmp", "--command", "pwd")
	if code != 0 {
		t.Fatalf("session %d\n%s\n%s", code, out, errb)
	}
	if !strings.Contains(out, "/tmp") {
		t.Fatalf("stdout %q", out)
	}
	auditText, err := os.ReadFile(newestAudit(t, dir))
	if err != nil {
		t.Fatal(err)
	}
	text := string(auditText)
	if !strings.Contains(text, `"op":"session"`) || !strings.Contains(text, "process_exit") || !strings.Contains(text, `"reason":"open"`) {
		t.Fatalf("audit\n%s", text)
	}
	if strings.Contains(text, "s3cret-session") {
		t.Fatal("password leaked into audit")
	}
}

func newestAudit(t *testing.T, dir string) string {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(dir, "audit", "*.jsonl"))
	if err != nil || len(matches) == 0 {
		t.Fatalf("audit files: %v %v", matches, err)
	}
	return matches[len(matches)-1]
}
