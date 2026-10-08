package cli

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/sshtest"
)

func TestAuditDenialsUploadsAndRemoteResults(t *testing.T) {
	ttyCheck = func() bool { return false }
	t.Cleanup(func() { ttyCheck = defaultTTY })
	t.Setenv("SSH_CLI_ACTOR", "agent-test")

	srv, err := sshtest.Start("tester", "s3cret-audit", nil)
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
	mustOK("env", "add", "prod", "--label", "生产", "--max-mode", "readonly", "--default-policy", "readonly")
	mustOK("env", "add", "test", "--label", "测试", "--max-mode", "standard", "--default-policy", "standard")
	mustOK("env", "add", "dev", "--label", "开发", "--max-mode", "admin", "--default-policy", "admin")
	mustOK("group", "add", "app-prod", "--env", "prod")
	mustOK("group", "add", "app-test", "--env", "test")
	mustOK("group", "add", "sandbox", "--env", "dev", "--policy", "admin")
	code, _, errb := runIn("s3cret-audit\n", "host", "add", "main", "--group", "app-prod", "--host", "192.0.2.10", "--user", "viewer", "--password-stdin", "--set-default")
	if code != 0 {
		t.Fatalf("host add main: %d %s", code, errb)
	}
	code, _, errb = runIn("s3cret-audit\n", "host", "add", "web", "--group", "app-test", "--host", "192.0.2.20", "--user", "root", "--password-stdin")
	if code != 0 {
		t.Fatalf("host add web: %d %s", code, errb)
	}
	code, _, errb = runIn("s3cret-audit\n", "host", "add", "box", "--group", "sandbox", "--host", host, "--port", port, "--user", "tester", "--password-stdin")
	if code != 0 {
		t.Fatalf("host add box: %d %s", code, errb)
	}

	code, _, errb = run("exec", "-H", "main", "--", "rm", "-rf", "/")
	if code != 253 || !strings.Contains(errb, "denied") {
		t.Fatalf("rm: %d %s", code, errb)
	}
	code, _, errb = run("exec", "-H", "main", "--", "echo", "password=s3cret-leak")
	if code != 253 {
		t.Fatalf("echo deny: %d %s", code, errb)
	}
	local := filepath.Join(dir, "payload.txt")
	if err := os.WriteFile(local, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, errb = run("upload", "-H", "main", local, "/tmp/payload.txt")
	if code != 253 {
		t.Fatalf("upload deny: %d %s", code, errb)
	}
	code, _, errb = run("exec", "-H", "web", "--", "systemctl", "restart", "nginx")
	if code != 253 {
		t.Fatalf("confirm deny: %d %s", code, errb)
	}

	code, out, errb := run("exec", "-H", "box", "--", "echo", "hello-audit")
	if code != 0 || !strings.Contains(out, "hello-audit") {
		t.Fatalf("echo: %d\n%s\n%s", code, out, errb)
	}
	code, _, errb = run("exec", "-H", "box", "--", "exit", "3")
	if code != 3 {
		t.Fatalf("exit 3: %d %s", code, errb)
	}
	code, _, errb = run("exec", "-H", "box", "--timeout", "1s", "--", "sleep", "30")
	if code != 251 {
		t.Fatalf("timeout: %d %s", code, errb)
	}
	code, _, errb = runIn("s3cret-wrong\n", "host", "edit", "box", "--password-stdin")
	if code != 0 {
		t.Fatalf("edit password: %d %s", code, errb)
	}
	code, _, errb = run("exec", "-H", "box", "--", "true")
	if code != 252 {
		t.Fatalf("auth: %d %s", code, errb)
	}

	raw := readAuditDir(t, dir)
	for _, secret := range []string{"s3cret-audit", "s3cret-leak", "s3cret-wrong"} {
		if strings.Contains(raw, secret) {
			t.Fatalf("audit log contains %s\n%s", secret, raw)
		}
	}
	if !strings.Contains(raw, "password=[redacted]") {
		t.Fatalf("expected redacted password command\n%s", raw)
	}

	code, out, errb = run("audit", "list", "--status", "denied", "--json")
	if code != 0 {
		t.Fatalf("audit list: %d %s", code, errb)
	}
	var listed struct {
		Records []map[string]any `json:"records"`
	}
	if err := json.Unmarshal([]byte(out), &listed); err != nil {
		t.Fatalf("json %v\n%s", err, out)
	}
	var sawRM, sawUpload, sawConfirm bool
	var rmID string
	for _, rec := range listed.Records {
		if rec["status"] != "denied" || rec["denied_by_policy"] != true || rec["op"] != "policy_check" {
			t.Fatalf("record %+v", rec)
		}
		if rec["actor"] != "agent-test" {
			t.Fatalf("actor %+v", rec["actor"])
		}
		cmd, _ := rec["command"].(string)
		switch {
		case strings.Contains(cmd, "rm -rf /"):
			sawRM = true
			if rec["high_risk"] != true {
				t.Fatalf("rm high_risk %+v", rec)
			}
			rmID, _ = rec["id"].(string)
		case strings.Contains(cmd, "systemctl restart nginx"):
			sawConfirm = true
			if rec["high_risk"] != true {
				t.Fatalf("confirm high_risk %+v", rec)
			}
		}
		if dst, ok := rec["dst"].(string); ok && strings.Contains(dst, "payload.txt") {
			sawUpload = true
		}
	}
	if !sawRM || !sawUpload || !sawConfirm || rmID == "" {
		t.Fatalf("missing denial records rm=%v upload=%v confirm=%v\n%s", sawRM, sawUpload, sawConfirm, out)
	}

	code, out, errb = run("audit", "show", rmID, "--json")
	if code != 0 || !strings.Contains(out, "rm -rf /") || !strings.Contains(out, `"high_risk": true`) {
		t.Fatalf("show %d\n%s\n%s", code, out, errb)
	}
	code, out, errb = run("audit", "list", "--host", "box", "--status", "ok", "--json")
	if code != 0 || !strings.Contains(out, "hello-audit") {
		t.Fatalf("ok list %d\n%s\n%s", code, out, errb)
	}
	code, out, errb = run("audit", "list", "--host", "box", "--status", "error", "--since", "24h", "--json")
	if code != 0 || !strings.Contains(out, `"exit_code":3`) {
		t.Fatalf("error list %d\n%s\n%s", code, out, errb)
	}
	code, out, errb = run("audit", "list", "--host", "box", "--status", "timeout", "--json")
	if code != 0 || !strings.Contains(out, "sleep 30") {
		t.Fatalf("timeout list %d\n%s\n%s", code, out, errb)
	}
	code, out, errb = run("audit", "list", "--host", "box", "--status", "auth", "--json")
	if code != 0 || !strings.Contains(out, `"status":"auth"`) {
		t.Fatalf("auth list %d\n%s\n%s", code, out, errb)
	}
	code, out, errb = run("audit", "tail", "-n", "1")
	if code != 0 || !strings.Contains(out, "auth") {
		t.Fatalf("tail %d\n%s\n%s", code, out, errb)
	}
	code, _, errb = run("audit", "show", "does-not-exist")
	if code == 0 {
		t.Fatal("missing id should fail")
	}

	code, _, errb = run("ui", "--addr", "0.0.0.0:7788")
	if code != 250 || !strings.Contains(errb, "refusing to bind") {
		t.Fatalf("ui bind %d %s", code, errb)
	}
}

func readAuditDir(t *testing.T, dir string) string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(dir, "audit"))
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".jsonl") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, "audit", e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		b.Write(data)
	}
	return b.String()
}
