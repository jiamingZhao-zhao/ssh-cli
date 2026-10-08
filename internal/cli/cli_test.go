package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRejectPlaintextPasswordFlag(t *testing.T) {
	var out, errb bytes.Buffer
	code := Execute([]string{"host", "add", "main", "--password", "secret"}, strings.NewReader(""), &out, &errb)
	if code != 250 {
		t.Fatalf("code %d stderr %s", code, errb.String())
	}
	if !strings.Contains(errb.String(), "refusing plaintext") {
		t.Fatalf("stderr %s", errb.String())
	}
	if strings.Contains(out.String()+errb.String(), "secret") && strings.Contains(errb.String(), "--password secret") {
		t.Fatal("plaintext password was echoed")
	}
}

func TestHostLifecycleAndPolicy(t *testing.T) {
	ttyCheck = func() bool { return false }
	t.Cleanup(func() { ttyCheck = defaultTTY })
	dir := t.TempDir()
	run := func(args ...string) (int, string, string) {
		t.Helper()
		var out, errb bytes.Buffer
		code := Execute(append([]string{"--config", dir}, args...), strings.NewReader(""), &out, &errb)
		return code, out.String(), errb.String()
	}
	code, _, errb := run("env", "add", "prod", "--label", "生产", "--color", "red", "--max-mode", "readonly", "--default-policy", "readonly")
	if code != 0 {
		t.Fatalf("env add: %d %s", code, errb)
	}
	code, _, errb = run("env", "add", "dev", "--label", "开发", "--color", "green", "--max-mode", "admin", "--default-policy", "admin")
	if code != 0 {
		t.Fatalf("env add dev: %d %s", code, errb)
	}
	code, _, errb = run("group", "add", "app-prod", "--env", "prod", "--protected-path", "/root/app")
	if code != 0 {
		t.Fatalf("group add: %d %s", code, errb)
	}
	code, _, errb = run("group", "add", "sandbox", "--env", "dev", "--policy", "admin")
	if code != 0 {
		t.Fatalf("group add sandbox: %d %s", code, errb)
	}
	var out, errb2 bytes.Buffer
	code = Execute([]string{"--config", dir, "host", "add", "main", "--group", "app-prod", "--host", "192.0.2.10", "--user", "viewer", "--password-stdin", "--tag", "app", "--set-default"},
		strings.NewReader("s3cret-value\n"), &out, &errb2)
	if code != 0 {
		t.Fatalf("host add: %d %s", code, errb2.String())
	}
	code, outText, errbText := run("host", "list")
	if code != 0 {
		t.Fatalf("list: %d %s", code, errbText)
	}
	if strings.Contains(outText, "s3cret-value") || strings.Contains(errbText, "s3cret-value") {
		t.Fatal("host list leaked the password")
	}
	yamlBytes, err := os.ReadFile(filepath.Join(dir, "hosts.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	secBytes, err := os.ReadFile(filepath.Join(dir, "secrets.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(yamlBytes), "s3cret-value") || strings.Contains(string(secBytes), "s3cret-value") {
		t.Fatal("password was stored in plaintext")
	}
	if !strings.Contains(outText, "main") || !strings.Contains(outText, "password") {
		t.Fatalf("list output: %s", outText)
	}
	code, _, errbText = run("host", "edit", "main", "--port", "2222")
	if code != 0 {
		t.Fatalf("edit: %d %s", code, errbText)
	}
	code, outText, _ = run("host", "list", "--json")
	if code != 0 || !strings.Contains(outText, "2222") || strings.Contains(outText, "s3cret-value") {
		t.Fatalf("json list: %s", outText)
	}
	code, outText, errbText = run("policy", "show", "-H", "main")
	if code != 0 {
		t.Fatalf("policy show: %d %s", code, errbText)
	}
	if !strings.Contains(outText, "readonly") {
		t.Fatalf("show: %s", outText)
	}
	code, outText, _ = run("policy", "explain", "-H", "main", "--", "ls", "-la")
	if code != 0 || !strings.Contains(outText, "ALLOW") {
		t.Fatalf("explain ls code %d\n%s", code, outText)
	}
	code, outText, _ = run("policy", "explain", "-H", "main", "--", "rm", "-rf", "/")
	if code != 253 || !strings.Contains(outText, "DENY") {
		t.Fatalf("explain rm code %d\n%s", code, outText)
	}
	code, _, errbText = run("--yes", "policy", "explain", "-H", "main", "--", "ls")
	if code != 253 || !strings.Contains(errbText, "--yes") {
		t.Fatalf("--yes without tty: %d %s", code, errbText)
	}
	code, _, errbText = run("group", "set-env", "app-prod", "nope")
	if code == 0 {
		t.Fatal("set-env should reject unknown env")
	}
	code, _, _ = run("version")
	if code != 0 {
		t.Fatal("version")
	}
}

func TestConfirmRequiresAlias(t *testing.T) {
	var buf bytes.Buffer
	if err := confirmFrom("main", strings.NewReader("nope\n"), &buf); err == nil {
		t.Fatal("expected mismatch")
	}
	if err := confirmFrom("main", strings.NewReader("main\n"), &buf); err != nil {
		t.Fatal(err)
	}
}
