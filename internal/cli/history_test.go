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

func TestHistoryAndList(t *testing.T) {
	ttyCheck = func() bool { return false }
	t.Cleanup(func() { ttyCheck = defaultTTY })
	srv, err := sshtest.Start("tester", "s3cret-hist", nil)
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
	mustOK("group", "add", "sandbox", "--env", "dev")
	code, _, errb := runIn("s3cret-hist\n", "host", "add", "box", "--group", "sandbox", "--host", host, "--port", port, "--user", "tester", "--password-stdin", "--set-default")
	if code != 0 {
		t.Fatalf("host %d %s", code, errb)
	}

	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := os.WriteFile(filepath.Join(home, ".bash_history"), []byte("echo password=s3cret-hist\nls\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, errb := run("history", "-H", "box", "--json")
	if code != 0 {
		t.Fatalf("history %d\n%s\n%s", code, out, errb)
	}
	var hist struct {
		Results []struct {
			Found  bool     `json:"found"`
			Status string   `json:"status"`
			Path   string   `json:"path"`
			Shell  string   `json:"shell"`
			Lines  []string `json:"lines"`
		} `json:"results"`
	}
	if err := json.Unmarshal([]byte(out), &hist); err != nil {
		t.Fatal(err)
	}
	if len(hist.Results) != 1 || !hist.Results[0].Found || hist.Results[0].Shell != "bash" {
		t.Fatalf("happy %#v", hist.Results)
	}
	joined := strings.Join(hist.Results[0].Lines, "\n")
	if strings.Contains(joined, "s3cret-hist") || !strings.Contains(joined, "password=[redacted]") || !strings.Contains(joined, "ls") {
		t.Fatalf("lines %q", joined)
	}
	raw := readAuditDir(t, dir)
	if !strings.Contains(raw, `"op":"history"`) || !strings.Contains(raw, `"source":"cli"`) || strings.Contains(raw, "s3cret-hist") {
		t.Fatalf("audit\n%s", raw)
	}

	emptyHome := t.TempDir()
	t.Setenv("HOME", emptyHome)
	code, out, errb = run("history", "-H", "box", "--json")
	if code != 0 {
		t.Fatalf("missing %d\n%s\n%s", code, out, errb)
	}
	if err := json.Unmarshal([]byte(out), &hist); err != nil {
		t.Fatal(err)
	}
	if hist.Results[0].Found || hist.Results[0].Status != "empty" {
		t.Fatalf("missing result %#v", hist.Results[0])
	}

	badHome := t.TempDir()
	if err := os.Mkdir(filepath.Join(badHome, ".bash_history"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", badHome)
	code, out, errb = run("history", "-H", "box", "--json")
	if code != 0 {
		t.Fatalf("unreadable %d\n%s\n%s", code, out, errb)
	}
	if err := json.Unmarshal([]byte(out), &hist); err != nil {
		t.Fatal(err)
	}
	if hist.Results[0].Found || hist.Results[0].Status != "unreadable" {
		t.Fatalf("unreadable result %#v", hist.Results[0])
	}

	listDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(listDir, "note.txt"), []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, errb = run("ls", "-H", "box", "--json", listDir)
	if code != 0 || !strings.Contains(out, "note.txt") {
		t.Fatalf("ls %d\n%s\n%s", code, out, errb)
	}
	raw = readAuditDir(t, dir)
	if !strings.Contains(raw, `"op":"list"`) || !strings.Contains(raw, `"source":"cli"`) {
		t.Fatalf("list audit\n%s", raw)
	}
	code, _, errb = run("ls", "-H", "box", "--json", filepath.Join(listDir, "missing"))
	if code == 0 {
		t.Fatalf("missing dir succeeded %s", errb)
	}

	mustOK("policy", "add", "tight", "--mode", "readonly", "--allow", "uptime")
	code, out, errb = run("group", "edit", "sandbox", "--policy", "tight")
	if code != 0 {
		t.Fatalf("group edit %d\n%s\n%s", code, out, errb)
	}
	code, _, errb = run("history", "-H", "box", "--json")
	if code != 253 {
		t.Fatalf("denied history %d %s", code, errb)
	}
	code, _, errb = run("ls", "-H", "box", "--json", listDir)
	if code != 253 {
		t.Fatalf("denied ls %d %s", code, errb)
	}
}
