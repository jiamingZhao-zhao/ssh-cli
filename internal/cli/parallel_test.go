package cli

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/sshtest"
)

func TestExecParallelMatchesBatchLimits(t *testing.T) {
	ttyCheck = func() bool { return false }
	t.Cleanup(func() { ttyCheck = defaultTTY })

	srv, err := sshtest.Start("tester", "s3cret-par", nil)
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
		code := Execute(append([]string{"--config", dir}, args...), strings.NewReader(""), &out, &errb)
		return code, out.String(), errb.String()
	}
	runIn := func(stdin string, args ...string) (int, string, string) {
		t.Helper()
		var out, errb strings.Builder
		code := Execute(append([]string{"--config", dir}, args...), strings.NewReader(stdin), &out, &errb)
		return code, out.String(), errb.String()
	}
	mustOK := func(stdin string, args ...string) {
		t.Helper()
		code, out, errb := runIn(stdin, args...)
		if code != 0 {
			t.Fatalf("%v: %d\n%s\n%s", args, code, out, errb)
		}
	}

	mustOK("", "group", "add", "lab", "--env", "dev")
	mustOK("s3cret-par\n", "host", "add", "a", "--group", "lab", "--host", host, "--port", port, "--user", "tester", "--password-stdin")
	mustOK("s3cret-par\n", "host", "add", "b", "--group", "lab", "--host", host, "--port", port, "--user", "tester", "--password-stdin")

	code, _, errb := run("exec", "--parallel", "0", "-H", "a", "--", "true")
	if code != 250 || !strings.Contains(errb, "--parallel must be from 1 to 4") {
		t.Fatalf("parallel 0: %d %s", code, errb)
	}
	code, _, errb = run("exec", "--parallel", "5", "-H", "a", "--", "true")
	if code != 250 || !strings.Contains(errb, "--parallel must be from 1 to 4") {
		t.Fatalf("parallel 5: %d %s", code, errb)
	}

	marker := filepath.Join(dir, "order.txt")
	script := fmt.Sprintf("echo start >> %s; sleep 0.6; echo end >> %s", marker, marker)
	code, out, errb := run("exec", "-H", "a", "-H", "b", "--parallel", "2", "--", script)
	if code != 0 {
		t.Fatalf("parallel exec: %d\n%s\n%s", code, out, errb)
	}
	if !strings.Contains(out, "start") && !strings.Contains(errb, "a") {
		t.Fatalf("missing host output\n%s\n%s", out, errb)
	}
	raw, err := os.ReadFile(marker)
	if err != nil {
		t.Fatal(err)
	}
	order := string(raw)
	starts := strings.Count(order, "start")
	if starts != 2 || strings.Count(order, "end") != 2 {
		t.Fatalf("order log: %q", order)
	}
	if strings.Index(order, "start") == strings.LastIndex(order, "start") {
		t.Fatal("expected two start lines")
	}
	secondStart := strings.LastIndex(order, "start")
	firstEnd := strings.Index(order, "end")
	if firstEnd >= 0 && firstEnd < secondStart {
		t.Fatalf("hosts ran one after another:\n%s", order)
	}

	code, out, errb = run("--json", "exec", "-H", "a", "-H", "b", "--parallel", "2", "--", "echo", "par-ok")
	if code != 0 {
		t.Fatalf("json parallel: %d\n%s\n%s", code, out, errb)
	}
	var body struct {
		Results []struct {
			Host   string `json:"host"`
			Stdout string `json:"stdout"`
		} `json:"results"`
	}
	if err := json.Unmarshal([]byte(out), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Results) != 2 {
		t.Fatalf("results: %+v", body.Results)
	}
	seen := map[string]bool{}
	for _, row := range body.Results {
		seen[row.Host] = true
		if !strings.Contains(row.Stdout, "par-ok") {
			t.Fatalf("stdout %s: %q", row.Host, row.Stdout)
		}
	}
	if !seen["a"] || !seen["b"] {
		t.Fatalf("hosts: %+v", body.Results)
	}

	for i := 0; i < 17; i++ {
		alias := fmt.Sprintf("h%02d", i)
		mustOK("s3cret-par\n", "host", "add", alias, "--group", "lab", "--host", "192.0.2.10", "--user", "viewer", "--password-stdin")
	}
	code, _, errb = run("exec", "-g", "lab", "--parallel", "2", "--", "true")
	if code != 250 || !strings.Contains(errb, "at most 16 hosts") {
		t.Fatalf("host cap: %d %s", code, errb)
	}
}
