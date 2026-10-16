package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/sshtest"
)

func TestExecArgvPolicyShowAndUploadMeta(t *testing.T) {
	ttyCheck = func() bool { return false }
	t.Cleanup(func() { ttyCheck = defaultTTY })
	srv, err := sshtest.Start("tester", "s3cret-quote", nil)
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
	code, _, errb := runIn("s3cret-quote\n", "host", "add", "box", "--group", "sandbox", "--host", host, "--port", port, "--user", "tester", "--password-stdin", "--set-default")
	if code != 0 {
		t.Fatalf("host %d %s", code, errb)
	}

	type execBody struct {
		Results []struct {
			Stdout   string `json:"stdout"`
			ExitCode int    `json:"exitCode"`
			Status   string `json:"status"`
			Outcome  string `json:"outcome"`
		} `json:"results"`
		Warnings []string `json:"warnings"`
	}
	execJSON := func(stdin string, args ...string) execBody {
		t.Helper()
		code, out, errb := runIn(stdin, args...)
		if code != 0 {
			t.Fatalf("%v: %d\n%s\n%s", args, code, out, errb)
		}
		var body execBody
		if err := json.Unmarshal([]byte(out), &body); err != nil {
			t.Fatalf("json %v\n%s", err, out)
		}
		if len(body.Results) != 1 || body.Results[0].Status != "ok" || body.Results[0].Outcome != "completed" {
			t.Fatalf("result %+v", body)
		}
		return body
	}

	body := execJSON("", "exec", "-H", "box", "--json", "--", "printf", "%s", `{"k":"v"}`)
	if body.Results[0].Stdout != `{"k":"v"}` {
		t.Fatalf("json body %q", body.Results[0].Stdout)
	}
	body = execJSON("", "exec", "-H", "box", "--json", "--", "printf", "%s", `say "hi"`)
	if body.Results[0].Stdout != `say "hi"` {
		t.Fatalf("nested quotes %q", body.Results[0].Stdout)
	}
	body = execJSON("", "exec", "-H", "box", "--json", "--", "printf %s single-ok")
	if body.Results[0].Stdout != "single-ok" {
		t.Fatalf("single arg %q", body.Results[0].Stdout)
	}
	body = execJSON("", "exec", "-H", "box", "--json", "--", "echo", "hello-audit")
	if !strings.Contains(body.Results[0].Stdout, "hello-audit") {
		t.Fatalf("simple echo %q", body.Results[0].Stdout)
	}

	a := filepath.Join(dir, "dir-a")
	b := filepath.Join(dir, "dir-b")
	code, out, errb := run("exec", "-H", "box", "--", "sh", "-c", "mkdir -p "+a+" "+b)
	if code != 0 {
		t.Fatalf("mkdir %d\n%s\n%s", code, out, errb)
	}
	for _, p := range []string{a, b} {
		info, err := os.Stat(p)
		if err != nil || !info.IsDir() {
			t.Fatalf("missing %s: %v", p, err)
		}
	}

	body = execJSON("piped-body", "exec", "-H", "box", "--forward-stdin", "--json", "--", "cat")
	if body.Results[0].Stdout != "piped-body" {
		t.Fatalf("stdin %q", body.Results[0].Stdout)
	}
	body = execJSON("piped-body", "exec", "-H", "box", "--json", "--", "cat")
	if body.Results[0].Stdout != "" {
		t.Fatalf("stdin forwarded without the flag: %q", body.Results[0].Stdout)
	}
	code, _, errb = run("exec", "--daemon", "--forward-stdin", "-H", "box", "--", "cat")
	if code != 250 || !strings.Contains(errb, "--forward-stdin") {
		t.Fatalf("daemon stdin %d %s", code, errb)
	}

	code, _, errb = run("exec", "-H", "box", "--", "docker", "stop", "nginx")
	if code != 253 {
		t.Fatalf("docker stop %d %s", code, errb)
	}
	code, _, errb = run("exec", "-H", "box", "--", "docker", "start", "nginx")
	if code != 253 {
		t.Fatalf("docker start %d %s", code, errb)
	}

	code, out, errb = run("policy", "show", "-H", "box")
	if code != 0 || !strings.Contains(out, "env-rules maxMode=admin defaultPolicy=standard noDataOutflow=false breakGlass=false") {
		t.Fatalf("policy show %d\n%s\n%s", code, out, errb)
	}
	if !strings.Contains(out, "docker restart") || !strings.Contains(out, "equivalence docker restart also matches docker stop, docker start, docker kill") {
		t.Fatalf("equivalence missing\n%s", out)
	}
	if !strings.Contains(out, "protected") && strings.Contains(out, "confirm (none)") {
		t.Fatalf("confirm list missing\n%s", out)
	}
	code, out, errb = run("policy", "show", "-H", "box", "--json")
	if code != 0 || !strings.Contains(out, `"noDataOutflow": false`) || !strings.Contains(out, `"maxMode": "admin"`) || !strings.Contains(out, "docker stop") {
		t.Fatalf("policy json %d\n%s\n%s", code, out, errb)
	}
	code, out, errb = run("policy", "explain", "-H", "box", "--", "curl", "-d", `{"k":"v"}`)
	if code != 0 || !strings.Contains(out, `{"k":"v"}`) || !strings.Contains(out, "ALLOW") {
		t.Fatalf("explain %d\n%s\n%s", code, out, errb)
	}

	body = execJSON("", "exec", "-H", "box", "--json", "--", "printf", "%s", `D:/soft/git/Git/etc/nginx`)
	if body.Results[0].Stdout != `D:/soft/git/Git/etc/nginx` || len(body.Warnings) != 1 || !strings.Contains(body.Warnings[0], "/etc/nginx") {
		t.Fatalf("msys %+v", body)
	}

	local := filepath.Join(dir, "payload.txt")
	payload := []byte("hello-upload")
	if err := os.WriteFile(local, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	remote := filepath.Join(dir, "remote-payload.txt")
	sum := sha256.Sum256(payload)
	code, out, errb = run("upload", "-H", "box", "--json", local, remote)
	if code != 0 {
		t.Fatalf("upload %d\n%s\n%s", code, out, errb)
	}
	var up struct {
		Op      string `json:"op"`
		Results []struct {
			Bytes      int64    `json:"bytes"`
			DurationMS int64    `json:"durationMs"`
			SHA256     string   `json:"sha256"`
			Backups    []string `json:"backups"`
			Error      string   `json:"error"`
		} `json:"results"`
	}
	if err := json.Unmarshal([]byte(out), &up); err != nil {
		t.Fatal(err)
	}
	if up.Op != "upload" || len(up.Results) != 1 || up.Results[0].Error != "" || up.Results[0].Bytes != int64(len(payload)) || up.Results[0].SHA256 != hex.EncodeToString(sum[:]) || up.Results[0].DurationMS < 0 {
		t.Fatalf("upload json %+v", up)
	}
	next := []byte("hello-replaced")
	if err := os.WriteFile(local, next, 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, errb = run("upload", "-H", "box", "--backup", "--json", local, remote)
	if code != 0 {
		t.Fatalf("backup upload %d\n%s\n%s", code, out, errb)
	}
	if err := json.Unmarshal([]byte(out), &up); err != nil {
		t.Fatal(err)
	}
	if len(up.Results) != 1 || len(up.Results[0].Backups) != 1 {
		t.Fatalf("backup json %+v", up)
	}
	backed, err := os.ReadFile(up.Results[0].Backups[0])
	if err != nil || string(backed) != string(payload) {
		t.Fatalf("backup contents %q %v", backed, err)
	}
	got, err := os.ReadFile(remote)
	if err != nil || string(got) != string(next) {
		t.Fatalf("replaced %q %v", got, err)
	}
	code, _, errb = run("upload", "-H", "box", "--confirm-overwrite", local, remote)
	if code != 253 {
		t.Fatalf("confirm overwrite %d %s", code, errb)
	}
	got, err = os.ReadFile(remote)
	if err != nil || string(got) != string(next) {
		t.Fatalf("confirm overwrite changed the file %q %v", got, err)
	}
}
