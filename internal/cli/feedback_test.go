package cli

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/audit"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/config"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/exitcode"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/guard"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/sshtest"
	"golang.org/x/crypto/ssh"
)

func TestFeedbackLogMaskAndWindow(t *testing.T) {
	var output strings.Builder
	start, _ := time.Parse(time.RFC3339, "2026-11-18T14:24:08+08:00")
	end := start.Add(2 * time.Second)
	writer := &logOutput{dst: &output, opts: logOutputOptions{redact: true, since: start, until: end, zone: time.FixedZone("UTC+8", 8*3600)}}
	for _, chunk := range []string{
		"lost preceding line\n2026-11-18 14:24:07 earlier\n",
		"2026-11-18 14:24:08.000 ERROR /api/report Author",
		"ization: Bearer synthetic-header-secret\r\n\tcontinued-secret\n",
		"2026-11-18 14:24:09 request {\"blade-auth\":\"blade-secret\",\"ms\":315}\n",
		"2026-11-18T06:24:10Z ERROR /api/summary\nstack trace retained\n",
		"2026-11-18 14:24:11 later\n", strings.Repeat("a", 1<<17), " secret\n",
	} {
		_, _ = writer.Write([]byte(chunk))
	}
	writer.finish(true)
	text := output.String()
	for _, hidden := range []string{"secret", "earlier", "later", "lost preceding line"} {
		if strings.Contains(text, hidden) {
			t.Fatalf("unwanted %q in %q", hidden, text)
		}
	}
	for _, expected := range []string{"/api/report Authorization: [REDACTED]", `"blade-auth":"[REDACTED]","ms":315`, "stack trace retained"} {
		if !strings.Contains(text, expected) {
			t.Fatalf("missing %q in %q", expected, text)
		}
	}
	if !writer.redacted || !writer.cut || writer.unstamped == 0 {
		t.Fatalf("redaction/window metadata not reported")
	}
	output.Reset()
	filter := &logOutput{dst: &output, opts: logOutputOptions{redact: true, filter: regexp.MustCompile(`^GET /orders`)}}
	_, _ = filter.Write([]byte("GET /users 200\nGET /orders Authorization: secret"))
	filter.finish(true)
	if output.String() != "GET /orders Authorization: [REDACTED]" {
		t.Fatal(output.String())
	}
}

func TestFeedbackReadonlyLoginAndHostAwareExample(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{Version: 1, Groups: map[string]*config.Group{"ops": {Env: "prod", Hosts: map[string]*config.Host{"box": {Host: "192.0.2.1", User: "tester"}}}}}
	if err := config.Save(dir, cfg); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) (int, string) {
		var output, stderr strings.Builder
		code := Execute(append([]string{"--config", dir}, args...), strings.NewReader(""), &output, &stderr)
		return code, output.String() + stderr.String()
	}
	if code, got := run("exec", "-H", "box", "--login", "--", "java", "-version"); code != exitcode.Denied || !strings.Contains(got, "login startup scripts") {
		t.Fatalf("login gate: %d %s", code, got)
	}
	if code, got := run("exec", "-H", "box", "--json", "--", "curl", "-sI", "http://127.0.0.1/"); code != exitcode.Denied || !strings.Contains(got, `"allowedExample":"curl -q`) {
		t.Fatalf("missing policy-checked example: %d %s", code, got)
	}
	if err := config.Update(dir, func(cfg *config.Config) error {
		cfg.Groups["ops"].Hosts["box"].Deny = []string{"curl"}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if code, got := run("exec", "-H", "box", "--json", "--", "curl", "-sI", "http://127.0.0.1/"); code != exitcode.Denied || strings.Contains(got, `"allowedExample"`) || !strings.Contains(got, "no built-in alternative") {
		t.Fatalf("example should respect custom denial: %d %s", code, got)
	}
	if decision := guard.DecideQuery(guard.Effective{}, `bash -l -c 'java -version'`); decision.Allowed {
		t.Fatalf("login startup should not run in readonly: %+v", decision)
	}
}

func TestFeedbackDaemonWaitsOnlyForReadonly(t *testing.T) {
	slots, waiters := make(chan struct{}, 1), make(chan struct{}, 1)
	slots <- struct{}{}
	if err := takeDaemonSlot(context.Background(), slots, waiters, false); err == nil {
		t.Fatal("non-readonly request waited")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()
	if err := takeDaemonSlot(ctx, slots, waiters, true); !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "not started") {
		t.Fatalf("queue expiration: %v", err)
	}
	ctx, cancel = context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- takeDaemonSlot(ctx, slots, waiters, true) }()
	<-slots
	if err := <-result; err != nil || len(slots) != 1 {
		t.Fatalf("queued readonly did not acquire free slot: %v", err)
	}
}

func feedbackCLI(t *testing.T, env string) (*sshtest.Server, string, func(string, ...string) (int, string)) {
	t.Helper()
	srv, err := sshtest.Start("tester", "synthetic-tcp-pass", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	sship, sshport, err := net.SplitHostPort(srv.Addr)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	run := func(stdin string, args ...string) (int, string) {
		t.Helper()
		var output, stderr strings.Builder
		code := Execute(append([]string{"--config", dir}, args...), strings.NewReader(stdin), &output, &stderr)
		return code, output.String() + stderr.String()
	}
	for _, command := range [][]string{{"group", "add", "ops", "--env", env}, {"host", "add", "box", "--group", "ops", "--host", sship, "--port", sshport, "--user", "tester", "--password-stdin"}} {
		if code, output := run("synthetic-tcp-pass\n", command...); code != 0 {
			t.Fatalf("register fixture: %d %s", code, output)
		}
	}
	return srv, dir, run
}

func TestFeedbackTCPConnectFromSSH(t *testing.T) {
	srv, _, run := feedbackCLI(t, "prod")
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	connections := make(chan bool, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			_ = conn.Close()
		}
		connections <- err == nil
	}()
	if code, output := run("", "check", "-H", "box", "--tcp", "192.0.2.80:3306", "--agent-mode"); code != exitcode.Denied || srv.Connections() != 0 {
		t.Fatalf("unregistered target was not rejected before SSH: %d %s", code, output)
	}
	if code, output := run("", "check", "-H", "box", "--tcp", listener.Addr().String(), "--agent-mode"); code != 0 || !strings.Contains(output, `"tcpStatus": "connected"`) {
		t.Fatalf("TCP check: %d %s", code, output)
	}
	select {
	case accepted := <-connections:
		if !accepted || srv.Sessions() != 0 {
			t.Fatal("TCP check did not run as a connect-only SSH channel")
		}
	case <-time.After(time.Second):
		t.Fatal("fixture did not receive the connection")
	}
	if tcpOutcome(&ssh.OpenChannelError{Reason: ssh.ConnectionFailed, Message: "Connection refused"}) != "refused" || tcpOutcome(&ssh.OpenChannelError{Reason: ssh.Prohibited}) != "ssh_channel_denied" || tcpOutcome(context.DeadlineExceeded) != "timeout" {
		t.Fatal("TCP failure classification")
	}
}

func TestFeedbackLogsRedactedInOutputAndAudit(t *testing.T) {
	for _, tool := range []string{"sh", "tail"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("fixture needs %s", tool)
		}
	}
	_, dir, run := feedbackCLI(t, "prod")
	name := filepath.Join(t.TempDir(), "events.log")
	content := "2025-10-26 14:24:09 GET /orders Authorization: synthetic-secret-header\n2025-10-26 14:24:10 GET /other\n"
	if err := os.WriteFile(name, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	remote := filepath.ToSlash(name)
	if runtime.GOOS == "windows" {
		remote = "/" + strings.ToLower(remote[:1]) + remote[2:]
	}
	code, output := run("", "logs", "-H", "box", "--agent-mode", remote, "--file-offset", "+08:00", "--since", "2025-10-26T14:24:09+08:00", "--until", "2025-10-26T14:24:09+08:00", "--regex", "GET /orders")
	if code != 0 || !strings.Contains(output, "GET /orders Authorization: [REDACTED]") || strings.Contains(output, "synthetic-secret-header") || strings.Contains(output, "GET /other") {
		t.Fatalf("log output: %d %s", code, output)
	}
	found := false
	if err := audit.List(dir, audit.Filter{Hosts: []string{"box"}}, func(record audit.Record) error {
		if strings.Contains(record.ResultSummary, "synthetic-secret-header") {
			return errors.New("secret reached audit summary")
		}
		found = found || strings.Contains(strings.ToLower(record.ResultSummary), "authorization: [redacted]")
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatal("redacted log missing from audit summary")
	}
}

func TestFeedbackExecTimeoutReportsUnknown(t *testing.T) {
	for _, tool := range []string{"sh", "sleep"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("fixture needs %s", tool)
		}
	}
	_, _, run := feedbackCLI(t, "dev")
	code, output := run("", "exec", "-H", "box", "--timeout", "400ms", "--json", "--", "sleep", "2")
	if code != exitcode.Connect || !strings.Contains(output, `"outcome": "unknown"`) || !strings.Contains(output, "remote command did not report completion") {
		t.Fatalf("timeout result: %d %s", code, output)
	}
}
