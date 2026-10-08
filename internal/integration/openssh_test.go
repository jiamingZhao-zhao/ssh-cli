package integration

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// TestOpenSSHContainer drives the real CLI against linuxserver/openssh-server.
// It runs in CI and when SSH_CLI_INTEGRATION=1. It never dials a host other than 127.0.0.1.
func TestOpenSSHContainer(t *testing.T) {
	// The CI workflow sets SSH_CLI_INTEGRATION=1 on the integration job only.
	// A normal `go test ./...` skips this even when CI=true, so image pulls
	// do not dominate the unit-test job.
	if os.Getenv("SSH_CLI_INTEGRATION") != "1" {
		t.Skip("set SSH_CLI_INTEGRATION=1 to run the OpenSSH container test")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Fatal("docker is required for the integration test")
	}

	bin := filepath.Join(t.TempDir(), "ssh-cli")
	build := exec.Command("go", "build", "-o", bin, "./cmd/ssh-cli")
	build.Dir = moduleRoot(t)
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}

	port := freePort(t)
	name := fmt.Sprintf("ssh-cli-it-%d", time.Now().UnixNano())
	const user = "sshcli"
	const pass = "test-pass-not-secret"
	run := exec.Command("docker", "run", "-d", "--rm", "--name", name,
		"-p", fmt.Sprintf("127.0.0.1:%d:2222", port),
		"-e", "PUID=1000",
		"-e", "PGID=1000",
		"-e", "TZ=Etc/UTC",
		"-e", "USER_NAME="+user,
		"-e", "USER_PASSWORD="+pass,
		"-e", "PASSWORD_ACCESS=true",
		"-e", "SUDO_ACCESS=false",
		"linuxserver/openssh-server:latest",
	)
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("docker run: %v\n%s", err, out)
	}
	t.Cleanup(func() {
		_ = exec.Command("docker", "rm", "-f", name).Run()
	})
	waitForSSH(t, name, port)

	cfg := t.TempDir()
	cli := func(stdin string, args ...string) (int, string, string) {
		t.Helper()
		cmd := exec.Command(bin, append([]string{"--config", cfg}, args...)...)
		cmd.Stdin = strings.NewReader(stdin)
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		err := cmd.Run()
		code := 0
		if err != nil {
			if ee, ok := err.(*exec.ExitError); ok {
				code = ee.ExitCode()
			} else {
				t.Fatalf("%v\n%s", err, stderr.String())
			}
		}
		return code, stdout.String(), stderr.String()
	}

	code, _, stderr := cli("", "env", "add", "lab", "--label", "lab", "--color", "green", "--max-mode", "admin", "--default-policy", "admin")
	if code != 0 {
		t.Fatalf("env add: %s", stderr)
	}
	code, _, stderr = cli("", "group", "add", "box", "--env", "lab")
	if code != 0 {
		t.Fatalf("group add: %s", stderr)
	}
	code, _, stderr = cli(pass+"\n", "host", "add", "box", "--group", "box", "--host", "127.0.0.1", "--port", fmt.Sprint(port), "--user", user, "--password-stdin", "--set-default")
	if code != 0 {
		t.Fatalf("host add: %s", stderr)
	}

	script := filepath.Join(t.TempDir(), "exit9.sh")
	if err := os.WriteFile(script, []byte("exit 9\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, _, stderr = cli("", "exec", "-H", "box", "--script", script)
	if code != 9 {
		t.Fatalf("exec exit code = %d, stderr %s", code, stderr)
	}
	code, stdout, stderr := cli("", "exec", "-H", "box", "--", "echo hello-from-remote")
	if code != 0 || !strings.Contains(stdout, "hello-from-remote") {
		t.Fatalf("echo code %d stdout %q stderr %q", code, stdout, stderr)
	}

	local := t.TempDir()
	if err := os.MkdirAll(filepath.Join(local, "nested"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(local, "nested", "f.txt"), []byte("payload"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, homeOut, stderr := cli("", "exec", "-H", "box", "--", "echo $HOME")
	if code != 0 {
		t.Fatalf("home: %s", stderr)
	}
	remote := strings.TrimSpace(homeOut) + "/ssh-cli-it"
	code, _, stderr = cli("", "upload", "-H", "box", local, remote+"/in")
	if code != 0 {
		t.Fatalf("upload: %s", stderr)
	}
	back := t.TempDir()
	code, _, stderr = cli("", "download", "-H", "box", remote+"/in", back)
	if code != 0 {
		t.Fatalf("download: %s", stderr)
	}
	got, err := os.ReadFile(filepath.Join(back, "nested", "f.txt"))
	if err != nil || string(got) != "payload" {
		t.Fatalf("round trip %q err %v", got, err)
	}

	kh := filepath.Join(cfg, "known_hosts")
	if st, err := os.Stat(kh); err != nil || st.Size() == 0 {
		t.Fatalf("known_hosts missing after TOFU: %v", err)
	}
	// Replace the trusted key. The server's real key must then be rejected.
	if err := os.WriteFile(kh, []byte(fakeKnownHost(port)), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, stderr = cli("", "exec", "-H", "box", "--", "echo should-not-run")
	if code != 254 {
		logs, _ := exec.Command("docker", "logs", name).CombinedOutput()
		t.Fatalf("TOFU change code = %d, want 254\nstderr: %s\nlogs:\n%s", code, stderr, logs)
	}
}

func fakeKnownHost(port int) string {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		panic(err)
	}
	return knownhosts.Line([]string{fmt.Sprintf("127.0.0.1:%d", port)}, signer.PublicKey()) + "\n"
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func waitForSSH(t *testing.T, name string, port int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Minute)
	var last string
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
		if err == nil {
			buf := make([]byte, 64)
			_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			n, _ := conn.Read(buf)
			conn.Close()
			if bytes.Contains(buf[:n], []byte("SSH-")) {
				return
			}
			last = string(buf[:n])
		} else {
			last = err.Error()
		}
		time.Sleep(time.Second)
	}
	logs, _ := exec.Command("docker", "logs", name).CombinedOutput()
	t.Fatalf("ssh not ready (%s)\n%s", last, logs)
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found")
		}
		dir = parent
	}
}
