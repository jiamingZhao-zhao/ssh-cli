package cli

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/sshtest"
)

func TestImportHelpAndRoundTrip(t *testing.T) {
	var out, errb strings.Builder
	code := Execute([]string{"import", "ssh-ops", "-h"}, strings.NewReader(""), &out, &errb)
	text := out.String()
	for _, fragment := range []string{"servers:", "dry-run", "does not connect", "password", "maxMode", "192.0.2.10"} {
		if code != 0 || !strings.Contains(text, fragment) {
			t.Fatalf("help %d missing %q\n%s", code, fragment, text)
		}
	}
	dir := t.TempDir()
	inv := filepath.Join(dir, "servers.yaml")
	const pw = "s3cret-import"
	body := "servers:\n  main:\n    host: 192.0.2.10\n    user: viewer\n    password: \"" + pw + "\"\n    group: app\n    env: dev\n"
	if err := os.WriteFile(inv, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) (int, string, string) {
		t.Helper()
		var stdout, stderr strings.Builder
		c := Execute(append([]string{"--config", dir}, args...), strings.NewReader(""), &stdout, &stderr)
		return c, stdout.String(), stderr.String()
	}
	code, stdout, stderr := run("import", "ssh-ops", "--dry-run", inv)
	if code != 0 || !strings.Contains(stdout, "add-host") || strings.Contains(stdout+stderr, pw) {
		t.Fatalf("dry-run %d\n%s\n%s", code, stdout, stderr)
	}
	if _, err := os.Stat(filepath.Join(dir, "hosts.yaml")); !os.IsNotExist(err) {
		t.Fatal("dry-run created hosts.yaml")
	}
	code, stdout, stderr = run("import", "ssh-ops", inv)
	if code != 0 || strings.Contains(stdout+stderr, pw) || !strings.Contains(stderr, "delete the plaintext") {
		t.Fatalf("import %d\n%s\n%s", code, stdout, stderr)
	}
	code, stdout, stderr = run("policy", "add", "tight", "--mode", "readonly", "--deny", "shutdown", "--confirm", "systemctl restart")
	if code != 0 {
		t.Fatalf("policy add %d %s", code, stderr)
	}
	code, stdout, _ = run("policy", "list")
	if code != 0 || !strings.Contains(stdout, "tight") || !strings.Contains(stdout, "readonly") {
		t.Fatalf("policy list %d\n%s", code, stdout)
	}
	code, _, stderr = run("env", "add", "lab", "--max-mode", "standard", "--no-data-outflow")
	if code != 0 {
		t.Fatalf("env add %d %s", code, stderr)
	}
	yamlBytes, err := os.ReadFile(filepath.Join(dir, "hosts.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(yamlBytes), pw) || !strings.Contains(string(yamlBytes), "noDataOutflow: true") || !strings.Contains(string(yamlBytes), "shutdown") {
		t.Fatalf("yaml\n%s", yamlBytes)
	}
}

func TestStatusServiceAndKeys(t *testing.T) {
	ttyCheck = func() bool { return false }
	t.Cleanup(func() { ttyCheck = defaultTTY })
	srv, err := sshtest.Start("tester", "s3cret-ops", nil)
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
	mustOK("group", "add", "app-prod", "--env", "prod")
	mustOK("group", "add", "sandbox", "--env", "dev")
	code, _, errb := runIn("s3cret-ops\n", "host", "add", "main", "--group", "app-prod", "--host", "192.0.2.10", "--user", "viewer", "--password-stdin", "--set-default")
	if code != 0 {
		t.Fatalf("host main %d %s", code, errb)
	}
	code, _, errb = runIn("s3cret-ops\n", "host", "add", "box", "--group", "sandbox", "--host", host, "--port", port, "--user", "tester", "--password-stdin")
	if code != 0 {
		t.Fatalf("host box %d %s", code, errb)
	}

	code, _, errb = run("service", "-H", "main", "restart", "nginx")
	if code != 253 {
		t.Fatalf("prod restart %d %s", code, errb)
	}
	auditText := readAuditDir(t, dir)
	if !strings.Contains(auditText, `"op":"policy_check"`) || !strings.Contains(auditText, "systemctl restart nginx") || strings.Contains(auditText, "s3cret-ops") {
		t.Fatalf("audit\n%s", auditText)
	}

	code, out, errb := run("status", "-H", "box", "--json")
	if code != 0 {
		t.Fatalf("status %d\n%s\n%s", code, out, errb)
	}
	var status struct {
		Results []struct {
			Connected bool `json:"connected"`
			Probes    []struct {
				Name     string `json:"name"`
				ExitCode int    `json:"exitCode"`
			} `json:"probes"`
		} `json:"results"`
	}
	if err := json.Unmarshal([]byte(out), &status); err != nil {
		t.Fatal(err)
	}
	if len(status.Results) != 1 || !status.Results[0].Connected {
		t.Fatalf("status json %s", out)
	}
	foundHost := false
	for _, p := range status.Results[0].Probes {
		if p.Name == "hostname" && p.ExitCode == 0 {
			foundHost = true
		}
	}
	if !foundHost {
		t.Fatalf("hostname probe %s", out)
	}
	if !strings.Contains(readAuditDir(t, dir), `"op":"status"`) {
		t.Fatal("status was not audited")
	}

	code, _, errb = run("service", "-H", "box", "status", "nginx")
	if code == 253 {
		t.Fatalf("dev service status denied: %s", errb)
	}
	if !strings.Contains(readAuditDir(t, dir), `"op":"service"`) {
		t.Fatal("service was not audited")
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pub := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))) + " laptop\n"
	keyPath := filepath.Join(dir, "authorized_keys")
	if err := os.WriteFile(keyPath, []byte(pub), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, errb = run("keys", "-H", "box", "--path", keyPath, "--json")
	if code != 0 {
		t.Fatalf("keys %d\n%s\n%s", code, out, errb)
	}
	if !strings.Contains(out, ssh.FingerprintSHA256(signer.PublicKey())) || strings.Contains(out, "s3cret-ops") {
		t.Fatalf("keys json %s", out)
	}
	if !strings.Contains(readAuditDir(t, dir), `"op":"keys"`) {
		t.Fatal("keys was not audited")
	}

	code, out, errb = run("keys", "known", "list", "--json")
	if code != 0 || !strings.Contains(out, "knownHosts") {
		t.Fatalf("known list %d\n%s\n%s", code, out, errb)
	}
	var known struct {
		KnownHosts []struct {
			Marker string `json:"marker"`
		} `json:"knownHosts"`
	}
	if err := json.Unmarshal([]byte(out), &known); err != nil {
		t.Fatal(err)
	}
	if len(known.KnownHosts) == 0 || known.KnownHosts[0].Marker == "" {
		t.Fatalf("known %s", out)
	}
	code, _, errb = run("keys", "known", "remove", known.KnownHosts[0].Marker)
	if code != 0 {
		t.Fatalf("remove %d %s", code, errb)
	}
	code, out, _ = run("keys", "known", "list", "--json")
	if code != 0 || !strings.Contains(out, `"knownHosts": []`) {
		t.Fatalf("known after remove %s", out)
	}
}
