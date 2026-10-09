package cli

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/update"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/version"
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
	if code == 0 || !strings.Contains(errb, "built-in") {
		t.Fatalf("env add builtin: %d %s", code, errb)
	}
	code, _, errb = run("env", "remove", "prod")
	if code == 0 || !strings.Contains(errb, "built-in") {
		t.Fatalf("env remove builtin: %d %s", code, errb)
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

func TestCustomEnvAndBuiltinGroup(t *testing.T) {
	dir := t.TempDir()
	run := func(args ...string) (int, string, string) {
		t.Helper()
		var out, errb bytes.Buffer
		code := Execute(append([]string{"--config", dir}, args...), strings.NewReader(""), &out, &errb)
		return code, out.String(), errb.String()
	}
	code, out, errb := run("env", "list")
	if code != 0 || !strings.Contains(out, "preprod") || !strings.Contains(out, "预生产") || !strings.Contains(out, "orange") {
		t.Fatalf("env list %d %s %s", code, out, errb)
	}
	code, _, errb = run("env", "add", "lab", "--label", "实验", "--color", "green", "--max-mode", "admin", "--default-policy", "standard")
	if code != 0 {
		t.Fatalf("env add lab: %d %s", code, errb)
	}
	code, _, errb = run("group", "add", "hunan-prod", "--env", "prod")
	if code != 0 {
		t.Fatalf("group add: %d %s", code, errb)
	}
	code, _, errb = run("env", "remove", "lab")
	if code != 0 {
		t.Fatalf("env remove lab: %d %s", code, errb)
	}
	code, out, _ = run("env", "list")
	if strings.Contains(out, "lab") || !strings.Contains(out, "prod") {
		t.Fatalf("env list after remove: %s", out)
	}
}

func TestVersionSwitchesMatch(t *testing.T) {
	want := version.String()
	for _, args := range [][]string{
		{"version"},
		{"--version"},
		{"-V"},
		{"-version"},
	} {
		var out, errb bytes.Buffer
		code := Execute(args, strings.NewReader(""), &out, &errb)
		if code != 0 {
			t.Fatalf("%v code %d stderr %s", args, code, errb.String())
		}
		if strings.TrimSpace(out.String()) != want {
			t.Fatalf("%v stdout %q want %q", args, out.String(), want)
		}
	}
	var out, errb bytes.Buffer
	code := Execute([]string{"version", "--json"}, strings.NewReader(""), &out, &errb)
	if code != 0 || !strings.Contains(out.String(), `"version": "dev"`) || strings.Contains(out.String(), "s3cret") {
		t.Fatalf("json version %d %s %s", code, out.String(), errb.String())
	}
}

func TestRootHelpListsCommands(t *testing.T) {
	for _, args := range [][]string{{"-h"}, {"--help"}} {
		var out, errb bytes.Buffer
		code := Execute(args, strings.NewReader(""), &out, &errb)
		if code != 0 {
			t.Fatalf("%v code %d %s", args, code, errb.String())
		}
		text := out.String()
		for _, fragment := range []string{
			"Available Commands:",
			"Manage hosts",
			"Manage groups",
			"Manage env label definitions",
			"Run a remote command",
			"Upload a file or directory over SFTP",
			"Download a file or directory over SFTP",
			"Show the effective policy for a host",
			"Read the local audit log",
			"Start the optional localhost UI",
			"Install the latest GitHub release",
			"Print the version",
			"ssh-cli version",
			"ssh-cli update --check",
			"Check connectivity and basic host health",
			"Check or change a remote service",
			"List remote authorized keys or local known_hosts",
			"Import hosts and groups from a local inventory file",
		} {
			if !strings.Contains(text, fragment) {
				t.Fatalf("%v help missing %q\n%s", args, fragment, text)
			}
		}
	}
	var out, errb bytes.Buffer
	code := Execute([]string{"update", "-h"}, strings.NewReader(""), &out, &errb)
	if code != 0 || !strings.Contains(out.String(), "checksums.txt") || !strings.Contains(out.String(), "ssh-cli_<version>_") || !strings.Contains(out.String(), "Without a TTY") {
		t.Fatalf("update help %d\n%s\n%s", code, out.String(), errb.String())
	}
}

func TestUpdateCheckAndNonTTYInstall(t *testing.T) {
	ttyCheck = func() bool { return false }
	t.Cleanup(func() { ttyCheck = defaultTTY })
	prompted := false
	openConfirmTTY = func() (io.ReadWriteCloser, error) {
		prompted = true
		return nil, os.ErrInvalid
	}
	t.Cleanup(func() { openConfirmTTY = defaultOpenConfirmTTY })
	srv := updateInstallServer(t)
	oldBase := update.ReleaseBase
	update.ReleaseBase = srv.URL
	t.Cleanup(func() { update.ReleaseBase = oldBase })
	t.Setenv("GITHUB_TOKEN", "")
	dest := filepath.Join(t.TempDir(), "ssh-cli")
	if err := os.WriteFile(dest, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	oldBin := update.CurrentBinary
	update.CurrentBinary = func() (string, error) { return dest, nil }
	t.Cleanup(func() { update.CurrentBinary = oldBin })

	dir := t.TempDir()
	var out, errb bytes.Buffer
	code := Execute([]string{"--config", dir, "update", "--check", "--repo", "example/ssh-cli"}, strings.NewReader(""), &out, &errb)
	if code != 0 {
		t.Fatalf("check %d %s %s", code, out.String(), errb.String())
	}
	if !strings.Contains(out.String(), "current: dev") || !strings.Contains(out.String(), "latest: 1.2.3") || !strings.Contains(out.String(), "update available") {
		t.Fatalf("check output %s", out.String())
	}
	got, err := os.ReadFile(dest)
	if err != nil || string(got) != "old" {
		t.Fatal("check replaced the binary")
	}
	if prompted {
		t.Fatal("check prompted")
	}

	out.Reset()
	errb.Reset()
	code = Execute([]string{"--config", dir, "update", "--repo", "example/ssh-cli"}, strings.NewReader(""), &out, &errb)
	if code != 0 || !strings.Contains(out.String(), "installed 1.2.3") {
		t.Fatalf("install without tty: %d %s %s", code, out.String(), errb.String())
	}
	if prompted {
		t.Fatal("non-TTY update prompted")
	}
	got, err = os.ReadFile(dest)
	if err != nil || string(got) != "updated-binary" {
		t.Fatalf("installed %q %v", got, err)
	}

	if err := os.WriteFile(dest, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	errb.Reset()
	code = Execute([]string{"--config", dir, "--yes", "update", "--repo", "example/ssh-cli"}, strings.NewReader(""), &out, &errb)
	if code != 0 || !strings.Contains(out.String(), "installed 1.2.3") {
		t.Fatalf("--yes update without tty: %d %s %s", code, out.String(), errb.String())
	}
	if prompted {
		t.Fatal("--yes non-TTY update prompted")
	}
	got, err = os.ReadFile(dest)
	if err != nil || string(got) != "updated-binary" {
		t.Fatalf("--yes installed %q %v", got, err)
	}
}

func TestUpdateTTYRequiresConfirm(t *testing.T) {
	ttyCheck = func() bool { return true }
	t.Cleanup(func() { ttyCheck = defaultTTY })
	srv := updateInstallServer(t)
	oldBase := update.ReleaseBase
	update.ReleaseBase = srv.URL
	t.Cleanup(func() { update.ReleaseBase = oldBase })
	t.Setenv("GITHUB_TOKEN", "")
	dest := filepath.Join(t.TempDir(), "ssh-cli")
	if err := os.WriteFile(dest, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	oldBin := update.CurrentBinary
	update.CurrentBinary = func() (string, error) { return dest, nil }
	t.Cleanup(func() { update.CurrentBinary = oldBin })
	t.Cleanup(func() { openConfirmTTY = defaultOpenConfirmTTY })

	var prompt bytes.Buffer
	openConfirmTTY = func() (io.ReadWriteCloser, error) {
		prompt.Reset()
		return confirmRWC{Reader: strings.NewReader("nope\n"), Writer: &prompt}, nil
	}
	dir := t.TempDir()
	var out, errb bytes.Buffer
	code := Execute([]string{"--config", dir, "update", "--repo", "example/ssh-cli"}, strings.NewReader(""), &out, &errb)
	if code != 253 || !strings.Contains(errb.String(), "confirmation did not match") {
		t.Fatalf("tty mismatch: %d %s %s", code, out.String(), errb.String())
	}
	if !strings.Contains(prompt.String(), `release version "1.2.3"`) {
		t.Fatalf("prompt %q", prompt.String())
	}
	got, _ := os.ReadFile(dest)
	if string(got) != "old" {
		t.Fatal("mismatched confirm replaced the binary")
	}

	openConfirmTTY = func() (io.ReadWriteCloser, error) {
		prompt.Reset()
		return confirmRWC{Reader: strings.NewReader("1.2.3\n"), Writer: &prompt}, nil
	}
	out.Reset()
	errb.Reset()
	code = Execute([]string{"--config", dir, "update", "--repo", "example/ssh-cli"}, strings.NewReader(""), &out, &errb)
	if code != 0 || !strings.Contains(out.String(), "installed 1.2.3") {
		t.Fatalf("tty confirm: %d %s %s", code, out.String(), errb.String())
	}
	if !strings.Contains(prompt.String(), `release version "1.2.3"`) {
		t.Fatalf("prompt %q", prompt.String())
	}
	got, err := os.ReadFile(dest)
	if err != nil || string(got) != "updated-binary" {
		t.Fatalf("confirmed install %q %v", got, err)
	}

	if err := os.WriteFile(dest, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	openConfirmTTY = func() (io.ReadWriteCloser, error) {
		t.Fatal("--yes on a TTY still prompted")
		return nil, os.ErrInvalid
	}
	out.Reset()
	errb.Reset()
	code = Execute([]string{"--config", dir, "--yes", "update", "--repo", "example/ssh-cli"}, strings.NewReader(""), &out, &errb)
	if code != 0 || !strings.Contains(out.String(), "installed 1.2.3") {
		t.Fatalf("--yes on tty: %d %s %s", code, out.String(), errb.String())
	}
	got, err = os.ReadFile(dest)
	if err != nil || string(got) != "updated-binary" {
		t.Fatalf("--yes installed %q %v", got, err)
	}
}

type confirmRWC struct {
	io.Reader
	io.Writer
}

func (confirmRWC) Close() error { return nil }

func updateInstallServer(t *testing.T) *httptest.Server {
	t.Helper()
	const ver = "1.2.3"
	const payload = "updated-binary"
	name := update.AssetName(ver, runtime.GOOS, runtime.GOARCH)
	var archive []byte
	if runtime.GOOS == "windows" {
		archive = testZip(t, update.BinaryName(runtime.GOOS), []byte(payload))
	} else {
		archive = testTarGz(t, update.BinaryName(runtime.GOOS), []byte(payload))
	}
	prefix := "/example/ssh-cli/releases/download/v" + ver + "/"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/releases/latest") {
			http.Redirect(w, r, "/example/ssh-cli/releases/tag/v"+ver, http.StatusFound)
			return
		}
		if strings.Contains(r.URL.Path, "/repos/") {
			t.Errorf("update contacted the releases API: %s", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		if r.URL.Path == prefix+name {
			_, _ = w.Write(archive)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func testTarGz(t *testing.T, name string, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(data))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func testZip(t *testing.T, name string, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
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
