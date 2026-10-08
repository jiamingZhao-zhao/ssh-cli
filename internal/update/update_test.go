package update

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/exitcode"
)

func TestAssetNames(t *testing.T) {
	if got := AssetName("v1.2.3", "linux", "amd64"); got != "ssh-cli_1.2.3_linux_amd64.tar.gz" {
		t.Fatal(got)
	}
	if got := AssetName("1.2.3", "darwin", "arm64"); got != "ssh-cli_1.2.3_darwin_arm64.tar.gz" {
		t.Fatal(got)
	}
	if got := AssetName("1.2.3", "windows", "arm64"); got != "ssh-cli_1.2.3_windows_arm64.zip" {
		t.Fatal(got)
	}
	if BinaryName("windows") != "ssh-cli.exe" || BinaryName("linux") != "ssh-cli" {
		t.Fatal("binary name")
	}
	_, err := selectAsset([]asset{{name: "ssh-cli_1.2.3_linux_arm64.tar.gz", url: "http://example.test/a"}}, "1.2.3", "linux", "amd64")
	if err == nil {
		t.Fatal("expected missing asset")
	}
	got, err := selectAsset([]asset{
		{name: "ssh-cli_1.2.3_linux_amd64.tar.gz", url: "http://example.test/a"},
		{name: ChecksumsName, url: "http://example.test/c"},
	}, "1.2.3", "linux", "amd64")
	if err != nil || got.name != "ssh-cli_1.2.3_linux_amd64.tar.gz" {
		t.Fatalf("select %+v %v", got, err)
	}
}

func TestCompareSemver(t *testing.T) {
	cases := []struct {
		current, latest string
		want            int
		err             bool
	}{
		{"1.2.3", "1.2.4", -1, false},
		{"v1.2.3", "1.2.3", 0, false},
		{"1.2.3", "v1.2.3", 0, false},
		{"1.2", "1.2.0", 0, false},
		{"1.2.3+build.5", "1.2.3", 0, false},
		{"1.2.3-rc.1", "1.2.3", -1, false},
		{"1.2.3", "1.2.3-rc.1", 1, false},
		{"1.0.0-alpha", "1.0.0-alpha.1", -1, false},
		{"1.0.0-alpha.1", "1.0.0-alpha.beta", -1, false},
		{"1.0.0-alpha.beta", "1.0.0-beta", -1, false},
		{"1.0.0-beta.2", "1.0.0-beta.11", -1, false},
		{"1.0.0-rc.1", "1.0.0", -1, false},
		{"dev", "1.0.0", -1, false},
		{"", "1.0.0", -1, false},
		{"1.2.3", "dev", 0, true},
		{"01.2.3", "1.2.3", -1, false},
		{"1.2.3", "01.2.3", 0, true},
		{"2.0.0", "1.9.9", 1, false},
	}
	for _, tc := range cases {
		got, err := compareSemver(tc.current, tc.latest)
		if tc.err {
			if err == nil {
				t.Fatalf("compare(%q, %q) want error", tc.current, tc.latest)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Fatalf("compare(%q, %q) = %d, %v; want %d", tc.current, tc.latest, got, err, tc.want)
		}
	}
}

func TestParseChecksums(t *testing.T) {
	raw := []byte("# comment\n\n" + strings.Repeat("ab", 32) + "  ssh-cli_1.2.3_linux_amd64.tar.gz\n" + strings.Repeat("cd", 32) + " *ssh-cli_1.2.3_windows_amd64.zip\n")
	sums, err := ParseChecksums(raw)
	if err != nil {
		t.Fatal(err)
	}
	if sums["ssh-cli_1.2.3_linux_amd64.tar.gz"] != strings.Repeat("ab", 32) {
		t.Fatalf("%v", sums)
	}
	if sums["ssh-cli_1.2.3_windows_amd64.zip"] != strings.Repeat("cd", 32) {
		t.Fatalf("%v", sums)
	}
	payload := []byte("hello")
	sum := sha256.Sum256(payload)
	ok := map[string]string{"a.bin": hex.EncodeToString(sum[:])}
	if err := verifyChecksum("a.bin", payload, ok); err != nil {
		t.Fatal(err)
	}
	if err := verifyChecksum("missing", payload, ok); err == nil {
		t.Fatal("expected missing entry")
	}
	ok["a.bin"] = strings.Repeat("00", 32)
	if err := verifyChecksum("a.bin", payload, ok); err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatal(err)
	}
}

func TestExtractAndRejectTraversal(t *testing.T) {
	good := tarGz(t, "ssh-cli", []byte("new-bin"))
	got, err := extractBinary("ssh-cli_1.0.0_linux_amd64.tar.gz", "linux", good)
	if err != nil || string(got) != "new-bin" {
		t.Fatalf("extract %q %v", got, err)
	}
	nested := tarGz(t, "dist/ssh-cli", []byte("nested"))
	got, err = extractBinary("ssh-cli_1.0.0_linux_amd64.tar.gz", "linux", nested)
	if err != nil || string(got) != "nested" {
		t.Fatalf("nested %q %v", got, err)
	}
	bad := tarGz(t, "../ssh-cli", []byte("x"))
	if _, err := extractBinary("ssh-cli_1.0.0_linux_amd64.tar.gz", "linux", bad); err == nil {
		t.Fatal("traversal was accepted")
	}
	z := zipBytes(t, "ssh-cli.exe", []byte("win"))
	got, err = extractBinary("ssh-cli_1.0.0_windows_amd64.zip", "windows", z)
	if err != nil || string(got) != "win" {
		t.Fatalf("zip %q %v", got, err)
	}
	z = zipBytes(t, `..\ssh-cli.exe`, []byte("x"))
	if _, err := extractBinary("ssh-cli_1.0.0_windows_amd64.zip", "windows", z); err == nil {
		t.Fatal("zip traversal was accepted")
	}
}

func TestReplaceBinary(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "ssh-cli")
	if err := os.WriteFile(dest, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := ReplaceBinary(dest, []byte("new")); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(dest)
	if err != nil || string(got) != "new" {
		t.Fatalf("dest %q %v", got, err)
	}
	if _, err := os.Stat(dest + ".old"); !os.IsNotExist(err) {
		t.Fatal("backup left behind")
	}
}

func TestRunCheckAndInstall(t *testing.T) {
	const payload = "#!/bin/sh\necho updated\n"
	srv, hits := releaseServer(t, "1.2.3", "linux", "amd64", []byte(payload), true, false, 0)
	old := APIBase
	APIBase = srv.URL
	t.Cleanup(func() { APIBase = old })

	ctx := context.Background()
	res, err := Run(ctx, updateOpts(t, "dev", true, false))
	if err != nil {
		t.Fatal(err)
	}
	if !res.UpdateAvailable || res.Installed || res.Latest != "1.2.3" || res.Asset != "ssh-cli_1.2.3_linux_amd64.tar.gz" {
		t.Fatalf("%+v", res)
	}
	if *hits != 0 {
		t.Fatalf("check downloaded the asset %d times", *hits)
	}

	dest := filepath.Join(t.TempDir(), "ssh-cli")
	if err := os.WriteFile(dest, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	res, err = Run(ctx, Options{
		Repo: "example/ssh-cli", Current: "dev", GOOS: "linux", GOARCH: "amd64",
		Client: srv.Client(), ExePath: dest,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Installed || !res.ChecksumVerified || res.Warning != "" {
		t.Fatalf("%+v", res)
	}
	got, err := os.ReadFile(dest)
	if err != nil || string(got) != payload {
		t.Fatalf("installed %q %v", got, err)
	}
	if *hits != 1 {
		t.Fatalf("hits %d", *hits)
	}

	same, err := Run(ctx, Options{
		Repo: "example/ssh-cli", Current: "1.2.3", GOOS: "linux", GOARCH: "amd64",
		Client: srv.Client(), ExePath: dest, Check: true,
	})
	if err != nil || same.UpdateAvailable || same.Installed || same.Ahead {
		t.Fatalf("%+v %v", same, err)
	}
	ahead, err := Run(ctx, Options{
		Repo: "example/ssh-cli", Current: "9.0.0", GOOS: "linux", GOARCH: "amd64",
		Client: srv.Client(), ExePath: dest, Check: true,
	})
	if err != nil || !ahead.Ahead || ahead.UpdateAvailable {
		t.Fatalf("%+v %v", ahead, err)
	}
}

func TestRunMissingChecksumWarns(t *testing.T) {
	srv, _ := releaseServer(t, "1.2.3", "linux", "amd64", []byte("bin"), false, false, 0)
	old := APIBase
	APIBase = srv.URL
	t.Cleanup(func() { APIBase = old })
	dest := filepath.Join(t.TempDir(), "ssh-cli")
	if err := os.WriteFile(dest, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	res, err := Run(context.Background(), Options{
		Repo: "example/ssh-cli", Current: "0.1.0", GOOS: "linux", GOARCH: "amd64",
		Client: srv.Client(), ExePath: dest,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Warning == "" || !strings.Contains(res.Warning, "checksums.txt") || res.ChecksumVerified {
		t.Fatalf("%+v", res)
	}
	got, err := os.ReadFile(dest)
	if err != nil || string(got) != "bin" {
		t.Fatalf("installed %q %v", got, err)
	}
}

func TestRunChecksumMismatch(t *testing.T) {
	srv, _ := releaseServer(t, "1.2.3", "linux", "amd64", []byte("bin"), true, true, 0)
	old := APIBase
	APIBase = srv.URL
	t.Cleanup(func() { APIBase = old })
	dest := filepath.Join(t.TempDir(), "ssh-cli")
	if err := os.WriteFile(dest, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	_, err := Run(context.Background(), Options{
		Repo: "example/ssh-cli", Current: "dev", GOOS: "linux", GOARCH: "amd64",
		Client: srv.Client(), ExePath: dest,
	})
	if err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatal(err)
	}
	var ee *exitcode.Error
	if !asExit(err, &ee) || ee.Code != exitcode.Usage {
		t.Fatalf("code %v", err)
	}
	got, _ := os.ReadFile(dest)
	if string(got) != "old" {
		t.Fatalf("binary changed to %q", got)
	}
}

func TestRunConfirmRefusedDoesNotDownload(t *testing.T) {
	srv, hits := releaseServer(t, "1.2.3", "linux", "amd64", []byte("bin"), true, false, 0)
	old := APIBase
	APIBase = srv.URL
	t.Cleanup(func() { APIBase = old })
	dest := filepath.Join(t.TempDir(), "ssh-cli")
	if err := os.WriteFile(dest, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	_, err := Run(context.Background(), Options{
		Repo: "example/ssh-cli", Current: "dev", GOOS: "linux", GOARCH: "amd64",
		Client: srv.Client(), ExePath: dest,
		Confirm: func(string) error { return exitcode.New(exitcode.Denied, "no tty") },
	})
	if err == nil {
		t.Fatal("expected confirm error")
	}
	if *hits != 0 {
		t.Fatalf("downloaded %d", *hits)
	}
	got, _ := os.ReadFile(dest)
	if string(got) != "old" {
		t.Fatal(string(got))
	}
}

func TestRunForceReinstallsSameVersion(t *testing.T) {
	srv, hits := releaseServer(t, "1.2.3", "linux", "amd64", []byte("same"), true, false, 0)
	old := APIBase
	APIBase = srv.URL
	t.Cleanup(func() { APIBase = old })
	dest := filepath.Join(t.TempDir(), "ssh-cli")
	if err := os.WriteFile(dest, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	res, err := Run(context.Background(), Options{
		Repo: "example/ssh-cli", Current: "1.2.3", GOOS: "linux", GOARCH: "amd64",
		Force: true, Client: srv.Client(), ExePath: dest,
	})
	if err != nil || !res.Installed {
		t.Fatalf("%+v %v", res, err)
	}
	if *hits != 1 {
		t.Fatal(*hits)
	}
}

func TestRunNetworkAndRepoErrors(t *testing.T) {
	srv, _ := releaseServer(t, "1.2.3", "linux", "amd64", []byte("bin"), false, false, http.StatusBadGateway)
	old := APIBase
	APIBase = srv.URL
	t.Cleanup(func() { APIBase = old })
	_, err := Run(context.Background(), Options{Repo: "example/ssh-cli", Client: srv.Client(), GOOS: "linux", GOARCH: "amd64", Check: true})
	var ee *exitcode.Error
	if !asExit(err, &ee) || ee.Code != exitcode.Connect {
		t.Fatalf("%v", err)
	}
	_, err = Run(context.Background(), Options{Repo: "not a repo", Check: true})
	if !asExit(err, &ee) || ee.Code != exitcode.Usage {
		t.Fatalf("%v", err)
	}
}

func asExit(err error, ee **exitcode.Error) bool {
	if err == nil {
		return false
	}
	e, ok := err.(*exitcode.Error)
	if !ok {
		return false
	}
	*ee = e
	return true
}

func updateOpts(t *testing.T, current string, check, force bool) Options {
	t.Helper()
	return Options{
		Repo: "example/ssh-cli", Current: current, GOOS: "linux", GOARCH: "amd64",
		Check: check, Force: force,
	}
}

func releaseServer(t *testing.T, ver, goos, goarch string, payload []byte, checksum, badSum bool, status int) (*httptest.Server, *int) {
	t.Helper()
	name := AssetName(ver, goos, goarch)
	var archive []byte
	if goos == "windows" {
		archive = zipBytes(t, BinaryName(goos), payload)
	} else {
		archive = tarGz(t, BinaryName(goos), payload)
	}
	sum := sha256.Sum256(archive)
	hits := 0
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/repos/example/ssh-cli/releases/latest" {
			if status != 0 {
				w.WriteHeader(status)
				return
			}
			type item struct {
				Name string `json:"name"`
				URL  string `json:"browser_download_url"`
			}
			assets := []item{{Name: name, URL: srv.URL + "/a/" + name}}
			if checksum {
				assets = append(assets, item{Name: ChecksumsName, URL: srv.URL + "/a/checksums.txt"})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"tag_name": "v" + ver, "assets": assets})
			return
		}
		if r.URL.Path == "/a/"+name {
			hits++
			_, _ = w.Write(archive)
			return
		}
		if r.URL.Path == "/a/checksums.txt" {
			hexsum := hex.EncodeToString(sum[:])
			if badSum {
				hexsum = strings.Repeat("ab", 32)
			}
			fmt.Fprintf(w, "%s  %s\n", hexsum, name)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

func tarGz(t *testing.T, name string, data []byte) []byte {
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

func zipBytes(t *testing.T, name string, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	h := &zip.FileHeader{Name: name, Method: zip.Deflate}
	h.SetMode(0o755)
	w, err := zw.CreateHeader(h)
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
