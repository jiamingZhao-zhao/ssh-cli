package transfer_test

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/transfer"
)

type brokenReader struct{ sent bool }

func (r *brokenReader) Read(p []byte) (int, error) {
	if r.sent {
		return 0, errors.New("synthetic stream interruption")
	}
	r.sent = true
	return copy(p, "partial"), nil
}

func TestUploadReaderPreservesOriginal(t *testing.T) {
	c := memorySFTP(t)
	sf, err := transfer.Client(c.Raw())
	if err != nil {
		t.Fatal(err)
	}
	defer sf.Close()
	f, err := sf.Create("/original")
	if err != nil {
		t.Fatal(err)
	}
	f.Write([]byte("keep"))
	f.Close()
	err = transfer.UploadReaderWithOptions(c.Raw(), &brokenReader{}, "original", 100, "/original", transfer.UploadOptions{})
	if err == nil {
		t.Fatal("interrupted input accepted")
	}
	f, err = sf.Open("/original")
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(f)
	f.Close()
	if string(got) != "keep" {
		t.Fatalf("original changed: %q", got)
	}
	entries, _ := sf.ReadDir("/")
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".ssh-cli-upload-") {
			t.Fatal("temporary file remains")
		}
	}
}

func TestDownloadCancelPreservesOriginal(t *testing.T) {
	c := memorySFTP(t)
	sf, err := transfer.Client(c.Raw())
	if err != nil {
		t.Fatal(err)
	}
	f, err := sf.Create("/large")
	if err != nil {
		t.Fatal(err)
	}
	f.Write([]byte(strings.Repeat("x", 2<<20)))
	f.Close()
	sf.Close()
	dir := t.TempDir()
	dest := filepath.Join(dir, "original")
	if err := os.WriteFile(dest, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	err = transfer.DownloadWithOptions(c.Raw(), "/large", dest, nil, transfer.DownloadOptions{Context: ctx, Progress: func(done, _ int64) {
		if done > 0 {
			cancel()
		}
	}})
	if err == nil {
		t.Fatal("canceled download succeeded")
	}
	got, _ := os.ReadFile(dest)
	if string(got) != "keep" {
		t.Fatalf("original changed: %q", got)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("download temp remains: %v", entries)
	}
}

func TestRelayFailureAndSymlinkPreserveOriginal(t *testing.T) {
	c := memorySFTP(t)
	sf, err := transfer.Client(c.Raw())
	if err != nil {
		t.Fatal(err)
	}
	defer sf.Close()
	for name, body := range map[string]string{"/source": "new", "/original": "keep"} {
		f, e := sf.Create(name)
		if e != nil {
			t.Fatal(e)
		}
		f.Write([]byte(body))
		f.Close()
	}
	// This fixture intentionally rejects exec, including both checksum commands.
	if _, err := transfer.Relay(c.Raw(), c.Raw(), "/source", "/original"); err == nil {
		t.Fatal("unverified copy committed")
	}
	f, _ := sf.Open("/original")
	got, _ := io.ReadAll(f)
	f.Close()
	if string(got) != "keep" {
		t.Fatal("checksum failure destroyed original")
	}
	if err := sf.Symlink("/original", "/link"); err != nil {
		t.Fatal(err)
	}
	if _, err := transfer.Relay(c.Raw(), c.Raw(), "/source", "/link"); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("followed destination link: %v", err)
	}
}
