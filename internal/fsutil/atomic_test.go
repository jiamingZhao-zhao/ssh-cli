package fsutil

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestWriteAtomicReplacesPrivately covers the shared write path on every OS.
// The protected-DACL check lives in harden_windows_test.go: it calls advapi32
// and cannot run on Linux CI. Linux CI still executes this test, and
// GOOS=windows go test -c compiles the Windows ACL test.
func TestWriteAtomicReplacesPrivately(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hosts.yaml")
	if err := WriteAtomic(path, []byte("one"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteAtomic(path, []byte("two\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte("two\n")) {
		t.Fatalf("content = %q, want %q", got, "two\n")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if len(e.Name()) >= 5 && e.Name()[:5] == ".tmp-" {
			t.Fatalf("temp file left behind: %s", e.Name())
		}
	}
	if runtime.GOOS == "windows" {
		// Unix permission bits are not the privacy mechanism on Windows.
		// harden_windows_test.go asserts the DACL.
		return
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o, want 600", info.Mode().Perm())
	}
}
