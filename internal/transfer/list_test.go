package transfer

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/sshclient"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/sshtest"
)

func TestListReadsDirectory(t *testing.T) {
	srv, err := sshtest.Start("tester", "test-pass", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	client, err := sshclient.Dial(ctx, srv.Addr, "tester", sshclient.PasswordAuth("test-pass"), sshclient.HostKeyCallback(filepath.Join(t.TempDir(), "known_hosts"), true), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(dir, "a.txt"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := List(client.Raw(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if got.Path == "" || len(got.Crumbs) == 0 || len(got.Entries) < 2 {
		t.Fatalf("listing %#v", got)
	}
	if !got.Entries[0].Dir || got.Entries[0].Name != "sub" {
		t.Fatalf("dir sort %#v", got.Entries)
	}
	found := false
	for _, e := range got.Entries {
		if e.Name == "a.txt" && !e.Dir && e.Size == int64(len("hello")) {
			found = true
		}
	}
	if !found {
		t.Fatalf("file missing %#v", got.Entries)
	}
	after, err := os.ReadFile(filepath.Join(dir, "a.txt"))
	if err != nil || string(after) != string(before) {
		t.Fatalf("list modified the file %q", after)
	}
	if _, err := List(client.Raw(), filepath.Join(dir, "missing")); err == nil {
		t.Fatal("missing directory succeeded")
	}
	if _, err := CleanListPath("bad\npath"); err == nil {
		t.Fatal("newline path accepted")
	}
}
