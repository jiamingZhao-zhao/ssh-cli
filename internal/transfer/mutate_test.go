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

func TestChangeCreatesRenamesRemoves(t *testing.T) {
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
	if err := Change(client.Raw(), "mkdir", dir, "sub"); err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(filepath.Join(dir, "sub")); err != nil || !st.IsDir() {
		t.Fatalf("mkdir %#v %v", st, err)
	}
	if err := Change(client.Raw(), "touch", dir, "note.txt"); err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(filepath.Join(dir, "note.txt")); err != nil || st.IsDir() || st.Size() != 0 {
		t.Fatalf("touch %#v %v", st, err)
	}
	if err := Change(client.Raw(), "rename", filepath.Join(dir, "note.txt"), "renamed.txt"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "renamed.txt")); err != nil {
		t.Fatal(err)
	}
	if err := Change(client.Raw(), "remove", filepath.Join(dir, "sub"), ""); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "sub")); !os.IsNotExist(err) {
		t.Fatalf("remove dir %v", err)
	}
	if err := Change(client.Raw(), "remove", "/", ""); err == nil {
		t.Fatal("root delete succeeded")
	}
	if _, err := EntryName("../x"); err == nil {
		t.Fatal("dotdot name accepted")
	}
}
