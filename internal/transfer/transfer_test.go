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

func TestUploadDownloadDirectory(t *testing.T) {
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

	local := t.TempDir()
	if err := os.MkdirAll(filepath.Join(local, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(local, "sub", "a.txt"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	remote := filepath.Join(t.TempDir(), "remote-dest")
	// The in-process SFTP server uses the local filesystem. Pass a POSIX-style
	// absolute path; on Linux filepath and path agree.
	if err := Upload(client.Raw(), local, remote, nil); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(remote, "sub", "a.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello" {
		t.Fatalf("uploaded %q", got)
	}
	back := t.TempDir()
	if err := Download(client.Raw(), remote, back, nil); err != nil {
		t.Fatal(err)
	}
	got, err = os.ReadFile(filepath.Join(back, "sub", "a.txt"))
	if err != nil || string(got) != "hello" {
		t.Fatalf("downloaded %q err %v", got, err)
	}
}
