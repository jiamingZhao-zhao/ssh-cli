package transfer

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/sshclient"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/sshtest"
	"golang.org/x/crypto/ssh"
)

func TestFeedbackTextSFTPAndPrivateUpload(t *testing.T) {
	server, err := sshtest.Start("tester", "synthetic-file-pass", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(server.Close)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	client, err := sshclient.Dial(ctx, server.Addr, "tester", sshclient.PasswordAuth("synthetic-file-pass"), ssh.FixedHostKey(server.Signer.PublicKey()), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	local := filepath.Join(t.TempDir(), "input.txt")
	if err := os.WriteFile(local, []byte("secret=synthetic\r\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	remote := filepath.ToSlash(filepath.Join(t.TempDir(), "test.conf"))
	mode := os.FileMode(0o600)
	if err := UploadWithOptions(client.Raw(), local, remote, nil, UploadOptions{FileMode: &mode}); err != nil {
		t.Fatal(err)
	}
	assertMode := func() {
		info, err := os.Stat(remote)
		if err != nil || runtime.GOOS != "windows" && info.Mode().Perm() != mode {
			t.Fatalf("requested mode did not survive publish: %v %v", info, err)
		}
	}
	assertMode()
	sftpClient, err := Client(client.Raw())
	if err != nil {
		t.Fatal(err)
	}
	defer sftpClient.Close()
	snapshot, err := ReadText(sftpClient, remote)
	if err != nil || snapshot.Content != "secret=synthetic\r\n" {
		t.Fatalf("text read: %v %q", err, snapshot.Content)
	}
	allow := func() error { return nil }
	if err := SaveText(sftpClient, remote, snapshot.Version, "updated=中文\r\n", allow); err != nil {
		t.Fatal(err)
	}
	assertMode()
	if err := SaveText(sftpClient, remote, snapshot.Version, "stale", allow); !errors.Is(err, ErrTextChanged) {
		t.Fatalf("stale edit accepted: %v", err)
	}
	got, err := os.ReadFile(remote)
	if err != nil || string(got) != "updated=中文\r\n" {
		t.Fatalf("overwrote newer data: %v %q", err, got)
	}
	if err := SaveText(sftpClient, remote, snapshot.Version, strings.Repeat("a", MaxTextBytes+1), allow); err == nil || !strings.Contains(err.Error(), "5 MiB") {
		t.Fatalf("oversize edit accepted: %v", err)
	}
	if err := ValidateText("text\x00binary"); err == nil {
		t.Fatal("binary edit accepted")
	}
}
