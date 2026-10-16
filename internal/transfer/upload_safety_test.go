package transfer_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/sshclient"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/sshtest"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/transfer"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// The POSIX filesystem exists only in memory; no OS symlink privilege or real remote paths are used.
func memorySFTP(t *testing.T) *sshclient.Client {
	t.Helper()
	seed, err := sshtest.Start("unused", "unused", nil)
	if err != nil {
		t.Fatal(err)
	}
	signer := seed.Signer
	seed.Close()
	cfg := &ssh.ServerConfig{PasswordCallback: func(m ssh.ConnMetadata, p []byte) (*ssh.Permissions, error) {
		if m.User() != "review-user" || string(p) != "synthetic-pass" {
			return nil, fmt.Errorf("bad synthetic auth")
		}
		return nil, nil
	}}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var sockets []net.Conn
	handlers := sftp.InMemHandler()
	t.Cleanup(func() {
		ln.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, c := range sockets {
			c.Close()
		}
	})
	go func() {
		for {
			tcp, e := ln.Accept()
			if e != nil {
				return
			}
			mu.Lock()
			sockets = append(sockets, tcp)
			mu.Unlock()
			go func() {
				defer tcp.Close()
				raw, channels, reqs, e := ssh.NewServerConn(tcp, cfg)
				if e != nil {
					return
				}
				defer raw.Close()
				go ssh.DiscardRequests(reqs)
				for ch := range channels {
					if ch.ChannelType() != "session" {
						ch.Reject(ssh.UnknownChannelType, "session only")
						continue
					}
					channel, requests, e := ch.Accept()
					if e != nil {
						continue
					}
					go func() {
						defer channel.Close()
						for req := range requests {
							if req.Type == "subsystem" {
								_ = req.Reply(true, nil)
								server := sftp.NewRequestServer(channel, handlers)
								_ = server.Serve()
								_ = server.Close()
								return
							}
							_ = req.Reply(false, nil)
						}
					}()
				}
			}()
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := sshclient.Dial(ctx, ln.Addr().String(), "review-user", sshclient.PasswordAuth("synthetic-pass"), ssh.FixedHostKey(signer.PublicKey()), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	return client
}

func TestUploadPreservesOriginalOnRefusalAndCancel(t *testing.T) {
	client := memorySFTP(t)
	sf, err := transfer.Client(client.Raw())
	if err != nil {
		t.Fatal(err)
	}
	defer sf.Close()
	f, err := sf.Create("/keep.txt")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.Write([]byte("before"))
	_ = f.Close()
	local := filepath.Join(t.TempDir(), "upload.txt")
	if err = os.WriteFile(local, []byte("after"), 0600); err != nil {
		t.Fatal(err)
	}
	read := func() string {
		t.Helper()
		f, e := sf.Open("/keep.txt")
		if e != nil {
			t.Fatal(e)
		}
		defer f.Close()
		b, e := io.ReadAll(f)
		if e != nil {
			t.Fatal(e)
		}
		return string(b)
	}
	err = transfer.UploadWithOptions(client.Raw(), local, "/keep.txt", nil, transfer.UploadOptions{RejectOverwrite: true})
	var overwrite *transfer.OverwriteError
	if !errors.As(err, &overwrite) || read() != "before" {
		t.Fatalf("overwrite without confirmation: %v", err)
	}
	checks := 0
	err = transfer.UploadWithOptions(client.Raw(), local, "/keep.txt", nil, transfer.UploadOptions{Check: func(string, []string) error {
		checks++
		if checks == 3 {
			return context.Canceled
		}
		return nil
	}})
	if err == nil || read() != "before" {
		t.Fatalf("canceled upload replaced original: %v", err)
	}
	files, e := sf.ReadDir("/")
	if e != nil {
		t.Fatal(e)
	}
	for _, entry := range files {
		if strings.HasPrefix(entry.Name(), ".ssh-cli-upload-") {
			t.Error("temporary file left after policy refusal")
		}
	}
	if err = sf.Symlink("/keep.txt", "/shortcut.txt"); err != nil {
		t.Fatal(err)
	}
	if err = transfer.Upload(client.Raw(), local, "/shortcut.txt", nil); err == nil || read() != "before" {
		t.Fatalf("followed destination symlink: %v", err)
	}
	if err = sf.Mkdir("/real"); err != nil {
		t.Fatal(err)
	}
	if err = sf.Symlink("/real", "/parent-link"); err != nil {
		t.Fatal(err)
	}
	if err = transfer.Upload(client.Raw(), local, "/parent-link/new.txt", nil); err == nil {
		t.Fatal("followed directory symlink")
	}
	if err = transfer.Upload(client.Raw(), local, "/keep.txt", nil); err != nil {
		t.Fatal(err)
	}
	var stats transfer.UploadStats
	if err = os.WriteFile(local, []byte("third"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = transfer.UploadWithOptions(client.Raw(), local, "/keep.txt", nil, transfer.UploadOptions{Backup: true, Stats: &stats}); err != nil {
		t.Fatal(err)
	}
	if stats.Bytes != 5 || len(stats.Backups) != 1 || stats.SHA256 == "" {
		t.Fatalf("stats %+v", stats)
	}
	bak, err := sf.Open(stats.Backups[0])
	if err != nil {
		t.Fatal(err)
	}
	backed, err := io.ReadAll(bak)
	_ = bak.Close()
	if err != nil || string(backed) != "after" {
		t.Fatalf("backup %q %v", backed, err)
	}
	if read() != "third" {
		t.Fatalf("replaced %q", read())
	}
}

func TestUploadCancelBeforeCommitPreservesOriginal(t *testing.T) {
	srv, err := sshtest.Start("tester", "synthetic-pass", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	ctx, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	client, err := sshclient.Dial(ctx, srv.Addr, "tester", sshclient.PasswordAuth("synthetic-pass"), ssh.FixedHostKey(srv.Signer.PublicKey()), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	dir := t.TempDir()
	local, remote := filepath.Join(dir, "source"), filepath.Join(dir, "original")
	if err = os.WriteFile(local, []byte("after"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(remote, []byte("before"), 0600); err != nil {
		t.Fatal(err)
	}
	uploadCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	checks := 0
	err = transfer.UploadWithOptions(client.Raw(), local, remote, nil, transfer.UploadOptions{Context: uploadCtx, Check: func(string, []string) error {
		checks++
		if checks == 3 {
			cancel()
			return uploadCtx.Err()
		}
		return nil
	}})
	got, readErr := os.ReadFile(remote)
	if err == nil || readErr != nil || string(got) != "before" {
		t.Fatalf("cancel replaced original: %q %v %v", got, err, readErr)
	}
}

func TestUploadResolvesProtectedAliasBeforeWriting(t *testing.T) {
	client := memorySFTP(t)
	sf, err := transfer.Client(client.Raw())
	if err != nil {
		t.Fatal(err)
	}
	defer sf.Close()
	if err = sf.Mkdir("/real"); err != nil {
		t.Fatal(err)
	}
	if err = sf.Symlink("/real", "/protected-alias"); err != nil {
		t.Fatal(err)
	}
	local := filepath.Join(t.TempDir(), "new.txt")
	if err = os.WriteFile(local, []byte("new"), 0600); err != nil {
		t.Fatal(err)
	}
	err = transfer.UploadWithOptions(client.Raw(), local, "/real/new.txt", nil, transfer.UploadOptions{Protected: []string{"/protected-alias"}, Check: func(dest string, protected []string) error {
		for _, p := range protected {
			if strings.HasPrefix(dest, p+"/") {
				return fmt.Errorf("protected %s", p)
			}
		}
		return nil
	}})
	if err == nil {
		t.Fatal("protected alias bypassed")
	}
	if _, err = sf.Stat("/real/new.txt"); !os.IsNotExist(err) {
		t.Fatal("blocked upload wrote file")
	}
}
