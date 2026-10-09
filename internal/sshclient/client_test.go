package sshclient

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/sshtest"
)

type netAddr string

func (a netAddr) Network() string { return "tcp" }
func (a netAddr) String() string  { return string(a) }

func TestTOFURejectsChangedKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "known_hosts")
	a, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	b, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sa, err := ssh.NewSignerFromKey(a)
	if err != nil {
		t.Fatal(err)
	}
	sb, err := ssh.NewSignerFromKey(b)
	if err != nil {
		t.Fatal(err)
	}
	cb := HostKeyCallback(path, false)
	addr := netAddr("127.0.0.1:2222")
	if err := cb("127.0.0.1:2222", addr, sa.PublicKey()); err != nil {
		t.Fatal(err)
	}
	if err := cb("127.0.0.1:2222", addr, sa.PublicKey()); err != nil {
		t.Fatalf("same key: %v", err)
	}
	err = cb("127.0.0.1:2222", addr, sb.PublicKey())
	var changed *HostKeyChangedError
	if !errors.As(err, &changed) {
		t.Fatalf("want host key change, got %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o", info.Mode().Perm())
	}
	insecure := HostKeyCallback(path, true)
	if err := insecure("127.0.0.1:2222", addr, sb.PublicKey()); err != nil {
		t.Fatal(err)
	}
}

func TestPasswordExecExitAndTransfer(t *testing.T) {
	srv, err := sshtest.Start("tester", "test-pass", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)

	dir := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, err := Dial(ctx, srv.Addr, "tester", PasswordAuth("test-pass"), HostKeyCallback(filepath.Join(dir, "known_hosts"), false), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	code, err := client.Run(ctx, "exit 7", nil, nil, nil)
	if err != nil || code != 7 {
		t.Fatalf("exit code %d err %v", code, err)
	}
	// A second connection with the recorded key must succeed, and a replaced
	// server key must be rejected.
	client.Close()
	client, err = Dial(ctx, srv.Addr, "tester", PasswordAuth("test-pass"), HostKeyCallback(filepath.Join(dir, "known_hosts"), false), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	client.Close()

	badDir := t.TempDir()
	// Seed known_hosts with a different key, then dial the real server.
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	osigner, err := ssh.NewSignerFromKey(other)
	if err != nil {
		t.Fatal(err)
	}
	kh := filepath.Join(badDir, "known_hosts")
	cb := HostKeyCallback(kh, false)
	if err := cb(srv.Addr, mustAddr(srv.Addr), osigner.PublicKey()); err != nil {
		t.Fatal(err)
	}
	_, err = Dial(ctx, srv.Addr, "tester", PasswordAuth("test-pass"), HostKeyCallback(kh, false), 5*time.Second)
	if err == nil {
		t.Fatal("expected host key rejection")
	}
	if _, ok := err.(*HostKeyChangedError); !ok && !errors.As(err, new(*HostKeyChangedError)) {
		// Dial returns the callback error directly, before Wrap.
		var changed *HostKeyChangedError
		if !errors.As(err, &changed) {
			t.Fatalf("dial error = %v", err)
		}
	}
}

func mustAddr(s string) net.Addr { return netAddr(s) }

func TestDialTimeoutBoundsHandshake(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var held []net.Conn
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			held = append(held, c)
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, c := range held {
			_ = c.Close()
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	start := time.Now()
	_, err = Dial(ctx, ln.Addr().String(), "tester", PasswordAuth("x"), HostKeyCallback(filepath.Join(t.TempDir(), "known_hosts"), true), 300*time.Millisecond)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected handshake timeout")
	}
	if elapsed > 2*time.Second {
		t.Fatalf("handshake waited %s", elapsed)
	}
}
