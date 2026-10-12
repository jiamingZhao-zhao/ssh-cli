package sshclient

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/sshtest"
	"golang.org/x/crypto/ssh"
)

func TestDialHopsShellAndExecStayOnDestination(t *testing.T) {
	root, err := sshtest.Start("rootuser", "root-secret", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(root.Close)
	mid, err := sshtest.Start("miduser", "mid-secret", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mid.Close)
	dest, err := sshtest.Start("destuser", "dest-secret", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(dest.Close)

	dir := t.TempDir()
	cb := HostKeyCallback(filepath.Join(dir, "known_hosts"), false)
	hop := func(name, addr, user, secret string) Hop {
		return Hop{Name: name, Addr: addr, User: user, Auth: PasswordAuth(secret), HostKey: cb}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	client, err := DialHops(ctx, []Hop{
		hop("root", root.Addr, "rootuser", "root-secret"),
		hop("mid", mid.Addr, "miduser", "mid-secret"),
		hop("dest", dest.Addr, "destuser", "dest-secret"),
	}, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })

	pty, err := StartPTY(client.Raw(), 80, 24)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pty.Close() })
	if root.Sessions() != 0 || mid.Sessions() != 0 || dest.Sessions() != 1 {
		t.Fatalf("pty sessions root=%d mid=%d dest=%d", root.Sessions(), mid.Sessions(), dest.Sessions())
	}

	var buf bytes.Buffer
	code, err := client.Run(ctx, "echo dest-only", &buf, io.Discard, nil)
	if err != nil || code != 0 || !strings.Contains(buf.String(), "dest-only") {
		t.Fatalf("run code=%d err=%v out=%q sessions=%d", code, err, buf.String(), dest.Sessions())
	}
	if root.Sessions() != 0 || mid.Sessions() != 0 || dest.Sessions() != 2 {
		t.Fatalf("exec sessions root=%d mid=%d dest=%d", root.Sessions(), mid.Sessions(), dest.Sessions())
	}
	known, err := ListKnownHosts(filepath.Join(dir, "known_hosts"))
	if err != nil {
		t.Fatal(err)
	}
	blob := ""
	for _, line := range known {
		blob += line.Marker + "\n"
	}
	for _, addr := range []string{root.Addr, mid.Addr, dest.Addr} {
		_, port, err := net.SplitHostPort(addr)
		if err != nil || !strings.Contains(blob, port) {
			t.Fatalf("known_hosts missing %s\n%s", addr, blob)
		}
	}

	ctx2, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel2()
	_, err = DialHops(ctx2, []Hop{
		hop("root", root.Addr, "rootuser", "root-secret"),
		hop("dest", dest.Addr, "destuser", "wrong-secret"),
	}, 8*time.Second)
	if err == nil {
		t.Fatal("bad destination password was accepted")
	}
	if root.Sessions() != 0 || dest.Sessions() != 2 {
		t.Fatalf("failed hop opened a session root=%d dest=%d", root.Sessions(), dest.Sessions())
	}
}

func silentBanner(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 64)
				_, _ = c.Read(buf)
				_, _ = io.Copy(io.Discard, c)
			}(c)
		}
	}()
	return ln
}

func testHop(name, addr, user, secret string) Hop {
	return Hop{Name: name, Addr: addr, User: user, Auth: PasswordAuth(secret), HostKey: ssh.InsecureIgnoreHostKey()}
}

func waitConns(s *sshtest.Server, want int) bool {
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if s.Connections() == want {
			return true
		}
		time.Sleep(15 * time.Millisecond)
	}
	return s.Connections() == want
}

func TestDialHopsSilentBannerTimesOut(t *testing.T) {
	jump, err := sshtest.Start("jumper", "jump-secret", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(jump.Close)
	silent := silentBanner(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	start := time.Now()
	_, err = DialHops(ctx, []Hop{
		testHop("jump", jump.Addr, "jumper", "jump-secret"),
		testHop("dest", silent.Addr().String(), "dest", "nope"),
	}, time.Second)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("silent banner handshake returned success")
	}
	if !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "dest") {
		t.Fatalf("err %v", err)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("handshake ignored timeout: %s", elapsed)
	}
	if !waitConns(jump, 0) {
		t.Fatalf("jump carrier still open: %d", jump.Connections())
	}
}

func TestDialHopsContextCancel(t *testing.T) {
	jump, err := sshtest.Start("jumper", "jump-secret", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(jump.Close)
	silent := silentBanner(t)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(200 * time.Millisecond)
		cancel()
	}()
	start := time.Now()
	_, err = DialHops(ctx, []Hop{
		testHop("jump", jump.Addr, "jumper", "jump-secret"),
		testHop("dest", silent.Addr().String(), "dest", "nope"),
	}, 30*time.Second)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("cancelled handshake returned success")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err %v", err)
	}
	if elapsed > 3*time.Second {
		t.Fatalf("cancel did not unblock handshake: %s", elapsed)
	}
	if !waitConns(jump, 0) {
		t.Fatalf("jump carrier still open: %d", jump.Connections())
	}
}

func TestDialHopsMidChainTimeout(t *testing.T) {
	jump, err := sshtest.Start("jumper", "jump-secret", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(jump.Close)
	mid := silentBanner(t)
	destLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = destLn.Close() })
	var hits atomic.Int32
	go func() {
		for {
			c, err := destLn.Accept()
			if err != nil {
				return
			}
			hits.Add(1)
			_ = c.Close()
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	start := time.Now()
	_, err = DialHops(ctx, []Hop{
		testHop("jump", jump.Addr, "jumper", "jump-secret"),
		testHop("mid", mid.Addr().String(), "mid", "nope"),
		testHop("dest", destLn.Addr().String(), "dest", "nope"),
	}, time.Second)
	if err == nil {
		t.Fatal("stalled middle hop returned success")
	}
	if !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "mid") {
		t.Fatalf("err %v", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatalf("middle hop ignored timeout: %s", time.Since(start))
	}
	if hits.Load() != 0 {
		t.Fatalf("dial continued past the stalled hop: %d", hits.Load())
	}
	if !waitConns(jump, 0) {
		t.Fatalf("jump carrier still open: %d", jump.Connections())
	}
}
