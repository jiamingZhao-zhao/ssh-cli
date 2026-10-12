package sshclient

import (
	"bytes"
	"context"
	"io"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/sshtest"
)

func shortenKeepAlive(t *testing.T, every, wait time.Duration) {
	t.Helper()
	prevEvery, prevWait := keepAliveEvery, keepAliveWait
	keepAliveEvery = every
	keepAliveWait = wait
	t.Cleanup(func() {
		keepAliveEvery = prevEvery
		keepAliveWait = prevWait
	})
}

func TestKeepAliveReachesServerAndExecStillWorks(t *testing.T) {
	shortenKeepAlive(t, 40*time.Millisecond, time.Second)
	srv, err := sshtest.Start("tester", "test-pass", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, err := Dial(ctx, srv.Addr, "tester", PasswordAuth("test-pass"), HostKeyCallback(filepath.Join(t.TempDir(), "known_hosts"), true), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	deadline := time.Now().Add(3 * time.Second)
	for srv.KeepAlives() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("server saw no keepalive")
		}
		time.Sleep(15 * time.Millisecond)
	}
	var buf bytes.Buffer
	code, err := client.Run(ctx, "echo alive", &buf, io.Discard, nil)
	if err != nil || code != 0 || !strings.Contains(buf.String(), "alive") {
		t.Fatalf("code %d err %v out %q", code, err, buf.String())
	}
}

func TestKeepAliveOnJumpAndDestination(t *testing.T) {
	shortenKeepAlive(t, 40*time.Millisecond, time.Second)
	jump, err := sshtest.Start("jumper", "jump-secret", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(jump.Close)
	dest, err := sshtest.Start("destuser", "dest-secret", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(dest.Close)
	cb := HostKeyCallback(filepath.Join(t.TempDir(), "known_hosts"), true)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, err := DialHops(ctx, []Hop{
		{Name: "jump", Addr: jump.Addr, User: "jumper", Auth: PasswordAuth("jump-secret"), HostKey: cb},
		{Name: "dest", Addr: dest.Addr, User: "destuser", Auth: PasswordAuth("dest-secret"), HostKey: cb},
	}, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	deadline := time.Now().Add(3 * time.Second)
	for jump.KeepAlives() == 0 || dest.KeepAlives() == 0 {
		if time.Now().After(deadline) {
			t.Fatalf("keepalive jump=%d dest=%d", jump.KeepAlives(), dest.KeepAlives())
		}
		time.Sleep(15 * time.Millisecond)
	}
}

func TestKeepAliveClosesSilentPeer(t *testing.T) {
	shortenKeepAlive(t, 30*time.Millisecond, 80*time.Millisecond)
	srv, err := sshtest.Start("tester", "test-pass", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	addr, freeze := holdProxy(t, srv.Addr)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	client, err := Dial(ctx, addr, "tester", PasswordAuth("test-pass"), HostKeyCallback(filepath.Join(t.TempDir(), "known_hosts"), true), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	freeze()
	start := time.Now()
	runCtx, runCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer runCancel()
	_, err = client.Run(runCtx, "echo should-not-run", nil, nil, nil)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("silent peer still ran a command")
	}
	if elapsed > 2*time.Second {
		t.Fatalf("dead peer hung for %s: %v", elapsed, err)
	}
	if !client.Dead() {
		t.Fatalf("silent peer returned %v in %s without marking the client dead", err, elapsed)
	}
}

// holdProxy forwards until freeze. After freeze the upstream replies are not
// copied back, and the sockets stay open so the client sees a black hole
// rather than a TCP close.
func holdProxy(t *testing.T, upstream string) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	freezeCh := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	freeze := func() { once.Do(func() { close(freezeCh) }) }
	t.Cleanup(func() {
		freeze()
		select {
		case <-release:
		default:
			close(release)
		}
		_ = ln.Close()
	})
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		u, err := net.Dial("tcp", upstream)
		if err != nil {
			return
		}
		defer u.Close()
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			forwardUntil(u, c, nil, release)
		}()
		go func() {
			defer wg.Done()
			forwardUntil(c, u, freezeCh, release)
		}()
		wg.Wait()
	}()
	return ln.Addr().String(), freeze
}

func forwardUntil(dst, src net.Conn, stop, release <-chan struct{}) {
	buf := make([]byte, 32<<10)
	for {
		if stop != nil {
			select {
			case <-stop:
				<-release
				return
			default:
			}
		}
		_ = src.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
		n, err := src.Read(buf)
		if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				if stop != nil {
					<-release
				}
				return
			}
		}
		if err == nil {
			continue
		}
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			continue
		}
		if stop != nil {
			<-release
		}
		return
	}
}
