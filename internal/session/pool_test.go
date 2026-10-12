package session

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/sshclient"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/sshtest"
	"golang.org/x/crypto/ssh"
)

const testFingerprint = "test-server"

func testPool(t *testing.T) (*Pool, *sshtest.Server, *[]string) {
	t.Helper()
	srv, err := sshtest.Start("tester", "test-pass", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	var reasons []string
	pool, err := New(DefaultIdle, DefaultMaxLife, func(ctx context.Context, alias, _ string) (*sshclient.Client, error) {
		return sshclient.Dial(ctx, srv.Addr, "tester", sshclient.PasswordAuth("test-pass"), sshclient.HostKeyCallback(filepath.Join(t.TempDir(), "known_hosts"), true), 5*time.Second)
	}, func(alias, reason string) {
		reasons = append(reasons, alias+":"+reason)
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Shutdown)
	return pool, srv, &reasons
}

func TestShellKeepsWorkingDirectory(t *testing.T) {
	pool, _, _ := testPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var out bytes.Buffer
	if code, err := pool.Exec(ctx, "main", testFingerprint, "cd /tmp", nil, nil); err != nil || code != 0 {
		t.Fatalf("cd code %d err %v", code, err)
	}
	out.Reset()
	if code, err := pool.Exec(ctx, "main", testFingerprint, "pwd", &out, nil); err != nil || code != 0 {
		t.Fatalf("pwd code %d err %v", code, err)
	}
	if got := out.String(); got != "/tmp\n" {
		t.Fatalf("pwd %q", got)
	}
	pool.Close("main")
	if len(pool.List()) != 0 {
		t.Fatalf("still listed: %+v", pool.List())
	}
}

func TestListCountdown(t *testing.T) {
	pool, _, _ := testPool(t)
	start := time.Date(2026, 10, 9, 4, 0, 0, 0, time.UTC)
	now := start
	pool.SetClock(func() time.Time { return now })
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := pool.Open(ctx, "main", testFingerprint, false); err != nil {
		t.Fatal(err)
	}
	now = start.Add(time.Minute)
	info := pool.List()
	if len(info) != 1 || info[0].Status != "open" {
		t.Fatalf("list %+v", info)
	}
	if info[0].IdleLeftSec != int((DefaultIdle-time.Minute)/time.Second) {
		t.Fatalf("idle left %d", info[0].IdleLeftSec)
	}
	if info[0].LifeLeftSec != int((DefaultMaxLife-time.Minute)/time.Second) {
		t.Fatalf("life left %d", info[0].LifeLeftSec)
	}
	if info[0].IdleLeft == "" || info[0].LifeLeft == "" {
		t.Fatalf("missing countdown strings %+v", info[0])
	}
}

func TestIdleAndMaxLife(t *testing.T) {
	pool, _, reasons := testPool(t)
	start := time.Date(2026, 10, 9, 3, 0, 0, 0, time.UTC)
	now := start
	pool.SetClock(func() time.Time { return now })
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := pool.Open(ctx, "main", testFingerprint, false); err != nil {
		t.Fatal(err)
	}
	now = start.Add(DefaultIdle)
	pool.Sweep(now)
	if len(pool.List()) != 0 {
		t.Fatalf("idle session still open: %+v", pool.List())
	}
	if len(*reasons) != 1 || (*reasons)[0] != "main:idle" {
		t.Fatalf("reasons %v", *reasons)
	}

	now = start
	if err := pool.Open(ctx, "busy", testFingerprint, false); err != nil {
		t.Fatal(err)
	}
	held := make(chan struct{})
	release := make(chan struct{})
	done := make(chan struct{})
	go func() {
		_ = pool.Use("busy", testFingerprint, func() error {
			close(held)
			<-release
			return nil
		})
		close(done)
	}()
	<-held
	now = start.Add(DefaultIdle)
	pool.Sweep(now)
	if len(pool.List()) != 1 {
		t.Fatalf("busy session should survive idle: %+v", pool.List())
	}
	now = start.Add(DefaultMaxLife)
	pool.Sweep(now)
	if len(pool.List()) != 0 {
		t.Fatalf("max life should close a busy session: %+v", pool.List())
	}
	close(release)
	<-done
	pool.Shutdown()
	found := false
	for _, r := range *reasons {
		if r == "busy:max_life" {
			found = true
		}
	}
	if !found {
		t.Fatalf("reasons %v", *reasons)
	}
}

func TestMaxLifeHooksBeforeSSHClose(t *testing.T) {
	srv, err := sshtest.Start("tester", "test-pass", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	var mu sync.Mutex
	var raw *ssh.Client
	dial := func(ctx context.Context, alias, _ string) (*sshclient.Client, error) {
		c, err := sshclient.Dial(ctx, srv.Addr, "tester", sshclient.PasswordAuth("test-pass"), sshclient.HostKeyCallback(filepath.Join(t.TempDir(), "known_hosts"), true), 5*time.Second)
		if err != nil {
			return nil, err
		}
		mu.Lock()
		raw = c.Raw()
		mu.Unlock()
		return c, nil
	}
	pool, err := New(time.Hour, time.Hour, dial, func(alias, reason string) {
		mu.Lock()
		conn := raw
		mu.Unlock()
		if conn == nil {
			t.Errorf("missing client at onClose")
			return
		}
		if _, _, err := conn.SendRequest("keepalive@openssh.com", true, nil); err == nil {
			t.Errorf("ssh client still answered after close, reason %s", reason)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Shutdown)
	pool.SetBeforeClose(func(alias, reason string) {
		if alias != "main" || reason != "max_life" {
			t.Errorf("before %s %s", alias, reason)
			return
		}
		mu.Lock()
		conn := raw
		mu.Unlock()
		if conn == nil {
			t.Errorf("missing client before close")
			return
		}
		if _, _, err := conn.SendRequest("keepalive@openssh.com", true, nil); err != nil {
			t.Errorf("ssh closed before the max-life notice: %v", err)
		}
	})
	start := time.Date(2026, 10, 12, 3, 0, 0, 0, time.UTC)
	now := start
	pool.SetClock(func() time.Time { return now })
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := pool.Open(ctx, "main", testFingerprint, false); err != nil {
		t.Fatal(err)
	}
	now = start.Add(time.Hour)
	pool.Sweep(now)
	if len(pool.List()) != 0 {
		t.Fatalf("max life left the session open: %+v", pool.List())
	}
}

func TestShutdownAuditsProcessExit(t *testing.T) {
	pool, _, reasons := testPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := pool.Open(ctx, "main", testFingerprint, false); err != nil {
		t.Fatal(err)
	}
	pool.Shutdown()
	if len(*reasons) != 1 || (*reasons)[0] != "main:process_exit" {
		t.Fatalf("reasons %v", *reasons)
	}
}

func TestExecKeepsBytesWithoutTrailingNewline(t *testing.T) {
	pool, _, _ := testPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var out bytes.Buffer
	code, err := pool.Exec(ctx, "main", testFingerprint, "printf 'synthetic-no-newline'", &out, nil)
	if err != nil || code != 0 {
		t.Fatalf("code %d err %v out %q", code, err, out.String())
	}
	if out.String() != "synthetic-no-newline" || strings.Contains(out.String(), "DONE_") {
		t.Fatalf("out %q", out.String())
	}
	out.Reset()
	code, err = pool.Exec(ctx, "main", testFingerprint, "printf 'a\\n'", &out, nil)
	if err != nil || code != 0 || out.String() != "a\n" {
		t.Fatalf("newline code %d err %v out %q", code, err, out.String())
	}
}

func TestOpenConnThenExecStartsShell(t *testing.T) {
	pool, _, reasons := testPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := pool.OpenConn(ctx, "main", testFingerprint); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	code, err := pool.Exec(ctx, "main", testFingerprint, "printf ok", &out, nil)
	if err != nil || code != 0 || out.String() != "ok" {
		t.Fatalf("code %d err %v out %q reasons %v", code, err, out.String(), *reasons)
	}
	if len(pool.List()) != 1 {
		t.Fatalf("session dropped: %+v reasons %v", pool.List(), *reasons)
	}
	for _, r := range *reasons {
		if strings.Contains(r, "desync") {
			t.Fatalf("desync %v", *reasons)
		}
	}
	if strings.Contains(errString(err), "has no shell") {
		t.Fatalf("noisy shell error %v", err)
	}
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func TestExecTimeoutDropsSession(t *testing.T) {
	pool, _, reasons := testPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := pool.Open(ctx, "main", testFingerprint, false); err != nil {
		t.Fatal(err)
	}
	short, cancelShort := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancelShort()
	if _, err := pool.Exec(short, "main", testFingerprint, "sleep 30", nil, nil); err == nil {
		t.Fatal("expected timeout")
	}
	if len(pool.List()) != 0 {
		t.Fatalf("session kept after timeout: %+v", pool.List())
	}
	found := false
	for _, r := range *reasons {
		if r == "main:desync" {
			found = true
		}
	}
	if !found {
		t.Fatalf("reasons %v", *reasons)
	}
}

func TestPoolDoesNotReuseAcrossIdentity(t *testing.T) {
	a, err := sshtest.Start("tester", "test-pass", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	b, err := sshtest.Start("tester", "test-pass", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Close)
	pool, err := New(DefaultIdle, DefaultMaxLife, func(ctx context.Context, alias, fp string) (*sshclient.Client, error) {
		srv := a
		if fp == "b" {
			srv = b
		}
		return sshclient.Dial(ctx, srv.Addr, "tester", sshclient.PasswordAuth("test-pass"), sshclient.HostKeyCallback(filepath.Join(t.TempDir(), "known_hosts"), true), 5*time.Second)
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Shutdown)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if code, err := pool.Exec(ctx, "box", "a", "X=from-a", nil, nil); err != nil || code != 0 {
		t.Fatalf("set code %d err %v", code, err)
	}
	var out bytes.Buffer
	if code, err := pool.Exec(ctx, "box", "a", "printf %s \"$X\"", &out, nil); err != nil || code != 0 {
		t.Fatalf("echo code %d err %v", code, err)
	}
	if out.String() != "from-a" {
		t.Fatalf("same identity %q", out.String())
	}
	out.Reset()
	if code, err := pool.Exec(ctx, "box", "b", "printf %s \"$X\"", &out, nil); err != nil || code != 0 {
		t.Fatalf("other code %d err %v out %q", code, err, out.String())
	}
	if out.String() != "" {
		t.Fatalf("reused old connection %q", out.String())
	}
}
