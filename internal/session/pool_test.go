package session

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/sshclient"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/sshtest"
)

func testPool(t *testing.T) (*Pool, *sshtest.Server, *[]string) {
	t.Helper()
	srv, err := sshtest.Start("tester", "test-pass", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	var reasons []string
	pool, err := New(DefaultIdle, DefaultMaxLife, func(ctx context.Context, alias string) (*sshclient.Client, error) {
		return sshclient.Dial(ctx, srv.Addr, "tester", sshclient.PasswordAuth("test-pass"), sshclient.HostKeyCallback(filepath.Join(t.TempDir(), "known_hosts"), true), 5*time.Second)
	}, func(alias, reason string) {
		reasons = append(reasons, alias+":"+reason)
	})
	if err != nil {
		t.Fatal(err)
	}
	return pool, srv, &reasons
}

func TestShellKeepsWorkingDirectory(t *testing.T) {
	pool, _, _ := testPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var out bytes.Buffer
	if code, err := pool.Exec(ctx, "main", "cd /tmp", nil, nil); err != nil || code != 0 {
		t.Fatalf("cd code %d err %v", code, err)
	}
	out.Reset()
	if code, err := pool.Exec(ctx, "main", "pwd", &out, nil); err != nil || code != 0 {
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

func TestIdleAndMaxLife(t *testing.T) {
	pool, _, reasons := testPool(t)
	start := time.Date(2026, 10, 9, 3, 0, 0, 0, time.UTC)
	now := start
	pool.SetClock(func() time.Time { return now })
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := pool.Open(ctx, "main", false); err != nil {
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
	if err := pool.Open(ctx, "busy", false); err != nil {
		t.Fatal(err)
	}
	held := make(chan struct{})
	release := make(chan struct{})
	done := make(chan struct{})
	go func() {
		_ = pool.Use("busy", func() error {
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

func TestShutdownAuditsProcessExit(t *testing.T) {
	pool, _, reasons := testPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := pool.Open(ctx, "main", false); err != nil {
		t.Fatal(err)
	}
	pool.Shutdown()
	if len(*reasons) != 1 || (*reasons)[0] != "main:process_exit" {
		t.Fatalf("reasons %v", *reasons)
	}
}
