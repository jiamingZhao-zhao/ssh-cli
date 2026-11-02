package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/config"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/guard"
)

func TestImplicitExecReuseEligibilityAndNoReplay(t *testing.T) {
	previous := prepareImplicitExecDaemon
	t.Cleanup(func() { prepareImplicitExecDaemon = previous })
	var starts int
	prepareImplicitExecDaemon = func(*App) error { starts++; return nil }
	ro := planned{eff: guard.Effective{Mode: config.ModeReadonly}, dec: guard.Decision{Allowed: true}}
	std := planned{eff: guard.Effective{Mode: config.ModeStandard}, dec: guard.Decision{Allowed: true}}
	confirmed := ro
	confirmed.dec.NeedsConfirm = true
	cases := []struct {
		name                            string
		app                             *App
		plan                            []planned
		script, stdin, forward, outflow bool
		timeout                         time.Duration
		want                            bool
	}{
		{"bounded readonly", &App{MaxOutputBytes: 16384}, []planned{ro}, false, false, false, false, 30 * time.Second, true},
		{"parallel readonly", &App{MaxOutputBytes: 16384}, []planned{ro, ro}, false, false, false, false, time.Second, true},
		{"standard", &App{MaxOutputBytes: 16384}, []planned{std}, false, false, false, false, time.Second, false},
		{"confirmation", &App{MaxOutputBytes: 16384}, []planned{confirmed}, false, false, false, false, time.Second, false},
		{"direct", &App{Direct: true, MaxOutputBytes: 16384}, []planned{ro}, false, false, false, false, time.Second, false},
		{"manual daemon", &App{UseDaemon: true, MaxOutputBytes: 16384}, []planned{ro}, false, false, false, false, time.Second, false},
		{"no cap", &App{}, []planned{ro}, false, false, false, false, time.Second, false},
		{"oversize cap", &App{MaxOutputBytes: 65537}, []planned{ro}, false, false, false, false, time.Second, false},
		{"no timeout", &App{MaxOutputBytes: 16384}, []planned{ro}, false, false, false, false, 0, false},
		{"long timeout", &App{MaxOutputBytes: 16384}, []planned{ro}, false, false, false, false, time.Hour + 1, false},
		{"script", &App{MaxOutputBytes: 16384}, []planned{ro}, true, false, false, false, time.Second, false},
		{"stdin", &App{MaxOutputBytes: 16384}, []planned{ro}, false, true, false, false, time.Second, false},
		{"forward", &App{MaxOutputBytes: 16384}, []planned{ro}, false, false, true, false, time.Second, false},
		{"outflow", &App{MaxOutputBytes: 16384}, []planned{ro}, false, false, false, true, time.Second, false},
		{"insecure", &App{Insecure: true, MaxOutputBytes: 16384}, []planned{ro}, false, false, false, false, time.Second, false},
		{"too many hosts", &App{MaxOutputBytes: 16384}, make([]planned, 17), false, false, false, false, time.Second, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var warn bytes.Buffer
			tc.app.Err = &warn
			before := starts
			if err := tc.app.prepareExecReuse(tc.plan, tc.script, tc.stdin, tc.forward, tc.outflow, tc.timeout); err != nil {
				t.Fatal(err)
			}
			if (starts > before) != tc.want || tc.want && (!tc.app.UseDaemon || !tc.app.AutoDaemon) {
				t.Fatalf("start=%d app=%+v", starts-before, tc.app)
			}
		})
	}
	prepareImplicitExecDaemon = func(*App) error { return errors.New("unavailable") }
	var warnings bytes.Buffer
	a := &App{MaxOutputBytes: 16384, Err: &warnings}
	if err := a.prepareExecReuse([]planned{ro}, false, false, false, false, time.Second); err != nil || a.UseDaemon || !strings.Contains(warnings.String(), "before dispatch") {
		t.Fatalf("startup fallback: %v %s", err, warnings.String())
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	a.OperationContext = canceled
	if err := a.prepareExecReuse([]planned{ro}, false, false, false, false, time.Second); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation: %v", err)
	}

	// A lost response must never cause a second IPC attempt or direct replay.
	dir := t.TempDir()
	sock, token := daemonPaths(dir)
	if err := os.WriteFile(token, []byte(strings.Repeat("a", 64)), 0600); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Skipf("AF_UNIX unavailable: %v", err)
	}
	defer ln.Close()
	var count atomic.Int32
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { count.Add(1); _, _ = io.WriteString(w, "{") })}
	go server.Serve(ln)
	defer server.Close()
	a = &App{Dir: dir, Err: io.Discard, UseDaemon: true}
	_, err = a.runOneObserved(ro, "ls", "", io.Discard, io.Discard, nil, time.Second, &connectionInfo{})
	if err == nil || count.Load() != 1 {
		t.Fatalf("lost reply: count=%d err=%v", count.Load(), err)
	}
}

func TestReuseDaemonStopAndCapability(t *testing.T) {
	dir := t.TempDir()
	if err := config.Save(dir, &config.Config{Version: 1}); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	a := &App{Dir: dir, Out: &stdout, Err: &stderr}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- a.serveDaemonWithIdle(ctx, 0) }()
	sock, _ := daemonPaths(dir)
	deadline := time.Now().Add(3 * time.Second)
	for {
		if c, err := net.DialTimeout("unix", sock, 50*time.Millisecond); err == nil {
			c.Close()
			break
		}
		select {
		case err := <-done:
			t.Skipf("AF_UNIX unavailable: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("daemon did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := a.verifyAutoReuseCapabilities(); err != nil {
		t.Fatalf("capability: %v", err)
	}
	if err := a.stopReuseDaemon(context.Background()); err != nil {
		t.Fatalf("stop: %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("daemon did not exit")
	}
	if _, err := os.Stat(sock); !os.IsNotExist(err) {
		t.Fatalf("socket remains: %v", err)
	}
	if !strings.Contains(stdout.String(), "stopped") {
		t.Fatal(stdout.String())
	}
	if err := a.stopReuseDaemon(context.Background()); err != nil {
		t.Fatal(err)
	}
}
