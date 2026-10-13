package cli

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/config"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/guard"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/session"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/sshclient"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/sshtest"
)

func TestElevationTTLBoundaries(t *testing.T) {
	if _, err := elevationTTL(&config.Env{}, "1m"); err == nil {
		t.Fatal("disabled grant accepted")
	}
	env := &config.Env{BreakGlass: &config.BreakGlass{Enabled: true, MaxTTL: "15m"}}
	for _, raw := range []string{"0s", "-1s", "16m", "invalid"} {
		if _, err := elevationTTL(env, raw); err == nil {
			t.Fatal(raw)
		}
	}
	if _, err := elevationTTL(env, "10m"); err != nil {
		t.Fatal(err)
	}
}

func TestDaemonIPC(t *testing.T) {
	dir := t.TempDir()
	if err := config.Save(dir, &config.Config{Version: 1}); err != nil {
		t.Fatal(err)
	}
	a := &App{Dir: dir, Err: io.Discard, Out: io.Discard}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.serveDaemon(ctx) }()
	defer func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(3 * time.Second):
			t.Error("reuse service did not stop")
		}
	}()
	sock, tokenPath := daemonPaths(dir)
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := os.Stat(tokenPath); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("reuse service did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", sock)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	response, err := client.Post("http://localhost/exec", "application/json", strings.NewReader(`{"alias":"missing","command":"echo x"}`))
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 401 {
		t.Fatal("local reuse API accepted missing token")
	}
	_, err = a.runViaDaemon(planned{host: config.ResolvedHost{Alias: "missing"}}, "echo x", io.Discard, io.Discard, time.Second)
	if err == nil || !strings.Contains(err.Error(), "outcome=not_started") {
		t.Fatalf("unexpected authenticated result: %v", err)
	}
}

func TestDaemonReusesConnectionAndRechecksPolicy(t *testing.T) {
	srv, err := sshtest.Start("tester", "pass", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	dir := t.TempDir()
	cfg := &config.Config{Version: 1, Groups: map[string]*config.Group{"g": {Env: "test", Hosts: map[string]*config.Host{"a": {Host: "127.0.0.1", User: "tester"}}}}}
	if err := config.Save(dir, cfg); err != nil {
		t.Fatal(err)
	}
	a := &App{Dir: dir, Err: io.Discard, Out: io.Discard}
	pool, err := session.New(time.Minute, time.Hour, func(ctx context.Context, alias, fp string) (*sshclient.Client, error) {
		return sshclient.Dial(ctx, srv.Addr, "tester", sshclient.PasswordAuth("pass"), sshclient.HostKeyCallback(dir+"/known_hosts", true), 3*time.Second)
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Shutdown()
	for i := 0; i < 3; i++ {
		r := a.daemonExec(context.Background(), pool, daemonRequest{Alias: "a", Command: "echo reuse", Timeout: time.Second})
		if r.Outcome != "completed" || !strings.Contains(r.Stdout, "reuse") || r.Error != "" {
			t.Fatalf("result: %+v", r)
		}
	}
	if srv.Connections() != 1 {
		t.Fatalf("connections %d", srv.Connections())
	}
	if err := config.Update(dir, func(c *config.Config) error { c.Groups["g"].Hosts["a"].Deny = []string{"echo"}; return nil }); err != nil {
		t.Fatal(err)
	}
	r := a.daemonExec(context.Background(), pool, daemonRequest{Alias: "a", Command: "echo forbidden"})
	if r.Outcome != "not_started" || r.Error == "" || srv.Sessions() != 3 {
		t.Fatalf("policy change bypassed: %+v", r)
	}
	r = a.daemonExec(context.Background(), pool, daemonRequest{Alias: "a", Command: "systemctl restart app"})
	if r.Outcome != "not_started" {
		t.Fatal("accepted confirming command")
	}
	h, _ := cfg.Find("a")
	eff, _ := guard.Resolve(cfg, h, false)
	var output bytes.Buffer
	if _, err := a.runViaDaemon(planned{host: h, eff: eff}, "echo x", &output, io.Discard, time.Second); err == nil {
		t.Fatal("missing daemon silently fell back")
	}
}
