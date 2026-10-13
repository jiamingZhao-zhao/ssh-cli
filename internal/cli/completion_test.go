package cli

import (
	"bytes"
	"context"
	"io"
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
