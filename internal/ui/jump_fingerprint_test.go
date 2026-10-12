package ui

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/config"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/sshtest"
	"golang.org/x/crypto/ssh"
)

func TestJumpChainChangeDropsDestinationSession(t *testing.T) {
	jump, err := sshtest.Start("jumper", "jump-secret", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeSoon(jump) })
	mid, err := sshtest.Start("miduser", "mid-secret", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeSoon(mid) })
	dest, err := sshtest.Start("destuser", "dest-secret", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeSoon(dest) })
	jHost, jPort, err := net.SplitHostPort(jump.Addr)
	if err != nil {
		t.Fatal(err)
	}
	mHost, mPort, err := net.SplitHostPort(mid.Addr)
	if err != nil {
		t.Fatal(err)
	}
	dHost, dPort, err := net.SplitHostPort(dest.Addr)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := AddGroup(dir, GroupDraft{Name: "sandbox", Env: "dev"}); err != nil {
		t.Fatal(err)
	}
	add := func(alias, host, port, user, password, via string) {
		t.Helper()
		n, err := strconv.Atoi(port)
		if err != nil {
			t.Fatal(err)
		}
		if err := AddHost(dir, HostDraft{
			Alias: alias, Group: "sandbox", Address: host, Port: &n,
			User: user, Password: password, Via: via,
		}); err != nil {
			t.Fatal(err)
		}
	}
	add("jump", jHost, jPort, "jumper", "jump-secret", "")
	add("mid", mHost, mPort, "miduser", "mid-secret", "jump")
	add("box", dHost, dPort, "destuser", "dest-secret", "mid")
	add("spare", "192.0.2.9", "22", "spare", "spare-secret", "")

	s := newService(dir, false, "")
	t.Cleanup(func() {
		if s.pool != nil {
			s.pool.Shutdown()
		}
	})
	open := func() *ssh.Client {
		t.Helper()
		cfg, err := config.Load(dir)
		if err != nil {
			t.Fatal(err)
		}
		h, ok := cfg.Find("box")
		if !ok {
			t.Fatal("missing box")
		}
		fp := cfg.SessionFingerprint(h)
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		if err := s.pool.OpenConn(ctx, "box", fp); err != nil {
			t.Fatal(err)
		}
		raw, ok := s.pool.Client("box", fp)
		if !ok || raw == nil {
			t.Fatal("session was not pooled")
		}
		return raw
	}
	raw := open()

	if err := config.Update(dir, func(cfg *config.Config) error {
		cfg.Groups["sandbox"].Hosts["spare"].Host = "192.0.2.10"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	s.reconcile()
	kept, ok := s.pool.Client("box", s.fingerprint(config.ResolvedHost{Alias: "box"}))
	if !ok || kept != raw {
		t.Fatal("unrelated host edit dropped the destination session")
	}

	if err := config.Update(dir, func(cfg *config.Config) error {
		cfg.Groups["sandbox"].Hosts["jump"].Identity = "/tmp/ssh-cli-not-a-key"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	s.reconcile()
	if len(s.pool.List()) != 0 {
		t.Fatalf("identity file change kept the destination session: %+v", s.pool.List())
	}

	raw = open()
	if err := config.Update(dir, func(cfg *config.Config) error {
		cfg.Groups["sandbox"].Hosts["jump"].Host = "192.0.2.8"
		cfg.Groups["sandbox"].Hosts["jump"].Identity = ""
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	s.reconcile()
	if _, ok := s.pool.Client("box", s.fingerprint(config.ResolvedHost{Alias: "box"})); ok || len(s.pool.List()) != 0 {
		t.Fatal("jump address change kept the destination session")
	}
	if raw == nil {
		t.Fatal("previous client was nil")
	}
}
