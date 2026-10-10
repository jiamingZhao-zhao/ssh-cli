package sshclient

import (
	"bytes"
	"context"
	"io"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/sshtest"
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
