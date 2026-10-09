package transfer

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/sshclient"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/sshtest"
)

func TestParseRemoteSum(t *testing.T) {
	sum := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	got, err := parseSumOutput("\\" + sum + "  D:\\tmp\\file")
	if err != nil || got != sum {
		t.Fatalf("msys %q %v", got, err)
	}
	md := "d41d8cd98f00b204e9800998ecf8427e"
	got, err = parseSumOutput("MD5 (file) = " + md)
	if err != nil || got != md {
		t.Fatalf("bsd %q %v", got, err)
	}
}

func TestRelayHashesFile(t *testing.T) {
	src, err := sshtest.Start("tester", "test-pass", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(src.Close)
	dst, err := sshtest.Start("tester", "test-pass", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(dst.Close)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	dial := func(addr string) *sshclient.Client {
		t.Helper()
		c, err := sshclient.Dial(ctx, addr, "tester", sshclient.PasswordAuth("test-pass"), sshclient.HostKeyCallback(filepath.Join(t.TempDir(), "known_hosts"), true), 5*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	left := dial(src.Addr)
	right := dial(dst.Addr)
	defer left.Close()
	defer right.Close()
	from := filepath.Join(t.TempDir(), "src.bin")
	to := filepath.Join(t.TempDir(), "nested", "dst.bin")
	if err := os.WriteFile(from, []byte("relay-bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := Relay(left.Raw(), right.Raw(), from, to)
	if err != nil {
		t.Fatal(err)
	}
	if res.Algo != "sha256" || res.Bytes != 11 {
		t.Fatalf("result %+v", res)
	}
	got, err := os.ReadFile(to)
	if err != nil || string(got) != "relay-bytes" {
		t.Fatalf("copied %q %v", got, err)
	}
}
