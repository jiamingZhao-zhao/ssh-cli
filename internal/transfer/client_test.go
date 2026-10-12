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

func TestSFTPWindowHeadroom(t *testing.T) {
	n := safeConcurrentRequests()
	if n < 1 || n >= 64 {
		t.Fatalf("concurrency %d", n)
	}
	inflight := n * (sftpMaxPacket + sftpDataOverhead)
	if inflight >= sshChannelWindow {
		t.Fatalf("pipeline %d exceeds window %d", inflight, sshChannelWindow)
	}
}

func TestLargeDownloadKeepsPTY(t *testing.T) {
	srv, err := sshtest.Start("tester", "test-pass", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client, err := sshclient.Dial(ctx, srv.Addr, "tester", sshclient.PasswordAuth("test-pass"), sshclient.HostKeyCallback(filepath.Join(t.TempDir(), "known_hosts"), true), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	pty, err := sshclient.StartPTY(client.Raw(), 80, 24)
	if err != nil {
		t.Fatal(err)
	}
	defer pty.Close()

	big := filepath.Join(t.TempDir(), "big.bin")
	f, err := os.Create(big)
	if err != nil {
		t.Fatal(err)
	}
	const size = 3 << 20
	buf := make([]byte, 32*1024)
	for i := range buf {
		buf[i] = byte(i)
	}
	left := size
	for left > 0 {
		n := len(buf)
		if n > left {
			n = left
		}
		if _, err := f.Write(buf[:n]); err != nil {
			t.Fatal(err)
		}
		left -= n
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), "out.bin")
	if err := Download(client.Raw(), big, dest, nil); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(dest)
	if err != nil || info.Size() != size {
		t.Fatalf("downloaded size %v %v", info, err)
	}
	if _, err := pty.Write([]byte("echo still-open\n")); err != nil {
		t.Fatalf("pty closed after download: %v", err)
	}
}
