package cli

import (
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestDialBudget(t *testing.T) {
	if dialBudget(0) != defaultDialTimeout {
		t.Fatalf("unset = %s", dialBudget(0))
	}
	if dialBudget(3*time.Second) != 3*time.Second {
		t.Fatalf("3s = %s", dialBudget(3*time.Second))
	}
	if dialBudget(8*time.Second) != 8*time.Second {
		t.Fatalf("8s = %s", dialBudget(8*time.Second))
	}
	if dialBudget(2*time.Minute) != defaultDialTimeout {
		t.Fatalf("long timeout should keep the 20s dial cap, got %s", dialBudget(2*time.Minute))
	}
}

// silentAccept accepts TCP and sends nothing, so the SSH handshake blocks
// until the dial deadline. It stays on localhost and does not depend on a
// blackhole route.
func silentAccept(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var held []net.Conn
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			held = append(held, c)
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, c := range held {
			_ = c.Close()
		}
	})
	return ln.Addr().String()
}

func TestExecTimeoutBoundsDial(t *testing.T) {
	ttyCheck = func() bool { return false }
	t.Cleanup(func() { ttyCheck = defaultTTY })

	addr := silentAccept(t)
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	runIn := func(stdin string, args ...string) (int, string, string) {
		t.Helper()
		var out, errb strings.Builder
		code := Execute(append([]string{"--config", dir}, args...), strings.NewReader(stdin), &out, &errb)
		return code, out.String(), errb.String()
	}
	code, _, errb := runIn("", "group", "add", "hunan-test", "--env", "dev", "--policy", "admin", "--label", "湖南组测试主机组")
	if code != 0 {
		t.Fatalf("group add: %d %s", code, errb)
	}
	code, _, errb = runIn("s3cret-dial\n", "host", "add", "box", "--group", "hunan-test", "--host", host, "--port", port, "--user", "tester", "--password-stdin")
	if code != 0 {
		t.Fatalf("host add: %d %s", code, errb)
	}

	const limit = 400 * time.Millisecond
	start := time.Now()
	code, _, errb = runIn("", "exec", "-H", "box", "--timeout", "400ms", "--", "echo", "hi")
	elapsed := time.Since(start)
	if code != 251 {
		t.Fatalf("exec code %d after %s\n%s", code, elapsed, errb)
	}
	if !strings.Contains(errb, "group=hunan-test") || !strings.Contains(errb, "[湖南组测试主机组]") || !strings.Contains(errb, "[开发]") {
		t.Fatalf("banner:\n%s", errb)
	}
	if elapsed < 150*time.Millisecond {
		t.Fatalf("dial returned too fast (%s); timeout was not applied", elapsed)
	}
	// The old dial path waited about 20s. Allow OS skew, but not that.
	if elapsed > 3*time.Second {
		t.Fatalf("dial took %s, want about %s", elapsed, limit)
	}
}
