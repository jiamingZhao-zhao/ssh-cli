package cli

import (
	"bytes"
	"context"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/config"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func TestOutputLimitUTF8(t *testing.T) {
	for _, limit := range []int{1, 2, 3, 4, 5, 6, 7} {
		var b bytes.Buffer
		w := &outputLimiter{dst: &b, maxLine: limit}
		for _, c := range []byte("中文abc\n下一行") {
			w.Write([]byte{c})
		}
		if !utf8.Valid(b.Bytes()) {
			t.Fatalf("limit %d: %q", limit, b.Bytes())
		}
	}
}

func TestOutputLimitsDrainAndReset(t *testing.T) {
	var b bytes.Buffer
	w := &outputLimiter{dst: &b, maxLine: 3, maxTotal: 8}
	for _, p := range []string{"abcde", "f\nx", "yz123\nmore"} {
		if n, e := w.Write([]byte(p)); e != nil || n != len(p) {
			t.Fatalf("drain %d %v", n, e)
		}
	}
	if !w.cut || b.String() != "abc\nxyz\n" {
		t.Fatalf("%q cut=%v", b.String(), w.cut)
	}
}
func TestDaemonIdleExitCleansSocket(t *testing.T) {
	dir := t.TempDir()
	if e := config.Save(dir, &config.Config{Version: 1}); e != nil {
		t.Fatal(e)
	}
	a := &App{Dir: dir, Err: &bytes.Buffer{}}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if e := a.serveDaemonWithIdle(ctx, 50*time.Millisecond); e != nil {
		t.Fatal(e)
	}
	if ctx.Err() != nil {
		t.Fatal("did not idle exit")
	}
	for _, name := range []string{"reuse.sock", "reuse.token"} {
		if _, e := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(e) {
			t.Fatalf("not removed: %s", name)
		}
	}
}
func TestInventoryMetadataAndDenialJSON(t *testing.T) {
	dir := t.TempDir()
	if e := config.Save(dir, &config.Config{Version: 1}); e != nil {
		t.Fatal(e)
	}
	run := func(args ...string) (int, string) {
		var b, e bytes.Buffer
		code := Execute(append([]string{"--config", dir}, args...), strings.NewReader(""), &b, &e)
		return code, b.String() + e.String()
	}
	for _, args := range [][]string{{"group", "add", "g", "--env", "prod"}, {"host", "add", "a", "--group", "g", "--host", "192.0.2.1", "--user", "u", "--identity", "dummy"}, {"host", "metadata", "a", "--lan-ip", "192.168.0.42", "--role", "nginx", "--entrypoint", "zibo-test"}} {
		if c, s := run(args...); c != 0 {
			t.Fatalf("%v: %d %s", args, c, s)
		}
	}
	if c, s := run("host", "list", "--json"); c != 0 || !strings.Contains(s, "192.168.0.42") || !strings.Contains(s, "zibo-test") {
		t.Fatal(c, s)
	}
	if c, s := run("exec", "-H", "a", "--json", "--", "ps -ef; touch /tmp/no"); c != 253 || !strings.Contains(s, `"command":"touch /tmp/no"`) {
		t.Fatal(c, s)
	}
	if c, _ := run("host", "metadata", "a", "--lan-ip", "invalid"); c == 0 {
		t.Fatal("invalid IP accepted")
	}
}
