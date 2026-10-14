package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestAgentKeyCLI(t *testing.T) {
	dir := t.TempDir()
	pin := "SHA256:" + strings.Repeat("A", 43)
	run := func(args ...string) (int, string) {
		t.Helper()
		var out, errb bytes.Buffer
		code := Execute(append([]string{"--config", dir}, args...), strings.NewReader(""), &out, &errb)
		return code, out.String() + errb.String()
	}
	if code, out := run("group", "add", "app", "--env", "test"); code != 0 {
		t.Fatal(out)
	}
	if code, _ := run("host", "add", "bad", "--group", "app", "--host", "example", "--user", "u", "--agent-key", pin); code == 0 {
		t.Fatal("selector without agent accepted")
	}
	if code, out := run("host", "add", "a", "--group", "app", "--host", "example", "--user", "u", "--agent", "--agent-key", pin); code != 0 {
		t.Fatal(out)
	}
	if code, out := run("--json", "host", "list"); code != 0 || !strings.Contains(out, pin) {
		t.Fatal(out)
	}
	if code, out := run("host", "edit", "a", "--agent-key", ""); code != 0 {
		t.Fatal(out)
	}
	if code, out := run("--json", "host", "list"); code != 0 || strings.Contains(out, pin) {
		t.Fatal(out)
	}
}
