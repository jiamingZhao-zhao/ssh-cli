package cli

import (
	"strings"
	"testing"
)

func TestShellCommandPreservesArgv(t *testing.T) {
	cases := []struct {
		args []string
		want string
	}{
		{[]string{"df -h /"}, "df -h /"},
		{[]string{"systemctl", "restart", "nginx"}, "systemctl restart nginx"},
		{[]string{"sh", "-c", "mkdir -p /a /b"}, "sh -c 'mkdir -p /a /b'"},
		{[]string{"curl", "-d", `{"k":"v"}`}, `curl -d '{"k":"v"}'`},
		{[]string{"printf", "%s", `say "hi"`}, `printf %s 'say "hi"'`},
		{[]string{"printf", "%s", "it's"}, "printf %s 'it'\\''s'"},
		{[]string{"echo", ""}, "echo ''"},
	}
	for _, tc := range cases {
		if got := shellCommand(tc.args); got != tc.want {
			t.Errorf("shellCommand(%q) = %q, want %q", tc.args, got, tc.want)
		}
	}
}

func TestMSYSWarningNamesUnixPath(t *testing.T) {
	got := msysWarnings([]string{"cat", `D:/soft/git/Git/etc/nginx`})
	if len(got) != 1 {
		t.Fatalf("warning %q", got)
	}
	for _, part := range []string{"D:/soft/git/Git/etc/nginx", "/etc/nginx", "MSYS_NO_PATHCONV=1", "//etc/nginx"} {
		if !strings.Contains(got[0], part) {
			t.Fatalf("warning %q missing %s", got[0], part)
		}
	}
	if extra := msysWarnings([]string{"/etc/nginx", "//etc/nginx", `C:/Users/dev/file.txt`}); len(extra) != 0 {
		t.Fatalf("unexpected warnings %q", extra)
	}
}
