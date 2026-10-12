package transfer

import (
	"strings"
	"testing"
)

func TestAbsRemoteJoinsHome(t *testing.T) {
	got, err := AbsRemote("/home/user", "../../root/app")
	if err != nil || got != "/root/app" {
		t.Fatalf("got %q %v", got, err)
	}
	got, err = AbsRemote("/home/user", "app/file")
	if err != nil || got != "/home/user/app/file" {
		t.Fatalf("relative %q %v", got, err)
	}
	got, err = AbsRemote("/home/user", "/root/app")
	if err != nil || got != "/root/app" {
		t.Fatalf("absolute %q %v", got, err)
	}
}

func TestAbsRemoteCollapsesTripleSlash(t *testing.T) {
	got, err := AbsRemote("/home/user", "///root")
	if err != nil || got != "/root" {
		t.Fatalf("triple %q %v", got, err)
	}
}

func TestNormalizeRemotePath(t *testing.T) {
	got, err := NormalizeRemotePath("", "///root")
	if err != nil || got != "/root" {
		t.Fatalf("collapse %q %v", got, err)
	}
	got, err = NormalizeRemotePath("/root", "app/file")
	if err != nil || got != "/root/app/file" {
		t.Fatalf("relative %q %v", got, err)
	}
	got, err = NormalizeRemotePath("/root/app", "../etc")
	if err != nil || got != "/root/etc" {
		t.Fatalf("parent %q %v", got, err)
	}
	if _, err := NormalizeRemotePath("/root", "  "); err == nil || !strings.Contains(err.Error(), "请输入要打开的路径") {
		t.Fatalf("empty %v", err)
	}
}

func TestRestoreRemotePath(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"//root/app", "/root/app"},
		{"//root", "/root"},
		{"//root/foo/bar", "/root/foo/bar"},
		{"/root/app", "/root/app"},
		{"root/app", "root/app"},
		{"///root/app", "///root/app"},
		{"", ""},
	}
	for _, tc := range cases {
		if got := RestoreRemotePath(tc.in); got != tc.want {
			t.Errorf("RestoreRemotePath(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
