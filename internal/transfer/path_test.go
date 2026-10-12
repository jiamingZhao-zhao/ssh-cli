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

func TestPlanPathsHomeRelativeAndTilde(t *testing.T) {
	src, dest, err := PlanPaths("/home/user", "rename", "~/secret.txt", "moved.txt")
	if err != nil || src != "/home/user/secret.txt" || dest != "/home/user/moved.txt" {
		t.Fatalf("tilde rename src=%q dest=%q err=%v", src, dest, err)
	}
	src, dest, err = PlanPaths("/home/user", "remove", "subdir/child", "")
	if err != nil || src != "/home/user/subdir/child" || dest != "" {
		t.Fatalf("relative remove src=%q dest=%q err=%v", src, dest, err)
	}
	src, dest, err = PlanPaths("/home/user", "touch", "/tmp", "note.txt")
	if err != nil || src != "" || dest != "/tmp/note.txt" {
		t.Fatalf("absolute touch src=%q dest=%q err=%v", src, dest, err)
	}
	if _, _, err := PlanPaths("/home/user", "remove", "/", ""); err == nil {
		t.Fatal("root delete planned")
	}
	if _, _, err := PlanPaths("/home/user", "rename", "/tmp/a", "../b"); err == nil {
		t.Fatal("dotdot name planned")
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
