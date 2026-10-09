package transfer

import "testing"

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
