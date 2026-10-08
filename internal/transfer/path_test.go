package transfer

import "testing"

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
