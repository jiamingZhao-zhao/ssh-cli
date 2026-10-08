// Package transfer copies files over SFTP.
package transfer

import "strings"

// RestoreRemotePath undoes the Git Bash / MSYS leading-slash escape.
// A remote path typed as //root/app reaches the program as //root/app and
// must be restored to /root/app. Three or more leading slashes are left alone.
func RestoreRemotePath(p string) string {
	if strings.HasPrefix(p, "//") && !strings.HasPrefix(p, "///") {
		return p[1:]
	}
	return p
}
