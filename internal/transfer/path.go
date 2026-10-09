// Package transfer copies files over SFTP.
package transfer

import (
	"fmt"
	"path"
	"strings"
)

// RestoreRemotePath undoes the Git Bash / MSYS leading-slash escape.
// A remote path typed as //root/app reaches the program as //root/app and
// must be restored to /root/app. Three or more leading slashes are left alone.
func RestoreRemotePath(p string) string {
	if strings.HasPrefix(p, "//") && !strings.HasPrefix(p, "///") {
		return p[1:]
	}
	return p
}

// AbsRemote joins a relative SFTP destination onto the remote working directory.
// Absolute destinations are cleaned in place. Callers pass home from RealPath(".")
// so a relative upload is checked against absolute protectedPaths.
func AbsRemote(home, remote string) (string, error) {
	remote = path.Clean(RestoreRemotePath(slash(remote)))
	if remoteAbs(remote) {
		return remote, nil
	}
	home = path.Clean(slash(strings.TrimSpace(home)))
	if !remoteAbs(home) {
		return "", fmt.Errorf("remote working directory %q is not absolute", home)
	}
	return path.Clean(path.Join(home, remote)), nil
}

func slash(p string) string {
	return strings.ReplaceAll(p, "\\", "/")
}

func remoteAbs(p string) bool {
	if strings.HasPrefix(p, "/") {
		return true
	}
	return len(p) >= 3 && p[1] == ':' && ((p[0] >= 'A' && p[0] <= 'Z') || (p[0] >= 'a' && p[0] <= 'z'))
}
