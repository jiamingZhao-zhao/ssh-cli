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

// NormalizeRemotePath turns a typed path into a clean absolute remote path.
// Empty input is refused. Extra slashes collapse, so ///root is /root.
// A relative path is joined onto base when base is absolute.
func NormalizeRemotePath(base, raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("请输入要打开的路径")
	}
	if strings.ContainsRune(raw, 0) || strings.ContainsAny(raw, "\r\n") {
		return "", fmt.Errorf("路径无效")
	}
	raw = RestoreRemotePath(slash(raw))
	base = path.Clean(slash(strings.TrimSpace(base)))
	switch {
	case raw == "~":
		if !remoteAbs(base) {
			return "", fmt.Errorf("请输入绝对路径，例如 /root")
		}
		return base, nil
	case strings.HasPrefix(raw, "~/"):
		if !remoteAbs(base) {
			return "", fmt.Errorf("请输入绝对路径，例如 /root")
		}
		raw = path.Join(base, raw[2:])
	case !remoteAbs(raw):
		if !remoteAbs(base) {
			return "", fmt.Errorf("请输入绝对路径，例如 /root")
		}
		raw = path.Join(base, raw)
	}
	cleaned := path.Clean(raw)
	if !remoteAbs(cleaned) {
		return "", fmt.Errorf("路径无效")
	}
	return cleaned, nil
}

// EntryName checks a single file or directory name. It rejects slashes and dot segments.
func EntryName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\\\x00\r\n") {
		return "", fmt.Errorf("名称无效")
	}
	if len(name) > 255 {
		return "", fmt.Errorf("名称过长")
	}
	return name, nil
}
