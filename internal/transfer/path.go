// Package transfer copies files over SFTP.
package transfer

import (
	"fmt"
	"path"
	"strings"
)

// MSYSRewrittenPath reports a Unix path that Git Bash / MSYS likely rewrote
// into a Windows path before this process saw the argument. guess is the
// Unix path. Callers warn and leave the argument unchanged.
//
// Conversion inserts the MSYS install prefix, so /etc/nginx arrives as
// something like D:/soft/git/Git/etc/nginx. The signal is a drive letter, a
// Git/MSYS prefix component, then a well-known Unix directory. C:/etc and
// C:/Users/dev/file.txt are not flagged.
func MSYSRewrittenPath(p string) (guess string, ok bool) {
	p = strings.TrimSpace(strings.ReplaceAll(p, "\\", "/"))
	if len(p) < 4 || p[1] != ':' || (p[2] != '/') {
		return "", false
	}
	if !isDriveLetter(p[0]) {
		return "", false
	}
	parts := strings.Split(strings.Trim(p[3:], "/"), "/")
	if len(parts) < 2 {
		return "", false
	}
	// Git Bash inserts its install prefix (Git, msys64, …) before the Unix
	// path. A later "dev" or "tmp" without that prefix is an ordinary
	// Windows directory, not /dev or /tmp.
	marked := false
	for i := 1; i < len(parts); i++ {
		if !marked {
			if msysPrefix(parts[i-1]) {
				marked = true
			} else {
				continue
			}
		}
		if msysUnixRoot[parts[i]] {
			return "/" + strings.Join(parts[i:], "/"), true
		}
	}
	return "", false
}

func msysPrefix(part string) bool {
	switch strings.ToLower(part) {
	case "git", "msys", "msys64", "msys32", "mingw64", "mingw32", "cygwin":
		return true
	default:
		return false
	}
}

func isDriveLetter(r byte) bool {
	return (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z')
}

var msysUnixRoot = map[string]bool{
	"etc": true, "var": true, "usr": true, "opt": true, "root": true,
	"home": true, "bin": true, "sbin": true, "lib": true, "lib64": true,
	"tmp": true, "srv": true, "proc": true, "sys": true, "dev": true,
	"run": true, "boot": true, "mnt": true,
}

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
