package transfer

import (
	"fmt"
	"os"
	"path"
	"strings"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// Change creates, renames, or removes one remote path over SFTP.
// op is mkdir, touch, rename, or remove.
// mkdir and touch take the parent directory in remote and the new base name.
// rename takes the existing path in remote and the new base name in the same directory.
// remove takes the existing path in remote.
func Change(client *ssh.Client, op, remote, name string) error {
	_, err := ChangeChecked(client, op, remote, name, nil, nil)
	return err
}

// ChangeChecked resolves absolute paths, optional symlink targets, and ~/
// against the remote home, then calls check before any mutation.
// protected is expanded the same way so a symlink path and its target compare
// equally. check nil skips the policy hook. The returned path is the primary
// path that would be created, renamed to, or removed.
func ChangeChecked(client *ssh.Client, op, remote, name string, protected []string, check func(targets, protected []string) error) (string, error) {
	sf, err := Client(client)
	if err != nil {
		return "", err
	}
	defer sf.Close()
	home, err := sf.RealPath(".")
	if err != nil {
		return "", fmt.Errorf("remote working directory: %w", err)
	}
	home = path.Clean(strings.ReplaceAll(home, "\\", "/"))
	src, dest, err := PlanPaths(home, op, remote, name)
	if err != nil {
		return "", err
	}
	primary := dest
	if op == "remove" || dest == "" {
		primary = src
	}
	targets := affectedPaths(sf, strings.TrimSpace(op), src, dest)
	expanded := expandProtected(sf, home, protected)
	if check != nil {
		if err := check(targets, expanded); err != nil {
			return primary, err
		}
	}
	if err := applyChange(sf, strings.TrimSpace(op), src, dest); err != nil {
		return primary, err
	}
	return primary, nil
}

// PlanPaths resolves one file change against home without opening a connection.
// Relative paths and ~/ are joined onto home. The returned paths are absolute
// when home is absolute.
func PlanPaths(home, op, remote, name string) (src, dest string, err error) {
	home = path.Clean(strings.ReplaceAll(strings.TrimSpace(home), "\\", "/"))
	switch strings.TrimSpace(op) {
	case "mkdir", "touch":
		parent, err := resolveListPath(home, remote)
		if err != nil {
			return "", "", err
		}
		base, err := EntryName(name)
		if err != nil {
			return "", "", err
		}
		return "", path.Join(parent, base), nil
	case "rename":
		src, err = resolveListPath(home, remote)
		if err != nil {
			return "", "", err
		}
		if src == "/" {
			return "", "", fmt.Errorf("不能重命名根目录")
		}
		base, err := EntryName(name)
		if err != nil {
			return "", "", err
		}
		dest = path.Join(path.Dir(src), base)
		return src, dest, nil
	case "remove":
		src, err = resolveListPath(home, remote)
		if err != nil {
			return "", "", err
		}
		if src == "/" || src == "." {
			return "", "", fmt.Errorf("不能删除根目录")
		}
		return src, "", nil
	default:
		return "", "", fmt.Errorf("未知操作")
	}
}

func applyChange(sf *sftp.Client, op, src, dest string) error {
	switch op {
	case "mkdir":
		return sf.Mkdir(dest)
	case "touch":
		f, err := sf.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_EXCL)
		if err != nil {
			return err
		}
		return f.Close()
	case "rename":
		if dest == src {
			return nil
		}
		return sf.Rename(src, dest)
	case "remove":
		return removeTree(sf, src, 0)
	default:
		return fmt.Errorf("未知操作")
	}
}

func affectedPaths(sf *sftp.Client, op, src, dest string) []string {
	var seeds []string
	switch op {
	case "mkdir", "touch":
		seeds = []string{dest}
	case "rename":
		seeds = []string{src, dest}
	case "remove":
		seeds = []string{src}
	}
	var out []string
	add := func(p string) {
		p = path.Clean(strings.ReplaceAll(p, "\\", "/"))
		if p == "" || p == "." {
			return
		}
		for _, item := range out {
			if item == p {
				return
			}
		}
		out = append(out, p)
	}
	for _, p := range seeds {
		add(p)
		if resolved, err := followRemote(sf, p); err == nil {
			add(resolved)
		}
	}
	return out
}

func expandProtected(sf *sftp.Client, home string, configured []string) []string {
	if configured == nil {
		return nil
	}
	var out []string
	add := func(p string) {
		p = path.Clean(strings.ReplaceAll(p, "\\", "/"))
		if p == "" || p == "." {
			return
		}
		for _, item := range out {
			if item == p {
				return
			}
		}
		out = append(out, p)
	}
	for _, raw := range configured {
		abs, err := NormalizeRemotePath(home, raw)
		if err != nil {
			add(raw)
			continue
		}
		add(abs)
		if resolved, err := followRemote(sf, abs); err == nil {
			add(resolved)
		}
	}
	return out
}

// followRemote resolves directory and final-component symlinks over SFTP.
// A missing tail is kept lexically so a path that does not exist yet still
// has a stable absolute form. Loops return an error.
func followRemote(sf *sftp.Client, abs string) (string, error) {
	abs = path.Clean(strings.ReplaceAll(abs, "\\", "/"))
	if !strings.HasPrefix(abs, "/") {
		return "", fmt.Errorf("path is not absolute")
	}
	return followRemoteFrom(sf, abs, map[string]int{})
}

func followRemoteFrom(sf *sftp.Client, abs string, seen map[string]int) (string, error) {
	abs = path.Clean(abs)
	if seen[abs] > 0 || len(seen) > 32 {
		return "", fmt.Errorf("symlink loop")
	}
	seen[abs]++
	if abs == "/" {
		return "/", nil
	}
	cur := "/"
	parts := strings.Split(strings.Trim(abs, "/"), "/")
	for i, part := range parts {
		if part == "" || part == "." || part == ".." {
			continue
		}
		next := path.Join(cur, part)
		info, err := sf.Lstat(next)
		if err != nil {
			rest := append([]string{cur}, parts[i:]...)
			return path.Clean(path.Join(rest...)), nil
		}
		if info.Mode()&os.ModeSymlink != 0 {
			target, err := sf.ReadLink(next)
			if err != nil {
				return "", err
			}
			target = path.Clean(strings.ReplaceAll(target, "\\", "/"))
			if !strings.HasPrefix(target, "/") {
				target = path.Clean(path.Join(cur, target))
			}
			if i+1 < len(parts) {
				target = path.Join(target, path.Join(parts[i+1:]...))
			}
			return followRemoteFrom(sf, target, seen)
		}
		cur = next
	}
	return path.Clean(cur), nil
}

func removeTree(sf *sftp.Client, remote string, depth int) error {
	if depth > 64 {
		return fmt.Errorf("目录层级过深")
	}
	info, err := sf.Lstat(remote)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return sf.Remove(remote)
	}
	entries, err := sf.ReadDir(remote)
	if err != nil {
		return err
	}
	for _, item := range entries {
		n := item.Name()
		if n == "" || n == "." || n == ".." || strings.ContainsAny(n, "/\\") {
			continue
		}
		if err := removeTree(sf, path.Join(remote, n), depth+1); err != nil {
			return err
		}
	}
	return sf.RemoveDirectory(remote)
}
