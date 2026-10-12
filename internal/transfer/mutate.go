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
	sf, err := Client(client)
	if err != nil {
		return err
	}
	defer sf.Close()
	home, err := sf.RealPath(".")
	if err != nil {
		return fmt.Errorf("remote working directory: %w", err)
	}
	switch strings.TrimSpace(op) {
	case "mkdir", "touch":
		parent, err := resolveListPath(home, remote)
		if err != nil {
			return err
		}
		base, err := EntryName(name)
		if err != nil {
			return err
		}
		dest := path.Join(parent, base)
		if op == "mkdir" {
			if err := sf.Mkdir(dest); err != nil {
				return err
			}
			return nil
		}
		f, err := sf.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_EXCL)
		if err != nil {
			return err
		}
		return f.Close()
	case "rename":
		src, err := resolveListPath(home, remote)
		if err != nil {
			return err
		}
		if src == "/" {
			return fmt.Errorf("不能重命名根目录")
		}
		base, err := EntryName(name)
		if err != nil {
			return err
		}
		dest := path.Join(path.Dir(src), base)
		if dest == src {
			return nil
		}
		return sf.Rename(src, dest)
	case "remove":
		src, err := resolveListPath(home, remote)
		if err != nil {
			return err
		}
		if src == "/" || src == "." {
			return fmt.Errorf("不能删除根目录")
		}
		return removeTree(sf, src, 0)
	default:
		return fmt.Errorf("未知操作")
	}
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
