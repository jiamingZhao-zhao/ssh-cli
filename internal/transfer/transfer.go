package transfer

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// LogFunc receives non-fatal transfer notes (skipped symlinks, chmod failures).
type LogFunc func(string)

// Upload copies a local file or directory to remote. Directories are recursive
// and missing remote parents are created.
func Upload(client *ssh.Client, local, remote string, log LogFunc) error {
	sf, err := sftp.NewClient(client)
	if err != nil {
		return err
	}
	defer sf.Close()
	remote = RestoreRemotePath(remote)
	info, err := os.Stat(local)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to upload symlink %s", local)
	}
	if info.IsDir() {
		return uploadDir(sf, local, remote, log)
	}
	remote, err = remoteFileDest(sf, remote, filepath.Base(local))
	if err != nil {
		return err
	}
	return uploadFile(sf, local, remote, info.Mode(), log)
}

// Download copies a remote file or directory to local.
func Download(client *ssh.Client, remote, local string, log LogFunc) error {
	sf, err := sftp.NewClient(client)
	if err != nil {
		return err
	}
	defer sf.Close()
	remote = RestoreRemotePath(remote)
	info, err := sf.Stat(remote)
	if err != nil {
		return err
	}
	if info.IsDir() {
		return downloadDir(sf, remote, local, log)
	}
	if st, err := os.Stat(local); err == nil && st.IsDir() {
		local = filepath.Join(local, path.Base(remote))
	}
	return downloadFile(sf, remote, local, info.Mode(), log)
}

func uploadDir(sf *sftp.Client, local, remote string, log LogFunc) error {
	if err := sf.MkdirAll(remote); err != nil {
		return err
	}
	return filepath.WalkDir(local, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type()&os.ModeSymlink != 0 {
			note(log, "skipping symlink "+p)
			return nil
		}
		rel, err := filepath.Rel(local, p)
		if err != nil {
			return err
		}
		remotePath := path.Join(remote, filepath.ToSlash(rel))
		info, err := d.Info()
		if err != nil {
			return err
		}
		if d.IsDir() {
			return sf.MkdirAll(remotePath)
		}
		if !info.Mode().IsRegular() {
			note(log, "skipping non-regular file "+p)
			return nil
		}
		return uploadFile(sf, p, remotePath, info.Mode(), log)
	})
}

func uploadFile(sf *sftp.Client, local, remote string, mode os.FileMode, log LogFunc) error {
	if dir := path.Dir(remote); dir != "" && dir != "." {
		if err := sf.MkdirAll(dir); err != nil {
			return fmt.Errorf("mkdir %s: %w", dir, err)
		}
	}
	src, err := os.Open(local)
	if err != nil {
		return err
	}
	defer src.Close()
	dst, err := sf.Create(remote)
	if err != nil {
		return fmt.Errorf("create %s: %w", remote, err)
	}
	_, copyErr := io.Copy(dst, src)
	closeErr := dst.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return closeErr
	}
	if err := sf.Chmod(remote, mode.Perm()); err != nil {
		note(log, fmt.Sprintf("chmod %s: %v", remote, err))
	}
	return nil
}

func downloadDir(sf *sftp.Client, remote, local string, log LogFunc) error {
	walker := sf.Walk(remote)
	for walker.Step() {
		if err := walker.Err(); err != nil {
			return err
		}
		rel := strings.TrimPrefix(walker.Path(), remote)
		rel = strings.TrimPrefix(rel, "/")
		localPath := local
		if rel != "" {
			localPath = filepath.Join(local, filepath.FromSlash(rel))
		}
		info := walker.Stat()
		if info.Mode()&os.ModeSymlink != 0 {
			note(log, "skipping symlink "+walker.Path())
			continue
		}
		if info.IsDir() {
			if err := os.MkdirAll(localPath, 0o755); err != nil {
				return err
			}
			continue
		}
		if !info.Mode().IsRegular() {
			note(log, "skipping non-regular file "+walker.Path())
			continue
		}
		if err := downloadFile(sf, walker.Path(), localPath, info.Mode(), log); err != nil {
			return err
		}
	}
	return nil
}

func downloadFile(sf *sftp.Client, remote, local string, mode os.FileMode, log LogFunc) error {
	if err := os.MkdirAll(filepath.Dir(local), 0o755); err != nil {
		return err
	}
	src, err := sf.Open(remote)
	if err != nil {
		return err
	}
	defer src.Close()
	dst, err := os.OpenFile(local, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode.Perm())
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(dst, src)
	closeErr := dst.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return closeErr
	}
	if err := os.Chmod(local, mode.Perm()); err != nil {
		note(log, fmt.Sprintf("chmod %s: %v", local, err))
	}
	return nil
}

func remoteFileDest(sf *sftp.Client, remote, base string) (string, error) {
	if strings.HasSuffix(remote, "/") {
		return path.Join(remote, base), nil
	}
	st, err := sf.Stat(remote)
	if err == nil && st.IsDir() {
		return path.Join(remote, base), nil
	}
	return remote, nil
}

func note(log LogFunc, msg string) {
	if log != nil {
		log(msg)
	}
}
