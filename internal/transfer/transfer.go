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

// CheckFunc is invoked with every remote path that would be created or written.
// UploadChecked calls it for the full plan before any write.
type CheckFunc func(remotePath string) error

// Upload copies a local file or directory to remote. Directories are recursive
// and missing remote parents are created.
func Upload(client *ssh.Client, local, remote string, log LogFunc) error {
	return UploadChecked(client, local, remote, log, nil)
}

// UploadChecked plans every destination, runs check on each path, then writes.
// A check error leaves the remote tree unchanged by this call.
func UploadChecked(client *ssh.Client, local, remote string, log LogFunc, check CheckFunc) error {
	sf, err := sftp.NewClient(client)
	if err != nil {
		return err
	}
	defer sf.Close()
	home, err := sf.RealPath(".")
	if err != nil {
		return fmt.Errorf("remote working directory: %w", err)
	}
	remote, err = AbsRemote(home, remote)
	if err != nil {
		return err
	}
	info, err := os.Lstat(local)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to upload symlink %s", local)
	}
	plan, err := planUpload(sf, local, remote, info, log)
	if err != nil {
		return err
	}
	if check != nil {
		for _, item := range plan {
			if err := check(item.remote); err != nil {
				return err
			}
		}
	}
	for _, item := range plan {
		if item.dir {
			if err := sf.MkdirAll(item.remote); err != nil {
				return err
			}
			continue
		}
		if err := uploadFile(sf, item.local, item.remote, item.mode, log); err != nil {
			return err
		}
	}
	return nil
}

type plannedUpload struct {
	local  string
	remote string
	dir    bool
	mode   os.FileMode
}

func planUpload(sf *sftp.Client, local, remote string, info os.FileInfo, log LogFunc) ([]plannedUpload, error) {
	if !info.IsDir() {
		dest, err := remoteFileDest(sf, remote, filepath.Base(local))
		if err != nil {
			return nil, err
		}
		items := missingParents(sf, dest)
		items = append(items, plannedUpload{local: local, remote: dest, mode: info.Mode()})
		return items, nil
	}
	items := []plannedUpload{{remote: remote, dir: true}}
	err := filepath.WalkDir(local, func(p string, d fs.DirEntry, err error) error {
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
		if rel == "." {
			return nil
		}
		remotePath := path.Join(remote, filepath.ToSlash(rel))
		st, err := d.Info()
		if err != nil {
			return err
		}
		if d.IsDir() {
			items = append(items, plannedUpload{remote: remotePath, dir: true})
			return nil
		}
		if !st.Mode().IsRegular() {
			note(log, "skipping non-regular file "+p)
			return nil
		}
		items = append(items, plannedUpload{local: p, remote: remotePath, mode: st.Mode()})
		return nil
	})
	return items, err
}

func missingParents(sf *sftp.Client, remote string) []plannedUpload {
	dir := path.Dir(remote)
	if dir == "" || dir == "." || dir == "/" {
		return nil
	}
	if _, err := sf.Stat(dir); err == nil {
		return nil
	}
	var chain []string
	for dir != "" && dir != "." && dir != "/" {
		if _, err := sf.Stat(dir); err == nil {
			break
		}
		chain = append(chain, dir)
		next := path.Dir(dir)
		if next == dir {
			break
		}
		dir = next
	}
	items := make([]plannedUpload, 0, len(chain))
	for i := len(chain) - 1; i >= 0; i-- {
		items = append(items, plannedUpload{remote: chain[i], dir: true})
	}
	return items
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
