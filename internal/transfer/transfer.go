package transfer

import (
	"context"
	"crypto/rand"
	"encoding/hex"
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
	return UploadWithOptions(client, local, remote, log, UploadOptions{Check: func(dest string, _ []string) error {
		if check != nil {
			return check(dest)
		}
		return nil
	}})
}

// UploadOptions applies cancellation and resolved path policy to the full plan.
// A non-nil Context owns the connection and closes it when canceled.
type UploadOptions struct {
	Context         context.Context
	Protected       []string
	Check           func(dest string, protected []string) error
	RejectOverwrite bool
}

// OverwriteError means an existing regular file needs an explicit overwrite decision.
type OverwriteError struct{ Path string }

func (e *OverwriteError) Error() string { return "文件已存在，覆盖前请确认：" + e.Path }

func UploadWithOptions(client *ssh.Client, local, remote string, log LogFunc, opt UploadOptions) error {
	ctx := opt.Context
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	// Context-aware uploads own a dedicated SSH connection. Closing it also
	// interrupts a server that never acknowledges SFTP startup or a write.
	stop := context.AfterFunc(ctx, func() { _ = client.Close() })
	defer stop()
	sf, err := Client(client)
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
	expanded := expandProtected(sf, home, opt.Protected)
	checkPath := func(dest string) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := rejectUploadSymlinks(sf, dest); err != nil {
			return err
		}
		if opt.Check != nil {
			return opt.Check(dest, expanded)
		}
		return nil
	}
	for _, item := range plan {
		if err := checkPath(item.remote); err != nil {
			return err
		}
		if !item.dir {
			if st, err := sf.Lstat(item.remote); err == nil {
				if !st.Mode().IsRegular() {
					return fmt.Errorf("refusing to replace non-regular file %s", item.remote)
				}
				if opt.RejectOverwrite {
					return &OverwriteError{Path: item.remote}
				}
			} else if !os.IsNotExist(err) {
				return err
			}
		}
	}
	for _, item := range plan {
		if err := checkPath(item.remote); err != nil {
			return err
		}
		if item.dir {
			if err := sf.MkdirAll(item.remote); err != nil {
				return err
			}
			continue
		}
		if err := uploadFile(sf, item.local, item.remote, item.mode, log, opt.RejectOverwrite, checkPath); err != nil {
			return err
		}
	}
	return nil
}

// Upload never follows existing destination symlinks. This also rejects links
// in parent directories; server-side permissions remain the race boundary.
func rejectUploadSymlinks(sf *sftp.Client, remote string) error {
	var paths []string
	for p := path.Clean(remote); p != "." && p != "/"; p = path.Dir(p) {
		paths = append(paths, p)
		if path.Dir(p) == p {
			break
		}
	}
	for i := len(paths) - 1; i >= 0; i-- {
		info, err := sf.Lstat(paths[i])
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing to upload through remote symlink %s", paths[i])
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
	return download(client, remote, local, log)
}

// DownloadContext is Download with cancellation. Cancelling ctx closes client
// so a stalled SFTP read unblocks. The CLI calls Download.
func DownloadContext(ctx context.Context, client *ssh.Client, remote, local string, log LogFunc) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	stop := context.AfterFunc(ctx, func() { _ = client.Close() })
	defer stop()
	return download(client, remote, local, log)
}

func download(client *ssh.Client, remote, local string, log LogFunc) error {
	sf, err := Client(client)
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

func uploadFile(sf *sftp.Client, local, remote string, mode os.FileMode, log LogFunc, rejectOverwrite bool, check func(string) error) error {
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
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	tmp := path.Join(path.Dir(remote), ".ssh-cli-upload-"+hex.EncodeToString(nonce[:]))
	dst, err := sf.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL)
	if err != nil {
		return fmt.Errorf("create %s: %w", remote, err)
	}
	defer sf.Remove(tmp)
	// Do not stream sensitive bytes into a file with the server's default mode.
	if err := dst.Chmod(0o600); err != nil {
		_ = dst.Close()
		return fmt.Errorf("restrict temporary upload permissions: %w", err)
	}
	_, copyErr := io.Copy(dst, src)
	closeErr := dst.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return closeErr
	}
	if err := sf.Chmod(tmp, mode.Perm()); err != nil {
		note(log, fmt.Sprintf("chmod %s: %v", remote, err))
	}
	if err := check(remote); err != nil {
		return err
	}
	if rejectOverwrite {
		return sf.Rename(tmp, remote)
	}
	if _, ok := sf.HasExtension("posix-rename@openssh.com"); ok {
		return sf.PosixRename(tmp, remote)
	}
	// Standard SFTP rename must fail if the destination exists. Never delete
	// the original as a fallback when atomic replacement is unavailable.
	if err := sf.Rename(tmp, remote); err != nil {
		return fmt.Errorf("safe replacement unavailable; original file preserved: %w", err)
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
