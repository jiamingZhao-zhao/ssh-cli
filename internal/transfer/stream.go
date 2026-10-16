package transfer

import (
	"context"
	"fmt"
	"io"
	"os"
	"path"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// UploadReaderWithOptions uploads a single already-staged browser file without
// making a second local copy. name is a basename, remote follows upload semantics.
func UploadReaderWithOptions(client *ssh.Client, src io.Reader, name string, size int64, remote string, opt UploadOptions) error {
	if name == "" || name == "." || name == ".." || path.Base(name) != name {
		return fmt.Errorf("invalid upload filename")
	}
	ctx := opt.Context
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	stop := context.AfterFunc(ctx, func() { _ = client.Close() })
	defer stop()
	sf, err := Client(client)
	if err != nil {
		return err
	}
	defer sf.Close()
	dest, check, err := streamDestination(sf, remote, name, opt)
	if err != nil {
		return err
	}
	prog := &byteProgress{fn: opt.Progress, total: size}
	prog.report(true)
	err = uploadReader(sf, src, dest, 0o600, nil, opt.RejectOverwrite, check, prog, nil, nil)
	prog.report(true)
	return err
}

func streamDestination(sf *sftp.Client, remote, name string, opt UploadOptions) (string, func(string) error, error) {
	home, err := sf.RealPath(".")
	if err != nil {
		return "", nil, err
	}
	dest, err := AbsRemote(home, remote)
	if err != nil {
		return "", nil, err
	}
	if st, e := sf.Stat(dest); e == nil && st.IsDir() {
		if name == "" {
			return "", nil, fmt.Errorf("relay destination must be a file")
		}
		dest = path.Join(dest, name)
	}
	protected := expandProtected(sf, home, opt.Protected)
	check := func(p string) error {
		if opt.Context != nil {
			if err := opt.Context.Err(); err != nil {
				return err
			}
		}
		if err := rejectUploadSymlinks(sf, p); err != nil {
			return err
		}
		if opt.Check != nil {
			return opt.Check(p, protected)
		}
		return nil
	}
	// Include missing parents before creating any directory.
	for _, item := range missingParents(sf, dest) {
		if err := check(item.remote); err != nil {
			return "", nil, err
		}
	}
	if err := check(dest); err != nil {
		return "", nil, err
	}
	if st, e := sf.Lstat(dest); e == nil {
		if !st.Mode().IsRegular() {
			return "", nil, fmt.Errorf("refusing to replace non-regular file %s", dest)
		}
		if opt.RejectOverwrite {
			return "", nil, &OverwriteError{Path: dest}
		}
	} else if !os.IsNotExist(e) {
		return "", nil, e
	}
	return dest, check, nil
}
