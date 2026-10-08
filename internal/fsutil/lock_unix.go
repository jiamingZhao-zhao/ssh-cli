//go:build unix

package fsutil

import (
	"os"

	"golang.org/x/sys/unix"
)

func flock(f *os.File) (func() error, error) {
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX); err != nil {
		return nil, err
	}
	return func() error {
		return unix.Flock(int(f.Fd()), unix.LOCK_UN)
	}, nil
}
