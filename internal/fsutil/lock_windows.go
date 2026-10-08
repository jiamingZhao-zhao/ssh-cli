//go:build windows

package fsutil

import (
	"os"

	"golang.org/x/sys/windows"
)

func flock(f *os.File) (func() error, error) {
	// The overlapped value must stay alive until unlock.
	ol := new(windows.Overlapped)
	handle := windows.Handle(f.Fd())
	err := windows.LockFileEx(handle, windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, ol)
	if err != nil {
		return nil, err
	}
	return func() error {
		return windows.UnlockFileEx(handle, 0, 1, 0, ol)
	}, nil
}
