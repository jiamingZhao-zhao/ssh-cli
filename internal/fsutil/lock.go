package fsutil

import (
	"os"
	"path/filepath"
)

// WithLock exclusively locks dir/.lock for the duration of fn.
// Same-process re-entry deadlocks; callers must not nest WithLock on one directory.
func WithLock(dir string, fn func() error) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(dir, ".lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	unlock, err := flock(f)
	if err != nil {
		return err
	}
	defer unlock()
	return fn()
}
