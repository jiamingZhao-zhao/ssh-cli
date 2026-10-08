//go:build !windows

package fsutil

import "os"

func replaceFile(tmp, dest string) error {
	return os.Rename(tmp, dest)
}

// harden is a no-op on Unix: Chmod in WriteAtomic already applied mode.
func harden(string) error { return nil }
