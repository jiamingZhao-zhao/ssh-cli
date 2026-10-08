//go:build !windows

package fsutil

import "os"

func replaceFile(tmp, dest string) error {
	return os.Rename(tmp, dest)
}

func harden(string) error { return nil }
