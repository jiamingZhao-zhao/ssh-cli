// Package fsutil holds private-file helpers shared by config and secrets.
package fsutil

import (
	"fmt"
	"os"
	"path/filepath"
)

// WriteAtomic replaces path with data via a same-directory temp file and rename.
// mode is applied before the rename (0600 for config and secrets). On Windows,
// harden also installs a protected DACL granting only the current user full access.
func WriteAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := harden(tmpName); err != nil {
		return err
	}
	if err := Replace(tmpName, path); err != nil {
		return fmt.Errorf("replace %s: %w", path, err)
	}
	cleanup = false
	return nil
}

// Replace hardens tmp and renames it onto dest. Callers that stream into a
// same-directory temp file use this so Windows still gets the protected DACL.
func Replace(tmp, dest string) error {
	if err := harden(tmp); err != nil {
		return err
	}
	return replaceFile(tmp, dest)
}

// MkdirPrivate creates dir with mode 0700.
func MkdirPrivate(dir string) error {
	return os.MkdirAll(dir, 0o700)
}
