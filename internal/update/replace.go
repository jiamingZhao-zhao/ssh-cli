package update

import (
	"fmt"
	"os"
	"path/filepath"
)

// ReplaceBinary writes data over dest.
// The new bytes land in a temp file beside dest, dest moves to dest.old,
// then the temp file takes dest's name. A failed second rename puts dest back.
// On Windows, renaming the running executable aside is what makes the replace succeed.
func ReplaceBinary(dest string, data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty binary")
	}
	dir := filepath.Dir(dest)
	tmp, err := os.CreateTemp(dir, ".ssh-cli-new-*")
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
	mode := os.FileMode(0o755)
	if st, err := os.Stat(dest); err == nil {
		if perm := st.Mode().Perm(); perm&0o111 != 0 {
			mode = perm
		}
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
	backup := dest + ".old"
	_ = os.Remove(backup)
	moved := false
	if _, err := os.Stat(dest); err == nil {
		if err := os.Rename(dest, backup); err != nil {
			return fmt.Errorf("move current binary aside: %w", err)
		}
		moved = true
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := os.Rename(tmpName, dest); err != nil {
		if moved {
			_ = os.Rename(backup, dest)
		}
		return fmt.Errorf("install new binary: %w", err)
	}
	cleanup = false
	_ = os.Remove(backup)
	return nil
}
