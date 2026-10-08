package config

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// ResolveDir picks the config directory.
// Order: explicit flag, SSH_CLI_HOME, then %APPDATA%\ssh-cli or ~/.config/ssh-cli.
func ResolveDir(flag string) (string, error) {
	if flag != "" {
		return flag, nil
	}
	if v := os.Getenv("SSH_CLI_HOME"); v != "" {
		return v, nil
	}
	if runtime.GOOS == "windows" {
		appdata := os.Getenv("APPDATA")
		if appdata == "" {
			return "", fmt.Errorf("APPDATA is not set")
		}
		return filepath.Join(appdata, "ssh-cli"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "ssh-cli"), nil
}
