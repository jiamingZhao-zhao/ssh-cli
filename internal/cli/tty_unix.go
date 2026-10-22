//go:build !windows

package cli

import "os"

func openTTY() (*consoleTTY, error) {
	f, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	return &consoleTTY{in: f, out: f}, nil
}
