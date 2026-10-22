//go:build windows

package cli

import "os"

func openTTY() (*consoleTTY, error) {
	in, err := os.OpenFile("CONIN$", os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	out, err := os.OpenFile("CONOUT$", os.O_RDWR, 0)
	if err != nil {
		in.Close()
		return nil, err
	}
	return &consoleTTY{in: in, out: out}, nil
}
