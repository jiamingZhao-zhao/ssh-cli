package cli

import (
	"errors"
	"os"
)

// consoleTTY keeps input and output separate: Windows has no read/write CON
// device. Unix uses the same /dev/tty file for both directions.
type consoleTTY struct {
	in, out *os.File
}

func (c *consoleTTY) Read(p []byte) (int, error)  { return c.in.Read(p) }
func (c *consoleTTY) Write(p []byte) (int, error) { return c.out.Write(p) }
func (c *consoleTTY) Fd() uintptr                 { return c.in.Fd() }
func (c *consoleTTY) Close() error {
	err := c.in.Close()
	if c.out != c.in {
		err = errors.Join(err, c.out.Close())
	}
	return err
}
