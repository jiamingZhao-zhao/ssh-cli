//go:build windows

package cli

import (
	"os/exec"
	"syscall"
)

func detachDaemon(c *exec.Cmd) {
	c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x00000200}
}
