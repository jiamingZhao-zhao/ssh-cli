//go:build !windows

package cli

func devTTY() string { return "/dev/tty" }
