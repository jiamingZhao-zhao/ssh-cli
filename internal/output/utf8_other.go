//go:build !windows

package output

// EnableUTF8 is a no-op off Windows. Go writes UTF-8 bytes already.
func EnableUTF8() {}
