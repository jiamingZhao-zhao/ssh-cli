//go:build windows

package output

import "golang.org/x/sys/windows"

// EnableUTF8 switches the Windows console to UTF-8 so CJK output is not
// decoded as the legacy GBK code page (the failure mode of the old Python tool).
func EnableUTF8() {
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	setOut := kernel32.NewProc("SetConsoleOutputCP")
	setIn := kernel32.NewProc("SetConsoleCP")
	const cpUTF8 = 65001
	_, _, _ = setOut.Call(uintptr(cpUTF8))
	_, _, _ = setIn.Call(uintptr(cpUTF8))
}
