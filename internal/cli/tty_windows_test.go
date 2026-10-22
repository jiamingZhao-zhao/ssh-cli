//go:build windows

package cli

import (
	"bytes"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// A real ConPTY catches invalid CON opens that mocked ttyCheck tests miss.
// It creates no visible window and never connects to an SSH host.
func TestWindowsConsoleInteractive(t *testing.T) {
	t.Setenv("SSH_CLI_TEST_CONSOLE", "interactive")
	inR, inW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer inR.Close()
	defer inW.Close()
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer outR.Close()
	defer outW.Close()
	var pc windows.Handle
	if err := windows.CreatePseudoConsole(windows.Coord{X: 180, Y: 40}, windows.Handle(inR.Fd()), windows.Handle(outW.Fd()), 0, &pc); err != nil {
		t.Fatal(err)
	}
	attrs, err := windows.NewProcThreadAttributeList(1)
	if err != nil {
		windows.ClosePseudoConsole(pc)
		t.Fatal(err)
	}
	defer attrs.Delete()
	// This attribute takes the HPCON value itself, not a pointer to its storage.
	update := windows.NewLazySystemDLL("kernel32.dll").NewProc("UpdateProcThreadAttribute")
	if ok, _, err := update.Call(uintptr(unsafe.Pointer(attrs.List())), 0, windows.PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, uintptr(pc), unsafe.Sizeof(pc), 0, 0); ok == 0 {
		windows.ClosePseudoConsole(pc)
		t.Fatal(err)
	}
	si := windows.StartupInfoEx{
		StartupInfo:             windows.StartupInfo{Cb: uint32(unsafe.Sizeof(windows.StartupInfoEx{}))},
		ProcThreadAttributeList: attrs.List(),
	}
	line, err := windows.UTF16PtrFromString(windows.ComposeCommandLine([]string{os.Args[0], "-test.run=^TestWindowsConsoleHelper$", "-test.v"}))
	if err != nil {
		windows.ClosePseudoConsole(pc)
		t.Fatal(err)
	}
	var pi windows.ProcessInformation
	if err := windows.CreateProcess(nil, line, nil, nil, false, windows.EXTENDED_STARTUPINFO_PRESENT, nil, nil, &si.StartupInfo, &pi); err != nil {
		windows.ClosePseudoConsole(pc)
		t.Fatal(err)
	}
	defer windows.CloseHandle(pi.Thread)
	defer windows.CloseHandle(pi.Process)

	type result struct {
		text string
		err  error
	}
	done := make(chan result, 1)
	go func() {
		var output strings.Builder
		responses := []struct{ prompt, reply string }{
			{`type host alias "console-测试" to confirm:`, "console-测试\r"},
			{`type phrase "outflow" to confirm:`, "outflow\r"},
			{`type confirmation "console-config" to confirm:`, "console-config\r"},
			{`type release version "1.2.3" to confirm:`, "1.2.3\r"},
			{"Password:", "console-secret\r"},
		}
		next := 0
		buf := make([]byte, 4096)
		for {
			n, readErr := outR.Read(buf)
			output.Write(buf[:n])
			if next < len(responses) && strings.Contains(output.String(), responses[next].prompt) {
				if _, err := io.WriteString(inW, responses[next].reply); err != nil {
					done <- result{output.String(), err}
					return
				}
				next++
			}
			if readErr != nil {
				done <- result{output.String(), nil}
				return
			}
		}
	}()
	status, waitErr := windows.WaitForSingleObject(pi.Process, 20000)
	if waitErr != nil || status != windows.WAIT_OBJECT_0 {
		windows.TerminateProcess(pi.Process, 1)
		windows.WaitForSingleObject(pi.Process, 5000)
	}
	windows.ClosePseudoConsole(pc)
	outW.Close()
	r := <-done
	if waitErr != nil || status != windows.WAIT_OBJECT_0 {
		t.Fatalf("console helper timed out: %v, %d\n%s", waitErr, status, r.text)
	}
	var code uint32
	if err := windows.GetExitCodeProcess(pi.Process, &code); err != nil || code != 0 || r.err != nil || !strings.Contains(r.text, "CONSOLE_TEST_OK") {
		t.Fatalf("console helper: exit=%d wait=%v io=%v\n%s", code, err, r.err, r.text)
	}
}

func TestWindowsConsoleDetached(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^TestWindowsConsoleHelper$", "-test.v")
	cmd.Env = append(os.Environ(), "SSH_CLI_TEST_CONSOLE=detached")
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.DETACHED_PROCESS}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("detached helper: %v\n%s", err, out)
	}
}

func TestWindowsConsoleHelper(t *testing.T) {
	switch os.Getenv("SSH_CLI_TEST_CONSOLE") {
	case "interactive":
		if !defaultTTY() {
			t.Fatal("real Windows console was not detected")
		}
		var out, errout bytes.Buffer
		if code := Execute([]string{"--config", t.TempDir(), "--yes", "env", "list"}, nil, &out, &errout); code != 0 {
			t.Fatalf("interactive --yes refused: %d %s", code, &errout)
		}
		if err := confirmAlias("console-测试", true); err != nil {
			t.Fatal(err)
		}
		if err := confirmAlias("console-测试", false); err != nil {
			t.Fatal(err)
		}
		if err := confirmOutflow(false); err != nil {
			t.Fatal(err)
		}
		if phrase, err := (&App{}).supplyPhrase("console-config"); err != nil || phrase != "console-config" {
			t.Fatalf("config confirmation failed: %v", err)
		}
		if err := confirmRelease("1.2.3", false); err != nil {
			t.Fatal(err)
		}
		console, err := openTTY()
		if err != nil {
			t.Fatal(err)
		}
		defer console.Close()
		if password, err := readPassword(nil, console, false); err != nil || password != "console-secret" {
			t.Fatalf("hidden password input failed: %v", err)
		}
		io.WriteString(console, "CONSOLE_TEST_OK\n")
	case "detached":
		if defaultTTY() {
			t.Fatal("detached process was treated as interactive")
		}
		if err := confirmAlias("fixture", true); err == nil {
			t.Fatal("detached --yes bypassed confirmation")
		}
		var out, errout bytes.Buffer
		if code := Execute([]string{"--yes", "env", "list"}, nil, &out, &errout); code != 253 || !strings.Contains(errout.String(), "--yes") {
			t.Fatalf("detached command accepted --yes: %d %s", code, &errout)
		}
	default:
		t.Skip("subprocess helper")
	}
}
