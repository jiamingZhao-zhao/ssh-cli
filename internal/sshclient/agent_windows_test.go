package sshclient

import (
	"fmt"
	"golang.org/x/sys/windows"
	"os"
	"testing"
	"time"
)

func TestAgentWindowsMissingPipe(t *testing.T) {
	start := time.Now()
	conn, err := connectAgent(fmt.Sprintf(`\\.\pipe\ssh-cli-missing-%d`, start.UnixNano()))
	if conn != nil {
		conn.Close()
		t.Fatal("unexpected pipe")
	}
	if err == nil {
		t.Fatal("missing agent must fail")
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("missing pipe blocked")
	}
	if conn, err := agentEndpoint("\\\\.\\pipe\\invalid\x00name"); err == nil {
		conn.Close()
		t.Fatal("invalid pipe accepted")
	}
}

func TestAgentWindowsPipeReadDeadline(t *testing.T) {
	name := fmt.Sprintf(`\\.\pipe\ssh-cli-deadline-%d`, time.Now().UnixNano())
	path, err := windows.UTF16PtrFromString(name)
	if err != nil {
		t.Fatal(err)
	}
	pipe, err := windows.CreateNamedPipe(path, windows.PIPE_ACCESS_DUPLEX|windows.FILE_FLAG_OVERLAPPED, windows.PIPE_TYPE_BYTE|windows.PIPE_READMODE_BYTE|windows.PIPE_WAIT, 1, 4096, 4096, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(pipe)
	conn, err := connectAgent(name)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := windows.ConnectNamedPipe(pipe, nil); err != nil && err != windows.ERROR_PIPE_CONNECTED {
		t.Fatal(err)
	}
	if err := conn.SetDeadline(time.Now().Add(30 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	_, err = conn.Read(make([]byte, 1))
	if !os.IsTimeout(err) {
		t.Fatalf("expected pipe timeout, got %v", err)
	}
}
