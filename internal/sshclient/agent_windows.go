package sshclient

import (
	"net"
	"os"
	"strings"
	"time"

	"golang.org/x/sys/windows"
)

func defaultAgentSocket() string { return `\\.\pipe\openssh-ssh-agent` }

func agentEndpoint(sock string) (agentConnection, error) {
	if !strings.HasPrefix(strings.ToLower(sock), `\\.\pipe\`) {
		return net.DialTimeout("unix", sock, 5*time.Second)
	}
	name, err := windows.UTF16PtrFromString(sock)
	if err != nil {
		return nil, err
	}
	// Overlapped handles participate in Go's poller and support deadlines.
	h, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OVERLAPPED, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(h), sock)
	if err := f.SetDeadline(time.Now().Add(20 * time.Second)); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}
