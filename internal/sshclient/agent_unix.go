//go:build !windows

package sshclient

import (
	"net"
	"time"
)

func agentEndpoint(sock string) (agentConnection, error) {
	return net.DialTimeout("unix", sock, 5*time.Second)
}

func defaultAgentSocket() string { return "" }
