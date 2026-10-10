package sshclient

import (
	"context"
	"fmt"
	"net"
	"time"

	"golang.org/x/crypto/ssh"
)

// maxDialHops matches config.MaxViaHops. sshclient does not import config.
const maxDialHops = 8

// Hop is one SSH handshake. The first hop is dialed over TCP.
// Each later hop is a new SSH handshake on a direct-tcpip channel
// through the previous hop. The hop is not given a shell or exec session.
type Hop struct {
	Name    string
	Addr    string
	User    string
	Auth    []ssh.AuthMethod
	HostKey ssh.HostKeyCallback
}

// DialHops connects to hops[0] over TCP, then completes an SSH handshake
// to each following hop through the previous client. The returned client
// is the last hop. Closing it closes the earlier hops. A one-element
// list is a direct connection.
func DialHops(ctx context.Context, hops []Hop, timeout time.Duration) (*Client, error) {
	if len(hops) == 0 {
		return nil, fmt.Errorf("no dial hops")
	}
	if len(hops) > maxDialHops {
		return nil, fmt.Errorf("jump chain longer than %d", maxDialHops)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	var carriers []*ssh.Client
	var current *ssh.Client
	for _, hop := range hops {
		netConn, err := dialHop(ctx, current, hop, timeout)
		if err != nil {
			closeChain(carriers, current)
			return nil, hopErr(hop, err)
		}
		next, err := clientHandshake(ctx, netConn, hop, timeout)
		if err != nil {
			closeChain(carriers, current)
			return nil, hopErr(hop, err)
		}
		if current != nil {
			carriers = append(carriers, current)
		}
		current = next
	}
	return &Client{conn: current, carriers: carriers}, nil
}

func dialHop(ctx context.Context, via *ssh.Client, hop Hop, timeout time.Duration) (net.Conn, error) {
	if via == nil {
		d := net.Dialer{Timeout: timeout}
		return d.DialContext(ctx, "tcp", hop.Addr)
	}
	return via.DialContext(ctx, "tcp", hop.Addr)
}

func clientHandshake(ctx context.Context, netConn net.Conn, hop Hop, timeout time.Duration) (*ssh.Client, error) {
	if hop.HostKey == nil {
		_ = netConn.Close()
		return nil, fmt.Errorf("host key callback is required")
	}
	deadline := time.Time{}
	if timeout > 0 {
		deadline = time.Now().Add(timeout)
	}
	if dl, ok := ctx.Deadline(); ok && (deadline.IsZero() || dl.Before(deadline)) {
		deadline = dl
	}
	if !deadline.IsZero() {
		_ = netConn.SetDeadline(deadline)
	}
	cfg := &ssh.ClientConfig{
		User:            hop.User,
		Auth:            hop.Auth,
		HostKeyCallback: hop.HostKey,
		Timeout:         timeout,
	}
	c, chans, reqs, err := ssh.NewClientConn(netConn, hop.Addr, cfg)
	if err != nil {
		return nil, err
	}
	_ = netConn.SetDeadline(time.Time{})
	return ssh.NewClient(c, chans, reqs), nil
}

func hopErr(hop Hop, err error) error {
	if err == nil || hop.Name == "" {
		return err
	}
	return fmt.Errorf("%s: %w", hop.Name, err)
}

func closeChain(carriers []*ssh.Client, current *ssh.Client) {
	if current != nil {
		_ = current.Close()
	}
	for i := len(carriers) - 1; i >= 0; i-- {
		if carriers[i] != nil {
			_ = carriers[i].Close()
		}
	}
}
