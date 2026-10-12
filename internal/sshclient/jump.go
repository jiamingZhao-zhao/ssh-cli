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
	out := &Client{}
	var carriers []*ssh.Client
	var current *ssh.Client
	var stops []context.CancelFunc
	for _, hop := range hops {
		netConn, err := dialHop(ctx, current, hop, timeout)
		if err != nil {
			stopAll(stops)
			closeChain(carriers, current)
			return nil, hopErr(hop, err)
		}
		next, err := clientHandshake(ctx, netConn, hop, timeout)
		if err != nil {
			stopAll(stops)
			closeChain(carriers, current)
			return nil, hopErr(hop, err)
		}
		stops = append(stops, startKeepAlive(next, out.markDead))
		if current != nil {
			carriers = append(carriers, current)
		}
		current = next
	}
	out.conn = current
	out.carriers = carriers
	out.stops = stops
	return out, nil
}

func dialHop(ctx context.Context, via *ssh.Client, hop Hop, timeout time.Duration) (net.Conn, error) {
	if via == nil {
		d := net.Dialer{Timeout: timeout}
		conn, err := d.DialContext(ctx, "tcp", hop.Addr)
		if err != nil {
			return nil, err
		}
		enableTCPKeepAlive(conn)
		return conn, nil
	}
	return via.DialContext(ctx, "tcp", hop.Addr)
}

func stopAll(stops []context.CancelFunc) {
	for _, stop := range stops {
		if stop != nil {
			stop()
		}
	}
}

func clientHandshake(ctx context.Context, netConn net.Conn, hop Hop, timeout time.Duration) (*ssh.Client, error) {
	if hop.HostKey == nil {
		_ = netConn.Close()
		return nil, fmt.Errorf("host key callback is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	// ssh.ClientConfig.Timeout only bounds ssh.Dial's TCP connect. It does
	// not bound NewClientConn. A direct-tcpip channel returns
	// "deadline not supported" from SetDeadline, so a peer that accepts TCP
	// and never sends a banner would ignore both the context and timeout.
	// Closing the channel is what unblocks the handshake.
	hctx := ctx
	stopTimeout := func() {}
	if timeout > 0 {
		var cancel context.CancelFunc
		hctx, cancel = context.WithTimeout(ctx, timeout)
		stopTimeout = cancel
	}
	defer stopTimeout()
	if err := hctx.Err(); err != nil {
		_ = netConn.Close()
		return nil, err
	}
	deadline := time.Time{}
	if timeout > 0 {
		deadline = time.Now().Add(timeout)
	}
	if dl, ok := hctx.Deadline(); ok && (deadline.IsZero() || dl.Before(deadline)) {
		deadline = dl
	}
	if !deadline.IsZero() {
		_ = netConn.SetDeadline(deadline)
	}
	stopWatch := context.AfterFunc(hctx, func() {
		_ = netConn.Close()
	})
	cfg := &ssh.ClientConfig{
		User:            hop.User,
		Auth:            hop.Auth,
		HostKeyCallback: hop.HostKey,
	}
	c, chans, reqs, err := ssh.NewClientConn(netConn, hop.Addr, cfg)
	// Stop before using the connection. false means the callback already
	// closed netConn, so a handshake that won the race must not be returned.
	if !stopWatch() {
		if c != nil {
			_ = c.Close()
		}
		if hctx.Err() != nil {
			return nil, hctx.Err()
		}
		if err != nil {
			return nil, err
		}
		return nil, context.DeadlineExceeded
	}
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
