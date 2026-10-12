package sshclient

import (
	"context"
	"errors"
	"net"
	"time"

	"golang.org/x/crypto/ssh"
)

// Keepalive timing is fixed. A pooled session is shared by the terminal and
// the workspace panels beside it, and those panels can sit quiet long enough
// for a NAT or a half-open link to go silent. Probes are SSH global requests,
// so a jump hop is covered too: TCP keepalive only sees the first socket.
//
// One unanswered probe closes that SSH client. A second global request would
// wait on the same mux lock as the probe that is still pending, so the timeout
// path closes instead of sending another. Tests shorten the two variables.
var (
	keepAliveEvery = 30 * time.Second
	keepAliveWait  = 45 * time.Second
)

var errKeepAliveTimeout = errors.New("ssh keepalive timed out")

const keepAliveName = "keepalive@openssh.com"

// enableTCPKeepAlive arms the kernel probes on a direct TCP socket.
// Jump channels are not TCP connections; SSH keepalive covers those.
func enableTCPKeepAlive(conn net.Conn) {
	tcp, ok := conn.(*net.TCPConn)
	if !ok || tcp == nil {
		return
	}
	_ = tcp.SetKeepAliveConfig(net.KeepAliveConfig{
		Enable:   true,
		Idle:     30 * time.Second,
		Interval: 10 * time.Second,
		Count:    3,
	})
}

// startKeepAlive probes conn until cancel or until a probe fails.
// The dial context is not used: callers cancel it as soon as Dial returns,
// while a pooled connection keeps living.
func startKeepAlive(conn *ssh.Client, onDead func()) context.CancelFunc {
	if conn == nil {
		return func() {}
	}
	ctx, cancel := context.WithCancel(context.Background())
	go keepAliveLoop(ctx, conn, onDead)
	return cancel
}

func keepAliveLoop(ctx context.Context, conn *ssh.Client, onDead func()) {
	every := keepAliveEvery
	wait := keepAliveWait
	if every <= 0 || wait <= 0 {
		return
	}
	timer := time.NewTimer(every)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			err := probeKeepAlive(ctx, conn, wait)
			if ctx.Err() != nil {
				return
			}
			if err != nil {
				if onDead != nil {
					onDead()
				}
				_ = conn.Close()
				return
			}
			timer.Reset(every)
		}
	}
}

func probeKeepAlive(ctx context.Context, conn *ssh.Client, wait time.Duration) error {
	errCh := make(chan error, 1)
	go func() {
		// A rejection is still a reply. OpenSSH answers this name with failure.
		_, _, err := conn.SendRequest(keepAliveName, true, nil)
		errCh <- err
	}()
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errCh:
		return err
	case <-timer.C:
		return errKeepAliveTimeout
	}
}
