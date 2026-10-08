package sshclient

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/exitcode"
)

// Client is one SSH connection.
type Client struct {
	conn *ssh.Client
}

// Dial connects and authenticates. timeout bounds the TCP dial and handshake.
func Dial(ctx context.Context, addr, user string, auth []ssh.AuthMethod, hk ssh.HostKeyCallback, timeout time.Duration) (*Client, error) {
	if hk == nil {
		return nil, fmt.Errorf("host key callback is required")
	}
	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            auth,
		HostKeyCallback: hk,
		Timeout:         timeout,
	}
	d := net.Dialer{Timeout: timeout}
	netConn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	if timeout > 0 {
		_ = netConn.SetDeadline(time.Now().Add(timeout))
	}
	c, chans, reqs, err := ssh.NewClientConn(netConn, addr, cfg)
	if err != nil {
		_ = netConn.Close()
		return nil, err
	}
	_ = netConn.SetDeadline(time.Time{})
	return &Client{conn: ssh.NewClient(c, chans, reqs)}, nil
}

// Close closes the connection.
func (c *Client) Close() error {
	if c == nil || c.conn == nil {
		return nil
	}
	return c.conn.Close()
}

// Raw returns the underlying client for SFTP.
func (c *Client) Raw() *ssh.Client { return c.conn }

// Run executes command. A remote non-zero status is returned as code with a nil
// error. Transport failures are returned as errors.
func (c *Client) Run(ctx context.Context, command string, stdout, stderr io.Writer, stdin io.Reader) (int, error) {
	sess, err := c.conn.NewSession()
	if err != nil {
		return 0, err
	}
	defer sess.Close()
	if stdout != nil {
		sess.Stdout = stdout
	}
	if stderr != nil {
		sess.Stderr = stderr
	}
	if stdin != nil {
		sess.Stdin = stdin
	}
	errCh := make(chan error, 1)
	go func() { errCh <- sess.Run(command) }()
	select {
	case <-ctx.Done():
		_ = sess.Close()
		return 0, fmt.Errorf("command timed out: %w", ctx.Err())
	case err := <-errCh:
		if err == nil {
			return 0, nil
		}
		var ee *ssh.ExitError
		if errors.As(err, &ee) {
			return ee.ExitStatus(), nil
		}
		return 0, err
	}
}

// PasswordAuth returns password and keyboard-interactive methods.
// The secret is not placed in any command line.
func PasswordAuth(secret string) []ssh.AuthMethod {
	return []ssh.AuthMethod{
		ssh.Password(secret),
		ssh.KeyboardInteractive(func(name, instruction string, questions []string, echos []bool) ([]string, error) {
			answers := make([]string, len(questions))
			for i := range questions {
				answers[i] = secret
			}
			return answers, nil
		}),
	}
}

// IdentityAuth loads an unencrypted private key file.
func IdentityAuth(path string) (ssh.AuthMethod, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	signer, err := ssh.ParsePrivateKey(b)
	if err != nil {
		var missing *ssh.PassphraseMissingError
		if errors.As(err, &missing) {
			return nil, fmt.Errorf("identity %s is encrypted; encrypted keys are not supported yet", path)
		}
		return nil, err
	}
	return ssh.PublicKeys(signer), nil
}

// Wrap classifies a dial or session error into an exit code.
func Wrap(err error) error {
	if err == nil {
		return nil
	}
	var hk *HostKeyChangedError
	if errors.As(err, &hk) {
		return exitcode.New(exitcode.HostKey, "%s", err.Error())
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "unable to authenticate"),
		strings.Contains(msg, "authentication failed"),
		strings.Contains(msg, "no supported methods"),
		strings.Contains(msg, "handshake failed") && strings.Contains(msg, "auth"):
		return exitcode.New(exitcode.Auth, "authentication failed")
	case strings.Contains(msg, "host key"):
		return exitcode.New(exitcode.HostKey, "%s", err.Error())
	default:
		return exitcode.New(exitcode.Connect, "connection failed: %s", err.Error())
	}
}
