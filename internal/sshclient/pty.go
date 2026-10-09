package sshclient

import (
	"fmt"
	"io"
	"sync"

	"golang.org/x/crypto/ssh"
)

// PTY is an interactive remote shell on its own SSH channel.
// It is separate from the non-interactive persistent shell used by Exec.
type PTY struct {
	mu     sync.Mutex
	sess   *ssh.Session
	stdin  io.WriteCloser
	stdout io.Reader
	once   sync.Once
}

// StartPTY requests a pseudo-terminal and the remote login shell.
// cols and rows are the initial window. Non-positive sizes fall back to 80x24.
func StartPTY(client *ssh.Client, cols, rows int) (*PTY, error) {
	if client == nil {
		return nil, fmt.Errorf("nil ssh client")
	}
	if cols < 1 {
		cols = 80
	}
	if rows < 1 {
		rows = 24
	}
	sess, err := client.NewSession()
	if err != nil {
		return nil, err
	}
	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}
	if err := sess.RequestPty("xterm-256color", rows, cols, modes); err != nil {
		_ = sess.Close()
		return nil, err
	}
	stdin, err := sess.StdinPipe()
	if err != nil {
		_ = sess.Close()
		return nil, err
	}
	stdout, err := sess.StdoutPipe()
	if err != nil {
		_ = sess.Close()
		return nil, err
	}
	if err := sess.Shell(); err != nil {
		_ = sess.Close()
		return nil, err
	}
	p := &PTY{sess: sess, stdin: stdin, stdout: stdout}
	go func() { _ = sess.Wait() }()
	return p, nil
}

// Read copies remote terminal output.
func (p *PTY) Read(b []byte) (int, error) {
	if p == nil || p.stdout == nil {
		return 0, io.EOF
	}
	return p.stdout.Read(b)
}

// Write sends keystrokes to the remote terminal.
func (p *PTY) Write(b []byte) (int, error) {
	if p == nil {
		return 0, io.ErrClosedPipe
	}
	p.mu.Lock()
	in := p.stdin
	p.mu.Unlock()
	if in == nil {
		return 0, io.ErrClosedPipe
	}
	return in.Write(b)
}

// Resize updates the remote window. cols and rows must be positive.
func (p *PTY) Resize(cols, rows int) error {
	if p == nil {
		return io.ErrClosedPipe
	}
	if cols < 1 || rows < 1 {
		return fmt.Errorf("invalid terminal size")
	}
	p.mu.Lock()
	sess := p.sess
	p.mu.Unlock()
	if sess == nil {
		return io.ErrClosedPipe
	}
	return sess.WindowChange(rows, cols)
}

// Close tears down the remote shell channel.
func (p *PTY) Close() error {
	if p == nil {
		return nil
	}
	p.once.Do(func() {
		p.mu.Lock()
		in := p.stdin
		sess := p.sess
		p.stdin = nil
		p.sess = nil
		p.mu.Unlock()
		if in != nil {
			_ = in.Close()
		}
		if sess != nil {
			_ = sess.Close()
		}
	})
	return nil
}
