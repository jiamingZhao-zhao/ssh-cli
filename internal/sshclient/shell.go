package sshclient

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"
)

// Shell is one persistent remote shell. Working directory and shell variables
// survive across Exec calls on this shell. The remote command is
// `stdbuf -oL -eL sh` so each printf is flushed. A remote without stdbuf fails
// the handshake with a clear error.
//
// Commands that read stdin can swallow the completion marker. Exec cancels
// those by closing the session when ctx ends.
type Shell struct {
	sess   *ssh.Session
	stdin  io.WriteCloser
	stdout *bufio.Reader
	stderr *bufio.Reader
	mu     sync.Mutex
}

// NewShell starts a line-buffered remote sh on client.
func NewShell(ctx context.Context, client *ssh.Client) (*Shell, error) {
	if client == nil {
		return nil, fmt.Errorf("nil ssh client")
	}
	sess, err := client.NewSession()
	if err != nil {
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
	stderr, err := sess.StderrPipe()
	if err != nil {
		_ = sess.Close()
		return nil, err
	}
	if err := sess.Start("stdbuf -oL -eL sh"); err != nil {
		_ = sess.Close()
		return nil, fmt.Errorf("start persistent shell: %w", err)
	}
	sh := &Shell{sess: sess, stdin: stdin, stdout: bufio.NewReader(stdout), stderr: bufio.NewReader(stderr)}
	token, err := randomToken()
	if err != nil {
		_ = sh.Close()
		return nil, err
	}
	ready := "READY_" + token
	if err := sh.write(ctx, "printf '%s\\n' "+shellQuote(ready)+"\n"); err != nil {
		_ = sh.Close()
		return nil, err
	}
	line, err := sh.readLine(ctx, sh.stdout)
	if err != nil || line != ready {
		_ = sh.Close()
		if err == nil {
			err = fmt.Errorf("handshake returned %q", line)
		}
		return nil, fmt.Errorf("persistent shell needs coreutils stdbuf (handshake failed: %w)", err)
	}
	return sh, nil
}

// Exec runs command in the persistent shell and returns its status.
func (s *Shell) Exec(ctx context.Context, command string, stdout, stderr io.Writer) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	token, err := randomToken()
	if err != nil {
		return 0, err
	}
	done := "DONE_" + token
	errMark := "ERR_" + token
	script := command + "\n__sshcli_rc=$?\nprintf '%s %s\\n' " + shellQuote(done) + " \"$__sshcli_rc\"\nprintf '%s\\n' " + shellQuote(errMark) + " >&2\n"
	if err := s.write(ctx, script); err != nil {
		return 0, err
	}
	type result struct {
		code int
		err  error
	}
	outCh := make(chan result, 1)
	errCh := make(chan error, 1)
	go func() {
		code, err := s.collect(ctx, s.stdout, stdout, done+" ")
		outCh <- result{code: code, err: err}
	}()
	go func() {
		_, err := s.collect(ctx, s.stderr, stderr, errMark)
		errCh <- err
	}()
	out := <-outCh
	errDone := <-errCh
	if out.err != nil {
		return 0, out.err
	}
	if errDone != nil {
		return out.code, errDone
	}
	return out.code, nil
}

// Close tears the shell session down.
func (s *Shell) Close() error {
	if s == nil || s.sess == nil {
		return nil
	}
	_ = s.stdin.Close()
	err := s.sess.Close()
	s.sess = nil
	return err
}

func (s *Shell) write(ctx context.Context, script string) error {
	done := make(chan error, 1)
	go func() { _, err := io.WriteString(s.stdin, script); done <- err }()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-done:
		return err
	}
}

func (s *Shell) collect(ctx context.Context, src *bufio.Reader, dst io.Writer, marker string) (int, error) {
	for {
		line, err := s.readLine(ctx, src)
		if err != nil {
			return 0, err
		}
		if marker == line || strings.HasPrefix(line, marker) {
			code := 0
			if rest, ok := strings.CutPrefix(line, marker); ok && marker != line {
				_, _ = fmt.Sscanf(strings.TrimSpace(rest), "%d", &code)
			}
			return code, nil
		}
		if dst != nil {
			if _, err := io.WriteString(dst, line+"\n"); err != nil {
				return 0, err
			}
		}
	}
}

func (s *Shell) readLine(ctx context.Context, src *bufio.Reader) (string, error) {
	type line struct {
		s   string
		err error
	}
	ch := make(chan line, 1)
	go func() {
		text, err := src.ReadString('\n')
		ch <- line{s: strings.TrimRight(text, "\r\n"), err: err}
	}()
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case got := <-ch:
		if got.err != nil && got.s == "" {
			return "", got.err
		}
		return got.s, nil
	}
}

func randomToken() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
