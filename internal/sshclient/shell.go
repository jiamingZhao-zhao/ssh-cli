package sshclient

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"

	"golang.org/x/crypto/ssh"
)

const maxShellRead = 8 << 20

// Shell is one persistent remote shell. Working directory and shell variables
// survive across Exec calls on this shell. The remote command is
// `stdbuf -oL -eL sh` so each printf is flushed. A remote without stdbuf fails
// the handshake with a clear error.
//
// Output is framed with a random marker preceded by a protocol newline, so a
// command that does not end in a newline still completes and that newline is
// not added to the caller's output. A timeout or a broken frame closes the
// session; the pool must not reuse it.
type Shell struct {
	sess   *ssh.Session
	stdin  io.WriteCloser
	stdout *bufio.Reader
	stderr *bufio.Reader
	mu     sync.Mutex
	dead   atomic.Bool
	once   sync.Once
}

// NewShell starts a line-buffered remote sh on client.
func NewShell(ctx context.Context, client *ssh.Client) (*Shell, error) {
	if client == nil {
		return nil, fmt.Errorf("nil ssh client")
	}
	if ctx == nil {
		ctx = context.Background()
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
	stop := sh.watch(ctx)
	defer close(stop)
	token, err := randomToken()
	if err != nil {
		sh.kill()
		return nil, err
	}
	ready := "READY_" + token
	if err := sh.write(ctx, "printf '%s\\n' "+shellQuote(ready)+"\n"); err != nil {
		sh.kill()
		return nil, err
	}
	line, err := sh.readLine(ctx, sh.stdout)
	if err != nil || line != ready {
		sh.kill()
		if err == nil {
			err = fmt.Errorf("handshake returned %q", line)
		}
		return nil, fmt.Errorf("persistent shell needs coreutils stdbuf (handshake failed: %w)", err)
	}
	return sh, nil
}

// Exec runs command in the persistent shell and returns its status.
func (s *Shell) Exec(ctx context.Context, command string, stdout, stderr io.Writer) (int, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := s.lock(ctx); err != nil {
		return 0, err
	}
	defer s.mu.Unlock()
	if s.dead.Load() || s.sess == nil {
		return 0, fmt.Errorf("persistent shell is closed")
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	stop := s.watch(ctx)
	defer close(stop)
	token, err := randomToken()
	if err != nil {
		return 0, err
	}
	done := "DONE_" + token
	errMark := "ERR_" + token
	// The leading \n is a framing byte, not part of the command output.
	script := command + "\n__sshcli_rc=$?\nprintf '\\n%s %s\\n' " + shellQuote(done) + " \"$__sshcli_rc\"\nprintf '\\n%s\\n' " + shellQuote(errMark) + " >&2\n"
	if err := s.write(ctx, script); err != nil {
		s.kill()
		return 0, err
	}
	type result struct {
		code int
		err  error
	}
	outCh := make(chan result, 1)
	errCh := make(chan error, 1)
	go func() {
		code, err := s.collect(s.stdout, stdout, "\n"+done+" ", true)
		outCh <- result{code: code, err: err}
	}()
	go func() {
		_, err := s.collect(s.stderr, stderr, "\n"+errMark+"\n", false)
		errCh <- err
	}()
	out := <-outCh
	errDone := <-errCh
	if out.err != nil || errDone != nil || s.dead.Load() {
		s.kill()
		if out.err != nil {
			return 0, out.err
		}
		if errDone != nil {
			return out.code, errDone
		}
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		return 0, fmt.Errorf("persistent shell closed")
	}
	return out.code, nil
}

// Close tears the shell session down.
func (s *Shell) Close() error {
	if s == nil {
		return nil
	}
	s.kill()
	return nil
}

func (s *Shell) watch(ctx context.Context) chan struct{} {
	stop := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			s.kill()
		case <-stop:
		}
	}()
	return stop
}

func (s *Shell) kill() {
	s.once.Do(func() {
		s.dead.Store(true)
		if s.stdin != nil {
			_ = s.stdin.Close()
		}
		// Exec reads s.sess under s.mu. kill also runs from the timeout watcher
		// without that lock, so the session pointer stays put and callers use
		// the dead flag.
		if s.sess != nil {
			_ = s.sess.Close()
		}
	})
}

func (s *Shell) lock(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	acquired := make(chan struct{})
	go func() {
		s.mu.Lock()
		close(acquired)
	}()
	select {
	case <-acquired:
		return nil
	case <-ctx.Done():
		go func() {
			<-acquired
			s.mu.Unlock()
		}()
		return ctx.Err()
	}
}

func (s *Shell) write(ctx context.Context, script string) error {
	done := make(chan error, 1)
	go func() { _, err := io.WriteString(s.stdin, script); done <- err }()
	select {
	case <-ctx.Done():
		s.kill()
		return ctx.Err()
	case err := <-done:
		return err
	}
}

func (s *Shell) collect(src *bufio.Reader, dst io.Writer, marker string, status bool) (int, error) {
	rest, err := streamUntil(src, dst, []byte(marker), maxShellRead)
	if err != nil {
		return 0, err
	}
	if !status {
		if len(bytes.TrimSpace(rest)) > 0 {
			return 0, fmt.Errorf("persistent shell framing desynced")
		}
		return 0, nil
	}
	line, extra, err := takeLine(src, rest)
	if err != nil {
		return 0, err
	}
	if len(bytes.TrimSpace(extra)) > 0 {
		return 0, fmt.Errorf("persistent shell framing desynced")
	}
	code := 0
	if _, err := fmt.Sscanf(strings.TrimSpace(line), "%d", &code); err != nil {
		return 0, fmt.Errorf("persistent shell status unreadable")
	}
	return code, nil
}

func streamUntil(src *bufio.Reader, dst io.Writer, marker []byte, max int) ([]byte, error) {
	var acc []byte
	buf := make([]byte, 4096)
	total := 0
	for {
		n, readErr := src.Read(buf)
		if n > 0 {
			total += n
			if total > max {
				return nil, fmt.Errorf("persistent shell output exceeded %d bytes", max)
			}
			acc = append(acc, buf[:n]...)
			if idx := bytes.Index(acc, marker); idx >= 0 {
				if dst != nil && idx > 0 {
					if _, err := dst.Write(acc[:idx]); err != nil {
						return nil, err
					}
				}
				return acc[idx+len(marker):], nil
			}
			keep := len(marker) - 1
			if keep < 1 {
				keep = 0
			}
			if len(acc) > keep {
				if dst != nil {
					if _, err := dst.Write(acc[:len(acc)-keep]); err != nil {
						return nil, err
					}
				}
				acc = append([]byte(nil), acc[len(acc)-keep:]...)
			}
		}
		if readErr != nil {
			return nil, readErr
		}
	}
}

func takeLine(src *bufio.Reader, rest []byte) (string, []byte, error) {
	acc := append([]byte(nil), rest...)
	for {
		if i := bytes.IndexByte(acc, '\n'); i >= 0 {
			return strings.TrimRight(string(acc[:i]), "\r"), acc[i+1:], nil
		}
		if len(acc) > 64 {
			return "", nil, fmt.Errorf("persistent shell status line too long")
		}
		b, err := src.ReadByte()
		if err != nil {
			return "", nil, err
		}
		acc = append(acc, b)
	}
}

func (s *Shell) readLine(ctx context.Context, src *bufio.Reader) (string, error) {
	type line struct {
		s   string
		err error
	}
	ch := make(chan line, 1)
	go func() {
		text, err := readCappedLine(src, 4096)
		ch <- line{s: text, err: err}
	}()
	select {
	case <-ctx.Done():
		s.kill()
		return "", ctx.Err()
	case got := <-ch:
		if got.err != nil && got.s == "" {
			return "", got.err
		}
		return got.s, nil
	}
}

func readCappedLine(src *bufio.Reader, max int) (string, error) {
	var b strings.Builder
	for b.Len() <= max {
		c, err := src.ReadByte()
		if err != nil {
			if b.Len() == 0 {
				return "", err
			}
			return strings.TrimRight(b.String(), "\r"), nil
		}
		if c == '\n' {
			return strings.TrimRight(b.String(), "\r"), nil
		}
		b.WriteByte(c)
	}
	return "", fmt.Errorf("persistent shell line exceeded %d bytes", max)
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
