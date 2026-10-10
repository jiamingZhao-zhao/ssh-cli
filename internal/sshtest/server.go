// Package sshtest is an in-process SSH server for unit tests.
package sshtest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"os/exec"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// Server is a password-authenticated SSH server on 127.0.0.1.
type Server struct {
	Addr     string
	Signer   ssh.Signer
	User     string
	ln       net.Listener
	wg       sync.WaitGroup
	closed   chan struct{}
	pass     string
	mu       sync.Mutex
	conns    map[net.Conn]struct{}
	sessions atomic.Int64
}

// Sessions is the number of shell and exec channels accepted.
// direct-tcpip tunnels are not counted. A jump host that only
// forwards a connection stays at zero.
func (s *Server) Sessions() int64 {
	if s == nil {
		return 0
	}
	return s.sessions.Load()
}

// Start listens and serves until Close.
func Start(user, pass string, signer ssh.Signer) (*Server, error) {
	if signer == nil {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		signer, err = ssh.NewSignerFromKey(key)
		if err != nil {
			return nil, err
		}
	}
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(meta ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			if meta.User() == user && string(password) == pass {
				return nil, nil
			}
			return nil, fmt.Errorf("authentication failed")
		},
	}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	s := &Server{Addr: ln.Addr().String(), Signer: signer, User: user, ln: ln, pass: pass, closed: make(chan struct{})}
	s.wg.Add(1)
	go s.accept(cfg)
	return s, nil
}

// Close stops the listener and waits for handlers.
func (s *Server) Close() {
	select {
	case <-s.closed:
	default:
		close(s.closed)
	}
	_ = s.ln.Close()
	s.mu.Lock()
	conns := make([]net.Conn, 0, len(s.conns))
	for c := range s.conns {
		conns = append(conns, c)
	}
	s.mu.Unlock()
	for _, c := range conns {
		_ = c.Close()
	}
	s.wg.Wait()
}

func (s *Server) accept(cfg *ssh.ServerConfig) {
	defer s.wg.Done()
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		if s.conns == nil {
			s.conns = map[net.Conn]struct{}{}
		}
		s.conns[conn] = struct{}{}
		s.mu.Unlock()
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer func() {
				s.mu.Lock()
				delete(s.conns, conn)
				s.mu.Unlock()
			}()
			s.handle(conn, cfg)
		}()
	}
}

func (s *Server) handle(conn net.Conn, cfg *ssh.ServerConfig) {
	defer conn.Close()
	sc, chans, reqs, err := ssh.NewServerConn(conn, cfg)
	if err != nil {
		return
	}
	defer sc.Close()
	go ssh.DiscardRequests(reqs)
	for ch := range chans {
		switch ch.ChannelType() {
		case "session":
			channel, requests, err := ch.Accept()
			if err != nil {
				continue
			}
			go s.session(channel, requests)
		case "direct-tcpip":
			go s.directTCP(ch)
		default:
			_ = ch.Reject(ssh.UnknownChannelType, "unknown channel")
		}
	}
}

func (s *Server) directTCP(newChan ssh.NewChannel) {
	var msg struct {
		DestAddr string
		DestPort uint32
		OrigAddr string
		OrigPort uint32
	}
	if err := ssh.Unmarshal(newChan.ExtraData(), &msg); err != nil {
		_ = newChan.Reject(ssh.ConnectionFailed, "bad open")
		return
	}
	dst, err := net.DialTimeout("tcp", net.JoinHostPort(msg.DestAddr, strconv.Itoa(int(msg.DestPort))), 5*time.Second)
	if err != nil {
		_ = newChan.Reject(ssh.ConnectionFailed, "dial failed")
		return
	}
	channel, requests, err := newChan.Accept()
	if err != nil {
		_ = dst.Close()
		return
	}
	go ssh.DiscardRequests(requests)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(channel, dst)
		_ = channel.CloseWrite()
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(dst, channel)
	}()
	go func() {
		wg.Wait()
		_ = dst.Close()
		_ = channel.Close()
	}()
}

func (s *Server) session(channel ssh.Channel, requests <-chan *ssh.Request) {
	defer channel.Close()
	for req := range requests {
		switch req.Type {
		case "pty-req", "window-change":
			_ = req.Reply(true, nil)
		case "shell":
			s.sessions.Add(1)
			_ = req.Reply(true, nil)
			go runLoginShell(channel)
		case "exec":
			var msg struct{ Command string }
			if err := ssh.Unmarshal(req.Payload, &msg); err != nil {
				_ = req.Reply(false, nil)
				return
			}
			s.sessions.Add(1)
			_ = req.Reply(true, nil)
			cmd := exec.Command("sh", "-c", msg.Command)
			cmd.Stdin = channel
			cmd.Stdout = channel
			cmd.Stderr = channel.Stderr()
			err := cmd.Run()
			code := uint32(0)
			if err != nil {
				if ee, ok := err.(*exec.ExitError); ok {
					code = uint32(ee.ExitCode())
				} else {
					code = 1
				}
			}
			_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{code}))
			return
		case "subsystem":
			var msg struct{ Name string }
			if err := ssh.Unmarshal(req.Payload, &msg); err != nil || msg.Name != "sftp" {
				_ = req.Reply(false, nil)
				continue
			}
			_ = req.Reply(true, nil)
			srv, err := sftp.NewServer(channel)
			if err != nil {
				return
			}
			_ = srv.Serve()
			return
		default:
			_ = req.Reply(false, nil)
		}
	}
}

// runLoginShell is the interactive terminal used by UI tests.
// stdbuf keeps echo output line-buffered on the SSH channel.
func runLoginShell(channel ssh.Channel) {
	cmd := exec.Command("stdbuf", "-oL", "-eL", "sh")
	if _, err := exec.LookPath("stdbuf"); err != nil {
		cmd = exec.Command("sh")
	}
	cmd.Stdin = channel
	cmd.Stdout = channel
	cmd.Stderr = channel.Stderr()
	err := cmd.Run()
	code := uint32(0)
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = uint32(ee.ExitCode())
		} else {
			code = 1
		}
	}
	_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{code}))
	_ = channel.Close()
}
