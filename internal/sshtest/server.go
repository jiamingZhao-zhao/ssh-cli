// Package sshtest is an in-process SSH server for unit tests.
package sshtest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"net"
	"os/exec"
	"sync"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// Server is a password-authenticated SSH server on 127.0.0.1.
type Server struct {
	Addr   string
	Signer ssh.Signer
	User   string
	ln     net.Listener
	wg     sync.WaitGroup
	closed chan struct{}
	pass   string
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
	s.wg.Wait()
}

func (s *Server) accept(cfg *ssh.ServerConfig) {
	defer s.wg.Done()
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
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
		if ch.ChannelType() != "session" {
			_ = ch.Reject(ssh.UnknownChannelType, "unknown channel")
			continue
		}
		channel, requests, err := ch.Accept()
		if err != nil {
			continue
		}
		go s.session(channel, requests)
	}
}

func (s *Server) session(channel ssh.Channel, requests <-chan *ssh.Request) {
	defer channel.Close()
	for req := range requests {
		switch req.Type {
		case "exec":
			var msg struct{ Command string }
			if err := ssh.Unmarshal(req.Payload, &msg); err != nil {
				_ = req.Reply(false, nil)
				return
			}
			_ = req.Reply(true, nil)
			cmd := exec.Command("sh", "-c", msg.Command)
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
