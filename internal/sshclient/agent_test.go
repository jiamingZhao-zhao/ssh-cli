package sshclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func TestAgentAuthenticationWithoutPrivateKeyFile(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(t.TempDir(), "agent.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Skipf("local Unix socket unavailable: %v", err)
	}
	defer ln.Close()
	ring := agent.NewKeyring()
	if err := ring.Add(agent.AddedKey{PrivateKey: key}); err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); agent.ServeAgent(ring, c) }()
		}
	}()
	t.Setenv("SSH_AUTH_SOCK", sock)
	method, err := AgentAuth()
	if err != nil {
		t.Fatal(err)
	}
	server, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	config := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, got ssh.PublicKey) (*ssh.Permissions, error) {
		if !bytes.Equal(got.Marshal(), signer.PublicKey().Marshal()) {
			return nil, fmt.Errorf("unknown key")
		}
		return nil, nil
	}}
	config.AddHostKey(signer)
	go func() {
		c, err := server.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		raw, ch, req, err := ssh.NewServerConn(c, config)
		if err != nil {
			return
		}
		defer raw.Close()
		go ssh.DiscardRequests(req)
		for channel := range ch {
			channel.Reject(ssh.UnknownChannelType, "auth test")
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := Dial(ctx, server.Addr().String(), "agent-user", []ssh.AuthMethod{method}, ssh.FixedHostKey(signer.PublicKey()), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
}
