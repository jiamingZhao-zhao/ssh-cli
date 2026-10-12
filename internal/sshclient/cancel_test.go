package sshclient

import (
	"context"
	"golang.org/x/crypto/ssh"
	"net"
	"testing"
	"time"
)

func TestCancelUnresponsiveHandshake(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, e := ln.Accept()
		if e == nil {
			accepted <- c
		}
	}()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, e := Dial(ctx, ln.Addr().String(), "test", nil, ssh.InsecureIgnoreHostKey(), 10*time.Second)
		done <- e
	}()
	select {
	case c := <-accepted:
		defer c.Close()
	case <-time.After(time.Second):
		t.Fatal("no connection")
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancel accepted handshake")
		}
	case <-time.After(time.Second):
		t.Fatal("cancel did not interrupt handshake")
	}
}
