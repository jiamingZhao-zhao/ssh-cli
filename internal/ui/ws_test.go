package ui

import (
	"bufio"
	"net"
	"testing"
	"time"
)

func TestWSPingFrame(t *testing.T) {
	left, right := net.Pipe()
	t.Cleanup(func() {
		_ = left.Close()
		_ = right.Close()
	})
	peer := &wsConn{c: left, r: bufio.NewReader(left), w: bufio.NewWriter(left)}
	srv := &wsConn{c: right, r: bufio.NewReader(right), w: bufio.NewWriter(right)}
	stop := srv.armIdle(20*time.Millisecond, time.Hour, time.Second)
	defer stop()
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	fin, op, _, err := peer.readFrame()
	if err != nil || !fin || op != wsPing {
		t.Fatalf("ping fin=%v op=%d err=%v", fin, op, err)
	}
}

func TestWSReadIdleUnblocks(t *testing.T) {
	left, right := net.Pipe()
	t.Cleanup(func() {
		_ = left.Close()
		_ = right.Close()
	})
	srv := &wsConn{c: right, r: bufio.NewReader(right), w: bufio.NewWriter(right), readMask: true}
	stop := srv.armIdle(0, 80*time.Millisecond, time.Second)
	defer stop()
	start := time.Now()
	_, _, err := srv.ReadMessage()
	if err == nil {
		t.Fatal("expected read error")
	}
	if time.Since(start) > time.Second {
		t.Fatalf("read blocked for %s: %v", time.Since(start), err)
	}
}

func TestWSPongKeepsReadOpen(t *testing.T) {
	left, right := net.Pipe()
	t.Cleanup(func() {
		_ = left.Close()
		_ = right.Close()
	})
	peer := &wsConn{c: left, r: bufio.NewReader(left), w: bufio.NewWriter(left), writeMask: true}
	srv := &wsConn{c: right, r: bufio.NewReader(right), w: bufio.NewWriter(right), readMask: true}
	stop := srv.armIdle(30*time.Millisecond, 120*time.Millisecond, time.Second)
	defer stop()
	go func() {
		for {
			if _, _, err := peer.ReadMessage(); err != nil {
				return
			}
		}
	}()
	errCh := make(chan error, 1)
	go func() {
		_, _, err := srv.ReadMessage()
		errCh <- err
	}()
	select {
	case err := <-errCh:
		t.Fatalf("read idle fired while pongs were flowing: %v", err)
	case <-time.After(400 * time.Millisecond):
	}
}
