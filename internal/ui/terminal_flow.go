package ui

import (
	"encoding/json"
	"sync"

	"golang.org/x/crypto/ssh"
)

const terminalOutputWindow = 256 << 10

// Share one watcher per pooled connection, rather than leaking a Wait goroutine
// for each closed tab while its SSH connection stays alive.
func (s *service) terminalClientClosed(client *ssh.Client) <-chan struct{} {
	s.mu.Lock()
	if s.terminalClients == nil {
		s.terminalClients = make(map[*ssh.Client]chan struct{})
	}
	if done := s.terminalClients[client]; done != nil {
		s.mu.Unlock()
		return done
	}
	done := make(chan struct{})
	s.terminalClients[client] = done
	s.mu.Unlock()
	go func() {
		_ = client.Wait()
		s.mu.Lock()
		delete(s.terminalClients, client)
		close(done)
		s.mu.Unlock()
	}()
	return done
}

// Browsers acknowledge output only after xterm consumes it. Exhausting the
// window pauses PTY reads, allowing SSH's existing channel flow control to
// slow the producer rather than dropping bytes or growing a browser queue.
type outputWindow struct {
	mu      sync.Mutex
	pending int
	wake    chan struct{}
	stop    chan struct{}
}

func newOutputWindow() *outputWindow {
	return &outputWindow{wake: make(chan struct{}, 1), stop: make(chan struct{})}
}

func (f *outputWindow) acquire(n int) error {
	if n <= 0 || n > terminalOutputWindow {
		return errString("invalid terminal output size")
	}
	for {
		f.mu.Lock()
		if f.pending+n <= terminalOutputWindow {
			f.pending += n
			f.mu.Unlock()
			return nil
		}
		f.mu.Unlock()
		select {
		case <-f.wake:
		case <-f.stop:
			return errString("terminal closed")
		}
	}
}

func (f *outputWindow) acknowledge(n int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if n <= 0 || n > f.pending {
		return errString("invalid terminal output acknowledgement")
	}
	f.pending -= n
	select {
	case f.wake <- struct{}{}:
	default:
	}
	return nil
}

func parseOutputAck(payload []byte) (int, bool) {
	var msg struct {
		Type  string          `json:"type"`
		Bytes json.RawMessage `json:"bytes"`
	}
	if json.Unmarshal(payload, &msg) != nil || msg.Type != "output_ack" {
		return 0, false
	}
	var n int
	_ = json.Unmarshal(msg.Bytes, &n)
	return n, true
}
