// Package session keeps an in-process pool of persistent SSH shells.
// There is no background daemon. The process that opened a session owns it,
// and process exit closes every session that process still holds.
//
// Idle auto-close defaults to 5 minutes without exec, upload, download, or
// relay. Max lifetime defaults to 60 minutes and wins even when the session
// is busy. Both windows are configurable. Zero means the default. Negative
// values are rejected.
package session

import (
	"context"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/sshclient"
	"golang.org/x/crypto/ssh"
)

const (
	// DefaultIdle is the auto-close window after the last use.
	DefaultIdle = 5 * time.Minute
	// DefaultMaxLife is the hard cap, including in-flight work.
	DefaultMaxLife = 60 * time.Minute
)

// DialFunc opens one SSH connection. The pool calls it outside its lock.
type DialFunc func(ctx context.Context, alias string) (*sshclient.Client, error)

// CloseFunc is invoked after a session's channel is torn down.
type CloseFunc func(alias, reason string)

// Info is a snapshot of one live session.
type Info struct {
	Alias   string    `json:"alias"`
	Opened  time.Time `json:"opened"`
	Used    time.Time `json:"used"`
	Busy    int       `json:"busy"`
	Idle    string    `json:"idle"`
	MaxLife string    `json:"maxLife"`
}

// Pool is the in-process session table.
type Pool struct {
	mu      sync.Mutex
	items   map[string]*entry
	idle    time.Duration
	maxLife time.Duration
	now     func() time.Time
	dial    DialFunc
	onClose CloseFunc
}

type entry struct {
	alias   string
	client  *sshclient.Client
	shell   *sshclient.Shell
	opened  time.Time
	used    time.Time
	busy    int
	closed  bool
	closeCh chan struct{}
}

// New returns a pool. dial is required. onClose may be nil.
func New(idle, maxLife time.Duration, dial DialFunc, onClose CloseFunc) (*Pool, error) {
	idle, err := normalize(idle, DefaultIdle)
	if err != nil {
		return nil, err
	}
	maxLife, err = normalize(maxLife, DefaultMaxLife)
	if err != nil {
		return nil, err
	}
	if dial == nil {
		return nil, fmt.Errorf("session dial is required")
	}
	return &Pool{
		items:   map[string]*entry{},
		idle:    idle,
		maxLife: maxLife,
		now:     time.Now,
		dial:    dial,
		onClose: onClose,
	}, nil
}

// ParseWindow accepts a duration. Zero selects def. Negative is an error.
func ParseWindow(raw string, def time.Duration) (time.Duration, error) {
	raw = stringsTrim(raw)
	if raw == "" || raw == "0" || raw == "0s" {
		return def, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("invalid duration %q", raw)
	}
	if d < 0 {
		return 0, fmt.Errorf("duration must be >= 0")
	}
	if d == 0 {
		return def, nil
	}
	return d, nil
}

func stringsTrim(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\t') {
		s = s[:len(s)-1]
	}
	return s
}

func normalize(v, def time.Duration) (time.Duration, error) {
	if v == 0 {
		return def, nil
	}
	if v < 0 {
		return 0, fmt.Errorf("duration must be >= 0")
	}
	return v, nil
}

// SetClock replaces the clock. Tests use it so idle and max life need no sleep.
func (p *Pool) SetClock(now func() time.Time) {
	if now == nil {
		return
	}
	p.mu.Lock()
	p.now = now
	p.mu.Unlock()
}

// Open returns the live shell for alias, dialing when needed.
// ForceNew closes any existing session for that alias first.
func (p *Pool) Open(ctx context.Context, alias string, forceNew bool) error {
	if forceNew {
		p.finish(alias, "explicit")
	}
	p.mu.Lock()
	if e := p.items[alias]; e != nil && !e.closed {
		e.used = p.now()
		p.mu.Unlock()
		return nil
	}
	p.mu.Unlock()
	client, err := p.dial(ctx, alias)
	if err != nil {
		return err
	}
	shell, err := sshclient.NewShell(ctx, client.Raw())
	if err != nil {
		_ = client.Close()
		return err
	}
	now := p.now()
	e := &entry{alias: alias, client: client, shell: shell, opened: now, used: now, closeCh: make(chan struct{})}
	p.mu.Lock()
	if cur := p.items[alias]; cur != nil && !cur.closed {
		p.mu.Unlock()
		_ = shell.Close()
		_ = client.Close()
		return nil
	}
	p.items[alias] = e
	p.mu.Unlock()
	return nil
}

// Exec runs command on the alias session, opening it when needed.
func (p *Pool) Exec(ctx context.Context, alias, command string, stdout, stderr io.Writer) (int, error) {
	if err := p.Open(ctx, alias, false); err != nil {
		return 0, err
	}
	p.mu.Lock()
	e := p.items[alias]
	if e == nil || e.closed {
		p.mu.Unlock()
		return 0, fmt.Errorf("session %s is closed", alias)
	}
	e.busy++
	e.used = p.now()
	shell := e.shell
	p.mu.Unlock()
	code, err := shell.Exec(ctx, command, stdout, stderr)
	p.mu.Lock()
	if e.busy > 0 {
		e.busy--
	}
	if !e.closed {
		e.used = p.now()
	}
	p.mu.Unlock()
	return code, err
}

// Use marks alias busy around fn. Upload, download, and relay call this so
// idle close does not drop an in-flight transfer. Max life still closes it.
func (p *Pool) Use(alias string, fn func() error) error {
	p.mu.Lock()
	e := p.items[alias]
	if e == nil || e.closed {
		p.mu.Unlock()
		return fmt.Errorf("session %s is not open", alias)
	}
	e.busy++
	e.used = p.now()
	p.mu.Unlock()
	err := fn()
	p.mu.Lock()
	if e.busy > 0 {
		e.busy--
	}
	if !e.closed {
		e.used = p.now()
	}
	p.mu.Unlock()
	return err
}

// Close tears down alias immediately.
func (p *Pool) Close(alias string) { p.finish(alias, "explicit") }

// Shutdown closes every session. Call it when the owning process exits.
func (p *Pool) Shutdown() {
	p.mu.Lock()
	aliases := make([]string, 0, len(p.items))
	for alias := range p.items {
		aliases = append(aliases, alias)
	}
	p.mu.Unlock()
	for _, alias := range aliases {
		p.finish(alias, "process_exit")
	}
}

// List returns live sessions.
func (p *Pool) List() []Info {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]Info, 0, len(p.items))
	for _, e := range p.items {
		if e.closed {
			continue
		}
		out = append(out, Info{
			Alias: e.alias, Opened: e.opened, Used: e.used, Busy: e.busy,
			Idle: p.idle.String(), MaxLife: p.maxLife.String(),
		})
	}
	return out
}

// Sweep closes sessions that are idle or past max life. now is the injected clock.
func (p *Pool) Sweep(now time.Time) {
	p.mu.Lock()
	var idle, expired []string
	for alias, e := range p.items {
		if e.closed {
			continue
		}
		if !e.opened.IsZero() && now.Sub(e.opened) >= p.maxLife {
			expired = append(expired, alias)
			continue
		}
		if e.busy == 0 && now.Sub(e.used) >= p.idle {
			idle = append(idle, alias)
		}
	}
	p.mu.Unlock()
	for _, alias := range expired {
		p.finish(alias, "max_life")
	}
	for _, alias := range idle {
		p.finish(alias, "idle")
	}
}

// Loop sweeps about once a second until ctx is cancelled, then shuts the pool down.
func (p *Pool) Loop(ctx context.Context) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			p.Shutdown()
			return
		case <-t.C:
			p.mu.Lock()
			now := p.now()
			p.mu.Unlock()
			p.Sweep(now)
		}
	}
}

func (p *Pool) finish(alias, reason string) {
	p.mu.Lock()
	e := p.items[alias]
	if e == nil || e.closed {
		p.mu.Unlock()
		return
	}
	e.closed = true
	delete(p.items, alias)
	shell := e.shell
	client := e.client
	p.mu.Unlock()
	if shell != nil {
		_ = shell.Close()
	}
	if client != nil {
		_ = client.Close()
	}
	if p.onClose != nil {
		p.onClose(alias, reason)
	}
}

// Client returns the live SSH client for alias, if the session is open.
func (p *Pool) Client(alias string) (*ssh.Client, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	e := p.items[alias]
	if e == nil || e.closed || e.client == nil {
		return nil, false
	}
	return e.client.Raw(), true
}
