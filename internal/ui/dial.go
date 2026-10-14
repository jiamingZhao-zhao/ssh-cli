package ui

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/audit"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/config"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/session"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/sshclient"
	"golang.org/x/crypto/ssh"
)

func (s *service) dialAlias(ctx context.Context, alias, fingerprint string) (*sshclient.Client, error) {
	cfg, err := config.Load(s.dir)
	if err != nil {
		return nil, err
	}
	h, ok := cfg.Find(alias)
	if !ok {
		return nil, fmt.Errorf("unknown host %s", alias)
	}
	if h.Host == nil || cfg.SessionFingerprint(h) != fingerprint {
		return nil, fmt.Errorf("host %s connection identity changed", alias)
	}
	return s.dialResolved(ctx, h)
}

// reconcile drops pooled sessions whose connection identity no longer matches
// the saved config, including hosts that were removed.
func (s *service) reconcile() {
	cfg, err := config.Load(s.dir)
	if err != nil || s.pool == nil {
		return
	}
	s.reconcileConfig(cfg)
}

func (s *service) reconcileConfig(cfg *config.Config) {
	if s.pool == nil {
		return
	}
	want := map[string]string{}
	for alias, h := range cfg.Index() {
		if h.Host != nil {
			want[alias] = cfg.SessionFingerprint(h)
		}
	}
	s.pool.Retain(want)
}

func (s *service) dialResolved(ctx context.Context, h config.ResolvedHost) (*sshclient.Client, error) {
	if h.Host == nil {
		return nil, fmt.Errorf("host %s is missing", h.Alias)
	}
	if strings.TrimSpace(h.Host.Via) == "" {
		return s.dialDirect(ctx, h)
	}
	return s.dialVia(ctx, h)
}

// dialDirect is one TCP connection to the saved address. Pool reuse, SFTP,
// and the terminal PTY all share that client. A host without via never
// dials a jump host.
func (s *service) dialDirect(ctx context.Context, h config.ResolvedHost) (*sshclient.Client, error) {
	auth, err := s.authMethods(h)
	if err != nil {
		return nil, err
	}
	addr := net.JoinHostPort(h.Host.Host, strconv.Itoa(h.Host.PortOrDefault()))
	kh := sshclient.HostKeyCallback(filepath.Join(s.dir, config.KnownHostsName), false)
	if ctx == nil {
		ctx = context.Background()
	}
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	c, err := sshclient.Dial(cctx, addr, h.Host.User, auth, kh, 20*time.Second)
	if err != nil {
		return nil, sshclient.Wrap(err)
	}
	return c, nil
}

// dialVia returns an SSH client whose sessions run on the destination.
// Earlier hops stay open only as direct-tcpip carriers and are closed with
// that client. The pool stores this one client under the destination alias.
func (s *service) dialVia(ctx context.Context, h config.ResolvedHost) (*sshclient.Client, error) {
	cfg, err := config.Load(s.dir)
	if err != nil {
		return nil, err
	}
	chain, err := cfg.ViaChainFrom(h)
	if err != nil {
		return nil, err
	}
	kh := sshclient.HostKeyCallback(filepath.Join(s.dir, config.KnownHostsName), false)
	hops := make([]sshclient.Hop, 0, len(chain))
	for _, hop := range chain {
		auth, err := s.authMethods(hop)
		if err != nil {
			return nil, err
		}
		hops = append(hops, sshclient.Hop{
			Name:    hop.Alias,
			Addr:    net.JoinHostPort(hop.Host.Host, strconv.Itoa(hop.Host.PortOrDefault())),
			User:    hop.Host.User,
			Auth:    auth,
			HostKey: kh,
		})
	}
	if ctx == nil {
		ctx = context.Background()
	}
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	c, err := sshclient.DialHops(cctx, hops, 20*time.Second)
	if err != nil {
		return nil, sshclient.Wrap(err)
	}
	return c, nil
}

func (s *service) authMethods(h config.ResolvedHost) ([]ssh.AuthMethod, error) {
	return sshclient.AuthForHost(s.dir, h, nil)
}

// fingerprint is the pooled session identity for h, including the resolved
// jump chain. Callers pass it to the pool; dialAlias checks the same value.
func (s *service) fingerprint(h config.ResolvedHost) string {
	cfg, err := config.Load(s.dir)
	if err != nil || cfg == nil {
		return ""
	}
	if cur, ok := cfg.Find(h.Alias); ok && cur.Host != nil {
		h = cur
	}
	return cfg.SessionFingerprint(h)
}

func (s *service) onSessionClose(alias, reason string) {
	rec := audit.Record{
		Op: audit.OpSession, Host: alias, Status: audit.StatusOK, Reason: reason, Actor: "ui", Source: audit.SourceUI,
	}
	if cfg, err := config.Load(s.dir); err == nil {
		if h, ok := cfg.Find(alias); ok {
			rec.Group = h.Group
			rec.Env = h.EnvName
		}
	}
	if _, err := audit.Append(s.dir, rec); err != nil {
		s.mu.Lock()
		s.auditCloseFailed = true
		s.mu.Unlock()
	}
}

func (s *service) openPool() *session.Pool { return s.pool }
