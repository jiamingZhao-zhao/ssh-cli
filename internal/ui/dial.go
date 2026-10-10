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
	"github.com/jiamingZhao-zhao/ssh-cli/internal/secrets"
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
	if h.Host == nil || h.Host.ConnFingerprint() != fingerprint {
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
	want := map[string]string{}
	for alias, h := range cfg.Index() {
		if h.Host != nil {
			want[alias] = h.Host.ConnFingerprint()
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
	switch h.Host.Auth {
	case "key":
		if h.Host.Identity == "" {
			return nil, fmt.Errorf("host %s: auth is key but identity is empty", h.Alias)
		}
		path, err := config.ExpandHome(h.Host.Identity)
		if err != nil {
			return nil, err
		}
		method, err := sshclient.IdentityAuth(path)
		if err != nil {
			return nil, err
		}
		return []ssh.AuthMethod{method}, nil
	case "", "password":
		if h.Host.PasswordRef == "" {
			return nil, fmt.Errorf("host %s has no passwordRef", h.Alias)
		}
		st, err := secrets.Open(s.dir, secrets.Options{})
		if err != nil {
			return nil, err
		}
		pw, err := st.Get(h.Host.PasswordRef)
		if err != nil {
			return nil, fmt.Errorf("host %s: %s", h.Alias, err.Error())
		}
		return sshclient.PasswordAuth(pw), nil
	default:
		return nil, fmt.Errorf("host %s: unsupported auth %q", h.Alias, h.Host.Auth)
	}
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
	_, _ = audit.Append(s.dir, rec)
}

func (s *service) openPool() *session.Pool { return s.pool }
