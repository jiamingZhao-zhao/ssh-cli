package ui

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"strconv"
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
		Op: audit.OpSession, Host: alias, Status: audit.StatusOK, Reason: reason, Actor: "ui",
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
