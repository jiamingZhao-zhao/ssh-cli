package sshclient

import (
	"io"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/config"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/exitcode"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/secrets"
	"golang.org/x/crypto/ssh"
)

// AuthForHost resolves local credentials without fallback or agent forwarding.
func AuthForHost(dir string, h config.ResolvedHost, warn io.Writer) ([]ssh.AuthMethod, error) {
	if h.Host == nil {
		return nil, exitcode.New(exitcode.Usage, "host %s is missing", h.Alias)
	}
	switch h.Host.Auth {
	case "agent":
		method, err := AgentAuth(h.Host.AgentKey)
		if err != nil {
			return nil, exitcode.New(exitcode.Auth, "%s", err.Error())
		}
		return []ssh.AuthMethod{method}, nil
	case "key":
		if h.Host.Identity == "" {
			return nil, exitcode.New(exitcode.Usage, "host %s: auth is key but identity is empty", h.Alias)
		}
		path, err := config.ExpandHome(h.Host.Identity)
		if err != nil {
			return nil, err
		}
		method, err := IdentityAuth(path)
		if err != nil {
			return nil, exitcode.New(exitcode.Auth, "%s", err.Error())
		}
		return []ssh.AuthMethod{method}, nil
	case "", "password":
		if h.Host.PasswordRef == "" {
			return nil, exitcode.New(exitcode.Auth, "host %s has no passwordRef", h.Alias)
		}
		st, err := secrets.Open(dir, secrets.Options{Warn: warn})
		if err != nil {
			return nil, err
		}
		pw, err := st.Get(h.Host.PasswordRef)
		if err != nil {
			return nil, exitcode.New(exitcode.Auth, "host %s: %s", h.Alias, err.Error())
		}
		return PasswordAuth(pw), nil
	default:
		return nil, exitcode.New(exitcode.Usage, "host %s: unsupported auth %q", h.Alias, h.Host.Auth)
	}
}
