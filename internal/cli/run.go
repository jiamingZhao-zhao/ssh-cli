package cli

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/config"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/exitcode"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/guard"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/output"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/secrets"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/sshclient"
	"golang.org/x/crypto/ssh"
)

type planned struct {
	host config.ResolvedHost
	dec  guard.Decision
	eff  guard.Effective
}

func (a *App) loadSelection() (*config.Config, []config.ResolvedHost, error) {
	cfg, err := config.Load(a.Dir)
	if err != nil {
		return nil, nil, exitcode.New(exitcode.Usage, "%s", err.Error())
	}
	hosts, err := cfg.Select(a.selector())
	if err != nil {
		return nil, nil, exitcode.New(exitcode.Usage, "%s", err.Error())
	}
	envs := make([]string, len(hosts))
	for i, h := range hosts {
		envs[i] = h.EnvName
	}
	if guard.CrossEnv(envs) && !a.AllowCrossEnv {
		return cfg, hosts, exitcode.New(exitcode.Denied, "selection spans multiple environments; pass --allow-cross-env")
	}
	return cfg, hosts, nil
}

func (a *App) plan(cfg *config.Config, hosts []config.ResolvedHost, meta auditMeta, decide func(guard.Effective) guard.Decision) ([]planned, error) {
	envs := make([]string, len(hosts))
	for i, h := range hosts {
		envs[i] = h.EnvName
	}
	force := len(hosts) > 1 && guard.IncludesProd(envs)
	all := make([]planned, 0, len(hosts))
	for _, h := range hosts {
		eff, err := guard.Resolve(cfg, h, force)
		if err != nil {
			return nil, exitcode.New(exitcode.Usage, "%s", err.Error())
		}
		for _, w := range eff.Warnings {
			fmt.Fprintf(a.Err, "warning: %s: %s\n", h.Alias, w)
		}
		dec := decide(eff)
		all = append(all, planned{host: h, dec: dec, eff: eff})
	}
	hd := make([]guard.HostDecision, len(all))
	for i, p := range all {
		hd[i] = guard.HostDecision{Alias: p.host.Alias, Env: p.host.EnvName, Decision: p.dec}
	}
	kept, err := guard.Filter(hd, a.SkipDenied)
	if err != nil {
		for _, p := range all {
			if !p.dec.Allowed {
				a.logDenial(meta, p.host, &p.dec, "")
			}
		}
		return nil, exitcode.New(exitcode.Denied, "%s", err.Error())
	}
	keep := map[string]bool{}
	for _, k := range kept {
		keep[k.Alias] = true
	}
	var out []planned
	for _, p := range all {
		if !keep[p.host.Alias] {
			a.logDenial(meta, p.host, &p.dec, "")
			continue
		}
		out = append(out, p)
	}
	if !ttyCheck() {
		var confirmErr error
		for _, p := range out {
			if !p.dec.NeedsConfirm {
				continue
			}
			msg := fmt.Sprintf("host %s requires confirmation on an interactive TTY", p.host.Alias)
			a.logDenial(meta, p.host, &p.dec, msg)
			if confirmErr == nil {
				confirmErr = exitcode.New(exitcode.Denied, "%s", msg)
			}
		}
		if confirmErr != nil {
			return nil, confirmErr
		}
	}
	return out, nil
}

// defaultDialTimeout is the connect budget when the command does not ask for
// a shorter one. It is not extended by a longer --timeout; that budget applies
// only after the session is up.
const defaultDialTimeout = 20 * time.Second

// dialBudget bounds the TCP dial and SSH handshake. A positive command timeout
// shortens it, so --timeout 3s fails an unreachable host in about 3s instead of
// the historical 20s. The command context created after a successful dial is a
// separate budget and is not reduced here.
func dialBudget(commandTimeout time.Duration) time.Duration {
	if commandTimeout > 0 && commandTimeout < defaultDialTimeout {
		return commandTimeout
	}
	return defaultDialTimeout
}

func (a *App) dial(h config.ResolvedHost, commandTimeout time.Duration) (*sshclient.Client, error) {
	if h.Host == nil {
		return nil, exitcode.New(exitcode.Usage, "host %s is missing", h.Alias)
	}
	if strings.TrimSpace(h.Host.Via) == "" {
		return a.dialDirect(h, commandTimeout)
	}
	return a.dialVia(h, commandTimeout)
}

// dialDirect is the pre-jump path: one TCP connection and one SSH handshake.
// Hosts without via stay on this path so exec, upload, download, session, and
// relay keep the same dial errors and do not open a second config read.
func (a *App) dialDirect(h config.ResolvedHost, commandTimeout time.Duration) (*sshclient.Client, error) {
	auth, err := a.auth(h)
	if err != nil {
		return nil, err
	}
	addr := net.JoinHostPort(h.Host.Host, strconv.Itoa(h.Host.PortOrDefault()))
	kh := sshclient.HostKeyCallback(filepath.Join(a.Dir, config.KnownHostsName), a.Insecure)
	limit := dialBudget(commandTimeout)
	ctx, cancel := context.WithTimeout(context.Background(), limit)
	defer cancel()
	c, err := sshclient.Dial(ctx, addr, h.Host.User, auth, kh, limit)
	if err != nil {
		return nil, sshclient.Wrap(err)
	}
	return c, nil
}

// dialVia SSHes to the destination through already registered jump hosts.
// Each earlier hop carries only a direct-tcpip channel. The returned client
// is the destination, so exec and PTY sessions are not opened on a jump host.
func (a *App) dialVia(h config.ResolvedHost, commandTimeout time.Duration) (*sshclient.Client, error) {
	cfg, err := config.Load(a.Dir)
	if err != nil {
		return nil, exitcode.New(exitcode.Usage, "%s", err.Error())
	}
	chain, err := cfg.ViaChainFrom(h)
	if err != nil {
		return nil, exitcode.New(exitcode.Connect, "%s", err.Error())
	}
	kh := sshclient.HostKeyCallback(filepath.Join(a.Dir, config.KnownHostsName), a.Insecure)
	hops := make([]sshclient.Hop, 0, len(chain))
	for _, hop := range chain {
		auth, err := a.auth(hop)
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
	limit := dialBudget(commandTimeout)
	ctx, cancel := context.WithTimeout(context.Background(), limit)
	defer cancel()
	c, err := sshclient.DialHops(ctx, hops, limit)
	if err != nil {
		return nil, sshclient.Wrap(err)
	}
	return c, nil
}

func (a *App) auth(h config.ResolvedHost) ([]ssh.AuthMethod, error) {
	switch h.Host.Auth {
	case "key":
		if h.Host.Identity == "" {
			return nil, exitcode.New(exitcode.Usage, "host %s: auth is key but identity is empty", h.Alias)
		}
		path, err := config.ExpandHome(h.Host.Identity)
		if err != nil {
			return nil, err
		}
		method, err := sshclient.IdentityAuth(path)
		if err != nil {
			return nil, exitcode.New(exitcode.Auth, "%s", err.Error())
		}
		return []ssh.AuthMethod{method}, nil
	case "", "password":
		if h.Host.PasswordRef == "" {
			return nil, exitcode.New(exitcode.Auth, "host %s has no passwordRef", h.Alias)
		}
		st, err := secrets.Open(a.Dir, secrets.Options{Warn: a.Err})
		if err != nil {
			return nil, err
		}
		pw, err := st.Get(h.Host.PasswordRef)
		if err != nil {
			return nil, exitcode.New(exitcode.Auth, "host %s: %s", h.Alias, err.Error())
		}
		return sshclient.PasswordAuth(pw), nil
	default:
		return nil, exitcode.New(exitcode.Usage, "host %s: unsupported auth %q", h.Alias, h.Host.Auth)
	}
}

func (a *App) header(h config.ResolvedHost) {
	if a.JSON {
		return
	}
	label := h.EnvName
	color := ""
	if h.Env != nil {
		if h.Env.Label != "" {
			label = h.Env.Label
		}
		color = h.Env.Color
	}
	painted := output.Paint(output.IsTerminal(a.Err), color, label)
	line := fmt.Sprintf("[%s] %s group=%s", painted, h.Alias, h.Group)
	if h.GroupDef != nil {
		if gl := strings.TrimSpace(h.GroupDef.Label); gl != "" {
			line += " [" + gl + "]"
		}
	}
	fmt.Fprintln(a.Err, line)
}

func shellForScript(script string) string {
	if strings.HasPrefix(script, "#!") {
		line, _, _ := strings.Cut(script, "\n")
		fields := strings.Fields(strings.TrimPrefix(line, "#!"))
		if len(fields) > 0 {
			base := path.Base(fields[0])
			switch base {
			case "sh", "bash", "dash", "zsh", "ksh", "ash":
				return base + " -s"
			}
		}
	}
	return "sh -s"
}

func readScriptFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 8<<20))
	if err != nil {
		return "", err
	}
	if len(b) == 8<<20 {
		return "", fmt.Errorf("script exceeds 8MiB")
	}
	return string(b), nil
}

func preferCode(current, next int) int {
	if next == 0 {
		return current
	}
	if current == 0 || (next >= 250 && current < 250) {
		return next
	}
	return current
}
