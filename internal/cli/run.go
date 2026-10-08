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

	"github.com/jiamingZhao-zhao/ssh-cli/internal/audit"
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
		return nil, nil, exitcode.New(exitcode.Denied, "selection spans multiple environments; pass --allow-cross-env")
	}
	return cfg, hosts, nil
}

func (a *App) plan(cfg *config.Config, hosts []config.ResolvedHost, decide func(guard.Effective) guard.Decision) ([]planned, error) {
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
		return nil, exitcode.New(exitcode.Denied, "%s", err.Error())
	}
	keep := map[string]bool{}
	for _, k := range kept {
		keep[k.Alias] = true
	}
	var out []planned
	for _, p := range all {
		if keep[p.host.Alias] {
			out = append(out, p)
		}
	}
	for _, p := range out {
		if p.dec.NeedsConfirm && !ttyCheck() {
			return nil, exitcode.New(exitcode.Denied, "host %s requires confirmation on an interactive TTY", p.host.Alias)
		}
	}
	return out, nil
}

func (a *App) dial(h config.ResolvedHost) (*sshclient.Client, error) {
	auth, err := a.auth(h)
	if err != nil {
		return nil, err
	}
	addr := net.JoinHostPort(h.Host.Host, strconv.Itoa(h.Host.PortOrDefault()))
	kh := sshclient.HostKeyCallback(filepath.Join(a.Dir, config.KnownHostsName), a.Insecure)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	c, err := sshclient.Dial(ctx, addr, h.Host.User, auth, kh, 20*time.Second)
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
	fmt.Fprintf(a.Err, "[%s] %s group=%s\n", painted, h.Alias, h.Group)
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

func ruleOf(dec guard.Decision) string {
	if len(dec.Findings) == 0 {
		return ""
	}
	f := dec.Findings[0]
	return f.Layer + ":" + f.Kind + ":" + f.Detail
}

func record(h config.ResolvedHost, command, rule string, code int) {
	audit.Log.Record(audit.Event{
		Time: time.Now().UTC(), Env: h.EnvName, Group: h.Group, Host: h.Alias,
		Command: command, Rule: rule, ExitCode: code,
	})
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
