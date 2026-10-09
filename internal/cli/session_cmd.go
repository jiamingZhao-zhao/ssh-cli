package cli

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/audit"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/config"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/exitcode"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/guard"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/session"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/sshclient"
)

func (a *App) sessionCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "session",
		Short: "Reuse one SSH shell inside this process",
		Long: `Sessions stay inside the process that opened them. ssh-cli does not
start a background daemon. Idle auto-close defaults to 5m and max lifetime
defaults to 60m; max lifetime wins even while a command is running.
Process exit closes every session this process still holds.

session run keeps one shell for repeated --command values, then closes it.
Separate session list/open/close processes do not see that shell.`,
	}
	cmd.AddCommand(a.sessionRun(), a.sessionList(), a.sessionOpen(), a.sessionClose())
	return cmd
}

func (a *App) sessionRun() *cobra.Command {
	var commands []string
	var idle, maxLife string
	var allowOutflow bool
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Run commands in one persistent shell, then close it",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := a.rejectYesWithoutTTY(); err != nil {
				return err
			}
			if len(commands) == 0 {
				return exitcode.New(exitcode.Usage, "pass at least one --command")
			}
			return a.sessionRunCommands(commands, idle, maxLife, allowOutflow)
		},
	}
	cmd.Flags().StringArrayVar(&commands, "command", nil, "remote command (repeatable; shares one shell)")
	cmd.Flags().StringVar(&idle, "idle", "", "idle auto-close (default 5m)")
	cmd.Flags().StringVar(&maxLife, "max-life", "", "hard session cap (default 60m)")
	cmd.Flags().BoolVar(&allowOutflow, "allow-outflow", false, "return stdout and stderr from a noDataOutflow env; requires typing outflow")
	return cmd
}

func (a *App) sessionList() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List sessions owned by this process",
		Long:  "A separate ssh-cli process has its own pool. This command does not attach to ssh-cli ui.",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintln(a.Out, "no sessions in this process")
			fmt.Fprintln(a.Err, "sessions live only in the process that opened them (session run, or ssh-cli ui)")
			return nil
		},
	}
}

func (a *App) sessionOpen() *cobra.Command {
	return &cobra.Command{
		Use:   "open <alias>",
		Short: "Open a session in a long-running process",
		RunE: func(cmd *cobra.Command, args []string) error {
			return exitcode.New(exitcode.Usage, "session open needs a long-running process; use session run or ssh-cli ui")
		},
	}
}

func (a *App) sessionClose() *cobra.Command {
	return &cobra.Command{
		Use:   "close <alias>",
		Short: "Close a session in a long-running process",
		RunE: func(cmd *cobra.Command, args []string) error {
			return exitcode.New(exitcode.Usage, "session close needs a long-running process; use session run or ssh-cli ui")
		},
	}
}

func (a *App) sessionRunCommands(commands []string, idleRaw, maxRaw string, allowOutflow bool) error {
	cfg, hosts, err := a.loadSelection()
	if err != nil {
		return err
	}
	if len(hosts) != 1 {
		return exitcode.New(exitcode.Usage, "session run targets one host")
	}
	host := hosts[0]
	eff, err := guard.Resolve(cfg, host, false)
	if err != nil {
		return exitcode.New(exitcode.Usage, "%s", err.Error())
	}
	idle := idleRaw
	maxLife := maxRaw
	if cfg.Session != nil {
		if idle == "" {
			idle = cfg.Session.Idle
		}
		if maxLife == "" {
			maxLife = cfg.Session.MaxLife
		}
	}
	idleD, err := session.ParseWindow(idle, session.DefaultIdle)
	if err != nil {
		return exitcode.New(exitcode.Usage, "%s", err.Error())
	}
	maxD, err := session.ParseWindow(maxLife, session.DefaultMaxLife)
	if err != nil {
		return exitcode.New(exitcode.Usage, "%s", err.Error())
	}
	fp := host.Host.ConnFingerprint()
	pool, err := session.New(idleD, maxD, func(ctx context.Context, alias, got string) (*sshclient.Client, error) {
		if got != fp {
			return nil, fmt.Errorf("session %s connection identity changed", alias)
		}
		return a.dial(host, 0)
	}, func(alias, reason string) {
		a.auditSession(host, reason, audit.StatusOK)
	})
	if err != nil {
		return err
	}
	defer pool.Shutdown()
	ctx, cancel := context.WithTimeout(context.Background(), maxD)
	defer cancel()
	if err := pool.Open(ctx, host.Alias, fp, false); err != nil {
		return exitcode.New(exitcode.Connect, "%s", err.Error())
	}
	a.auditSession(host, "open", audit.StatusOK)
	suppress, needsOut := guard.ExecOutflow(eff.NoDataOut, allowOutflow)
	if needsOut {
		if err := confirmOutflow(a.Yes); err != nil {
			return err
		}
	}
	for _, command := range commands {
		dec := guard.Decide(eff, command)
		meta := a.auditMeta(audit.OpExec, command, "", "")
		if !dec.Allowed {
			a.logDenial(meta, host, &dec, "")
			return exitcode.New(exitcode.Denied, "%s", decisionReason(dec))
		}
		if dec.NeedsConfirm {
			if err := confirmAlias(host.Alias, a.Yes); err != nil {
				a.logDenial(meta, host, &dec, err.Error())
				return err
			}
		}
		start := time.Now()
		var stdout, stderr io.Writer
		var outBuf, errBuf strings.Builder
		if suppress {
			stdout, stderr = io.Discard, io.Discard
		} else {
			stdout, stderr = &outBuf, &errBuf
		}
		code, err := pool.Exec(ctx, host.Alias, fp, command, stdout, stderr)
		if suppress {
			fmt.Fprintln(a.Err, guard.OutflowDiscarded)
		} else {
			if outBuf.Len() > 0 {
				fmt.Fprint(a.Out, outBuf.String())
			}
			if errBuf.Len() > 0 {
				fmt.Fprint(a.Err, errBuf.String())
			}
		}
		meta.started = start
		if err != nil {
			if logErr := a.logRemote(meta, host, dec, audit.StatusError, exitcode.Connect, err.Error(), err.Error()); logErr != nil {
				return logErr
			}
			return exitcode.New(exitcode.Connect, "%s", err.Error())
		}
		if logErr := a.logRemote(meta, host, dec, audit.StatusOK, code, "session exec", ""); logErr != nil {
			return logErr
		}
		if code != 0 {
			return exitcode.New(code, "remote status %d", code)
		}
	}
	return nil
}

func (a *App) auditSession(h config.ResolvedHost, reason, status string) {
	_, _ = audit.Append(a.Dir, audit.Record{
		Op:     audit.OpSession,
		Host:   h.Alias,
		Group:  h.Group,
		Env:    h.EnvName,
		Status: status,
		Reason: reason,
		Actor:  audit.Actor(),
		Source: audit.SourceCLI,
	})
}
