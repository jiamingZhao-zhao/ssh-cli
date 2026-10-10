package cli

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/audit"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/exitcode"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/guard"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/history"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/sshclient"
)

func (a *App) historyCmd() *cobra.Command {
	var timeout string
	var lines int
	var allowOutflow bool
	cmd := &cobra.Command{
		Use:   "history",
		Short: "Read remote shell history",
		Long: `history reads the remote login user's shell history over the selected hosts.

It is best-effort and read-only. A short cat of common rc files looks for a
static HISTFILE. Otherwise it tries ~/.bash_history, ~/.zsh_history, and
~/.local/share/fish/fish_history. Missing files, an unreadable file, or a
shell this command does not understand return an empty result. They do not
crash the process.

The read uses cat and tail only. It does not write, truncate, or rewrite the
history file. Output is the last N commands (default 100, maximum 500) and at
most 64KiB. Obvious secrets are redacted with the audit-log patterns
(password=, token=, PEM private keys, secret flags, URL userinfo). Other
secrets, including short flags such as -p, can still appear. History text may
contain secrets.

noDataOutflow discards the lines unless --allow-outflow is set and confirmed.
The attempt is audited as op history with source cli.

Fish stores commands as "- cmd:" lines. zsh extended history timestamps and
bash history timestamps are stripped. Multiline commands and history from
shells other than bash, zsh, and fish are not reconstructed.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return a.readHistory(timeout, lines, allowOutflow)
		},
	}
	cmd.Flags().StringVar(&timeout, "timeout", "", "per-command timeout (duration or seconds; default 15s); also bounds SSH connect")
	cmd.Flags().IntVar(&lines, "lines", 0, "number of commands to keep (default 100, maximum 500)")
	cmd.Flags().BoolVar(&allowOutflow, "allow-outflow", false, "return history lines from a noDataOutflow env; requires typing outflow")
	return cmd
}

func (a *App) readHistory(timeout string, lines int, allowOutflow bool) error {
	if err := a.rejectYesWithoutTTY(); err != nil {
		return err
	}
	n, err := history.ClampLines(lines)
	if err != nil {
		return exitcode.New(exitcode.Usage, "%s", err.Error())
	}
	dur, err := parseTimeout(timeout)
	if err != nil {
		return exitcode.New(exitcode.Usage, "%s", err.Error())
	}
	if dur == 0 {
		dur = 15 * time.Second
	}
	cmds, err := history.PlannedCommands(n)
	if err != nil {
		return exitcode.New(exitcode.Usage, "%s", err.Error())
	}
	meta := a.auditMeta(audit.OpHistory, strings.Join(cmds, "; "), "", "")
	cfg, hosts, err := a.loadSelection()
	if err != nil {
		a.auditSelectionError(meta, hosts, err)
		return err
	}
	plan, err := a.plan(cfg, hosts, meta, func(eff guard.Effective) guard.Decision {
		return history.PolicyDecision(eff, n)
	})
	if err != nil {
		return err
	}
	type view struct {
		Host      string   `json:"host"`
		Group     string   `json:"group"`
		Env       string   `json:"env"`
		Found     bool     `json:"found"`
		Status    string   `json:"status"`
		Path      string   `json:"path,omitempty"`
		Shell     string   `json:"shell,omitempty"`
		Lines     []string `json:"lines"`
		Truncated bool     `json:"truncated,omitempty"`
		Notes     []string `json:"notes,omitempty"`
		Error     string   `json:"error,omitempty"`
	}
	views := make([]view, 0, len(plan))
	final := 0
	for _, p := range plan {
		if err := a.confirmPlanned(meta, p); err != nil {
			return err
		}
		suppress, needsOut := guard.ExecOutflow(p.eff.NoDataOut, allowOutflow)
		if needsOut {
			if err := confirmOutflow(a.Yes); err != nil {
				return err
			}
		}
		a.header(p.host)
		start := time.Now()
		client, dialErr := a.dial(p.host, dur)
		v := view{Host: p.host.Alias, Group: p.host.Group, Env: p.host.EnvName, Lines: []string{}, Status: "empty"}
		var res history.Result
		var runErr error
		if dialErr != nil {
			runErr = dialErr
			v.Error = dialErr.Error()
			v.Status = "error"
		} else {
			res, runErr = history.Collect(context.Background(), func(ctx context.Context, command string) (string, string, int, error) {
				return runRemote(ctx, client, command, dur)
			}, func(command string) error {
				dec := guard.Decide(p.eff, command)
				if !dec.Allowed {
					return fmt.Errorf("%s", decisionReason(dec))
				}
				return nil
			}, history.Options{Lines: n})
			_ = client.Close()
			if runErr != nil {
				v.Error = runErr.Error()
				v.Status = "error"
			} else {
				v.Found = res.Found
				v.Status = res.Status
				v.Path = res.Path
				v.Shell = res.Shell
				v.Truncated = res.Truncated
				v.Notes = res.Notes
				v.Error = res.Error
				v.Lines = res.Lines
				if suppress {
					v.Lines = []string{}
					v.Notes = append(v.Notes, guard.OutflowDiscarded)
				}
			}
		}
		if !a.JSON {
			if v.Error != "" && runErr != nil {
				fmt.Fprintf(a.Err, "error: %s: %s\n", p.host.Alias, v.Error)
			} else if v.Status != "ok" {
				fmt.Fprintf(a.Out, "%s: %s\n", v.Status, emptyDash(v.Error))
				for _, note := range v.Notes {
					fmt.Fprintf(a.Err, "note: %s\n", note)
				}
			} else {
				fmt.Fprintf(a.Out, "# %s (%s)", v.Path, v.Shell)
				if v.Truncated {
					fmt.Fprint(a.Out, " truncated")
				}
				fmt.Fprintln(a.Out)
				if suppress {
					fmt.Fprintln(a.Out, guard.OutflowDiscarded)
				} else {
					for _, line := range v.Lines {
						fmt.Fprintln(a.Out, line)
					}
				}
			}
		}
		summary := historySummary(v.Status, v.Path, v.Shell, v.Lines, v.Error)
		if suppress {
			summary = guard.OutflowDiscarded
		}
		code := 0
		if runErr != nil {
			code = exitcode.From(runErr)
		}
		if err := a.auditHost(meta, p, start, code, runErr, summary); err != nil {
			return err
		}
		views = append(views, v)
		if runErr != nil {
			final = preferCode(final, code)
		}
	}
	if a.JSON {
		if err := a.emit(map[string]any{"results": views}); err != nil {
			return err
		}
	}
	if final != 0 {
		return exitcode.Silent(final)
	}
	return nil
}

func runRemote(ctx context.Context, client *sshclient.Client, command string, timeout time.Duration) (string, string, int, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	var stdout, stderr bytes.Buffer
	code, err := client.Run(ctx, command, &limitedBuf{buf: &stdout, n: 1 << 20}, &limitedBuf{buf: &stderr, n: 64 << 10}, nil)
	if err != nil {
		return stdout.String(), stderr.String(), code, sshWrapRun(err)
	}
	return stdout.String(), stderr.String(), code, nil
}

type limitedBuf struct {
	buf *bytes.Buffer
	n   int
}

func (b *limitedBuf) Write(p []byte) (int, error) {
	if b.buf.Len() >= b.n {
		return len(p), nil
	}
	remain := b.n - b.buf.Len()
	if len(p) > remain {
		_, _ = b.buf.Write(p[:remain])
		return len(p), nil
	}
	return b.buf.Write(p)
}

func historySummary(status, path, shell string, lines []string, errText string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "status=%s", status)
	if path != "" {
		fmt.Fprintf(&b, " path=%s", path)
	}
	if shell != "" {
		fmt.Fprintf(&b, " shell=%s", shell)
	}
	fmt.Fprintf(&b, " lines=%d", len(lines))
	if errText != "" {
		fmt.Fprintf(&b, " error=%s", errText)
	}
	if len(lines) > 0 {
		b.WriteByte('\n')
		b.WriteString(strings.Join(lines, "\n"))
	}
	return b.String()
}
