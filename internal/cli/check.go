package cli

import (
	"github.com/jiamingZhao-zhao/ssh-cli/internal/audit"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/exitcode"
	"github.com/spf13/cobra"
	"strings"
	"time"
)

func (a *App) checkCmd() *cobra.Command {
	var commands []string
	var timeout, total, tcp string
	var parallel int
	cmd := &cobra.Command{Use: "check", Short: "Run independent readonly checks with separate results", Args: cobra.NoArgs,
		Long: `Submit 1..16 --command values. Each runs in its own shell; cd, variables
and exports do not carry to the next command. Every command is checked against
the current policy AND the builtin readonly ceiling, even in standard/admin.
The full batch is checked before any SSH dispatch; --skip-denied skips a whole
host, never a denied command. Nonzero exits retain results; transport failure
leaves later commands not_started. No command is automatically replayed.
--agent-mode selects bounded JSON output and automatic eligible readonly reuse.

Alternatively --tcp checks a single IP:port from the one explicitly selected
SSH host. The destination must be loopback or a registered inventory address.
It uses the SSH server's connection channel, sends no application data and
requires the same policy permission as a bounded nc query.`,
		Example: `  ssh-cli check -H app-a -H app-b --agent-mode --command "ss -tlnp" --command "jps -l"`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			for _, c := range commands {
				if strings.TrimSpace(c) == "" {
					return exitcode.New(exitcode.Usage, "empty command")
				}
			}
			dur, err := parseTimeout(timeout)
			if err != nil {
				return exitcode.New(exitcode.Usage, "%s", err)
			}
			if dur == 0 {
				dur = 15 * time.Second
			}
			budget, err := parseTimeout(total)
			if err != nil {
				return exitcode.New(exitcode.Usage, "%s", err)
			}
			if budget == 0 {
				budget = 30 * time.Second
			}
			if cmd.Flags().Changed("tcp") {
				if len(commands) != 0 {
					return exitcode.New(exitcode.Usage, "--tcp cannot be combined with --command")
				}
				return a.runTCPCheck(tcp, min(dur, 5*time.Second), budget)
			}
			results, err := a.collectQueries(audit.OpExec, commands, dur, budget, parallel, true)
			if err != nil {
				return err
			}
			if a.JSON {
				if err := a.emit(map[string]any{"results": results}); err != nil {
					return err
				}
			} else {
				a.printQueries(results)
			}
			return queryExit(results)
		},
	}
	cmd.Flags().StringArrayVar(&commands, "command", nil, "independent readonly command (repeatable; at most 16)")
	cmd.Flags().StringVar(&tcp, "tcp", "", "connect-only TCP check from one -H host to a registered IP:port (max 5s)")
	cmd.Flags().StringVar(&timeout, "timeout", "", "per-command and SSH connect timeout (default 15s)")
	cmd.Flags().StringVar(&total, "total-timeout", "", "whole batch budget including queue and connect (default 30s)")
	cmd.Flags().IntVar(&parallel, "parallel", 4, "concurrent hosts (1-4; at most 16 hosts)")
	return cmd
}
