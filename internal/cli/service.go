package cli

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/audit"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/exitcode"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/guard"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/remote"
)

func (a *App) serviceCmd() *cobra.Command {
	var timeout string
	cmd := &cobra.Command{
		Use:   "service <action> <name>",
		Short: "Check or change a remote service",
		Long: `Run systemctl <action> <name> on the selected hosts.

Actions: status, start, stop, restart, reload. The service name must match
^[A-Za-z0-9][A-Za-z0-9@._+-]{0,127}$. The command goes through the same
policy engine as exec, including the service capability (readonly allows
status) and confirm rules (restart and stop on the standard policy). There
is no separate supervisor.

The attempt is appended to the audit log.`,
		Example: `  ssh-cli service -H main status nginx
  ssh-cli service -H main restart nginx`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := a.rejectYesWithoutTTY(); err != nil {
				return err
			}
			command, err := remote.ServiceCommand(args[0], args[1])
			if err != nil {
				return exitcode.New(exitcode.Usage, "%s", err.Error())
			}
			dur, err := parseTimeout(timeout)
			if err != nil {
				return exitcode.New(exitcode.Usage, "%s", err.Error())
			}
			if dur == 0 {
				dur = 30 * time.Second
			}
			action := strings.TrimSpace(args[0])
			meta := a.auditMeta(audit.OpService, command, "", "")
			cfg, hosts, err := a.loadSelection()
			if err != nil {
				a.auditSelectionError(meta, hosts, err)
				return err
			}
			plan, err := a.plan(cfg, hosts, meta, func(eff guard.Effective) guard.Decision {
				return guard.Merge(guard.DecideService(eff, action), guard.Decide(eff, command))
			})
			if err != nil {
				return err
			}
			type view struct {
				Host     string `json:"host"`
				Group    string `json:"group"`
				Env      string `json:"env"`
				Action   string `json:"action"`
				Service  string `json:"service"`
				Command  string `json:"command"`
				ExitCode int    `json:"exitCode"`
				Stdout   string `json:"stdout,omitempty"`
				Stderr   string `json:"stderr,omitempty"`
				Error    string `json:"error,omitempty"`
			}
			views := make([]view, 0, len(plan))
			final := 0
			for _, p := range plan {
				if err := a.confirmPlanned(meta, p); err != nil {
					return err
				}
				a.header(p.host)
				start := time.Now()
				outputs, runErr := a.runCommands(p, []string{command}, dur)
				v := view{
					Host: p.host.Alias, Group: p.host.Group, Env: p.host.EnvName,
					Action: action, Service: strings.TrimSpace(args[1]), Command: command,
				}
				summary := ""
				if runErr != nil {
					v.Error = runErr.Error()
					v.ExitCode = exitcode.From(runErr)
					fmt.Fprintf(a.Err, "error: %s: %s\n", p.host.Alias, runErr.Error())
					summary = runErr.Error()
				} else if len(outputs) > 0 {
					v.ExitCode = outputs[0].ExitCode
					v.Stdout = outputs[0].Stdout
					v.Stderr = outputs[0].Stderr
					summary = summarizeOutputs(outputs[0].Stdout, outputs[0].Stderr, false, "")
					if !a.JSON {
						fmt.Fprint(a.Out, outputs[0].Stdout)
						fmt.Fprint(a.Err, outputs[0].Stderr)
					}
				}
				if err := a.auditHost(meta, p, start, v.ExitCode, runErr, summary); err != nil {
					return err
				}
				views = append(views, v)
				final = preferCode(final, v.ExitCode)
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
		},
	}
	cmd.Flags().StringVar(&timeout, "timeout", "", "command timeout (duration or seconds; default 30s); also bounds SSH connect")
	return cmd
}
