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

func (a *App) statusCmd() *cobra.Command {
	var timeout string
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Check connectivity and basic host health",
		Long: `Check the selected hosts (the same -H / -g / -t / --env filters as exec).

status dials each host and runs a fixed set of read-only commands: hostname,
uptime, load, memory, disk, and listening ports. Every command is checked by
the policy engine before the connection opens. A host that cannot be reached
is a failed status. A probe that exits non-zero is reported on that host and
does not by itself mark the host down.

The attempt is appended to the audit log.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := a.rejectYesWithoutTTY(); err != nil {
				return err
			}
			dur, err := parseTimeout(timeout)
			if err != nil {
				return exitcode.New(exitcode.Usage, "%s", err.Error())
			}
			if dur == 0 {
				dur = 15 * time.Second
			}
			probes := remote.StatusProbes()
			meta := a.auditMeta(audit.OpStatus, remote.StatusCommand(), "", "")
			cfg, hosts, err := a.loadSelection()
			if err != nil {
				a.auditSelectionError(meta, hosts, err)
				return err
			}
			plan, err := a.plan(cfg, hosts, meta, func(eff guard.Effective) guard.Decision {
				parts := make([]guard.Decision, 0, len(probes))
				for _, probe := range probes {
					parts = append(parts, guard.Decide(eff, probe.Command))
				}
				return guard.Merge(parts...)
			})
			if err != nil {
				return err
			}
			type probeView struct {
				Name     string `json:"name"`
				Command  string `json:"command"`
				ExitCode int    `json:"exitCode"`
				Stdout   string `json:"stdout,omitempty"`
				Stderr   string `json:"stderr,omitempty"`
			}
			type view struct {
				Host      string      `json:"host"`
				Group     string      `json:"group"`
				Env       string      `json:"env"`
				Connected bool        `json:"connected"`
				ExitCode  int         `json:"exitCode"`
				Error     string      `json:"error,omitempty"`
				Probes    []probeView `json:"probes,omitempty"`
			}
			views := make([]view, 0, len(plan))
			final := 0
			for _, p := range plan {
				if err := a.confirmPlanned(meta, p); err != nil {
					return err
				}
				a.header(p.host)
				start := time.Now()
				commands := make([]string, len(probes))
				for i, probe := range probes {
					commands[i] = probe.Command
				}
				outputs, runErr := a.runCommands(p, commands, dur)
				v := view{Host: p.host.Alias, Group: p.host.Group, Env: p.host.EnvName}
				var summaryParts []string
				if runErr != nil {
					v.Error = runErr.Error()
					v.ExitCode = exitcode.From(runErr)
					v.Connected = false
					fmt.Fprintf(a.Err, "error: %s: %s\n", p.host.Alias, runErr.Error())
				} else {
					v.Connected = true
					v.ExitCode = 0
				}
				for i, probe := range probes {
					pv := probeView{Name: probe.Name, Command: probe.Command}
					if i < len(outputs) {
						pv.ExitCode = outputs[i].ExitCode
						pv.Stdout = outputs[i].Stdout
						pv.Stderr = outputs[i].Stderr
						if !a.JSON {
							fmt.Fprintf(a.Out, "[%s]\n", probe.Name)
							if pv.Stdout != "" {
								fmt.Fprint(a.Out, pv.Stdout)
								if !strings.HasSuffix(pv.Stdout, "\n") {
									fmt.Fprintln(a.Out)
								}
							}
							if pv.ExitCode != 0 {
								fmt.Fprintf(a.Err, "%s: exit %d\n", probe.Name, pv.ExitCode)
								if pv.Stderr != "" {
									fmt.Fprint(a.Err, pv.Stderr)
								}
							}
						}
						line := probe.Name + ": " + oneLine(pv.Stdout)
						if pv.ExitCode != 0 {
							line += fmt.Sprintf(" (exit %d)", pv.ExitCode)
						}
						summaryParts = append(summaryParts, line)
					}
					v.Probes = append(v.Probes, pv)
				}
				summary := joinSummary(summaryParts)
				if err := a.auditHost(meta, p, start, v.ExitCode, runErr, summary); err != nil {
					return err
				}
				views = append(views, v)
				if runErr != nil {
					final = preferCode(final, v.ExitCode)
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
		},
	}
	cmd.Flags().StringVar(&timeout, "timeout", "", "per-command timeout (duration or seconds; default 15s)")
	return cmd
}
