package cli

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/audit"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/exitcode"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/metrics"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/remote"
	"github.com/spf13/cobra"
)

type statusProbe struct {
	Name string `json:"name"`
	commandOutput
}
type statusView struct {
	Host             string         `json:"host"`
	Group            string         `json:"group"`
	Env              string         `json:"env"`
	Connected        bool           `json:"connected"`
	Complete         bool           `json:"complete"`
	StdoutSuppressed bool           `json:"stdoutSuppressed,omitempty"`
	ExitCode         int            `json:"exitCode"`
	Error            string         `json:"error,omitempty"`
	Guidance         *guidance      `json:"guidance,omitempty"`
	Warnings         []string       `json:"warnings,omitempty"`
	Facts            map[string]any `json:"facts"`
	Notes            []string       `json:"notes"`
	Probes           []statusProbe  `json:"probes"`
}

func (a *App) statusCmd() *cobra.Command {
	var timeout, total string
	var parallel int
	cmd := &cobra.Command{Use: "status", Short: "Check connectivity and basic host health", Args: cobra.NoArgs,
		Long: `Check selected hosts with bounded read-only probes. Raw probes remain available;
facts contains parsed hostname, load, memory bytes and disks when complete data
is available. Missing, failed or truncated probes are noted, never filled as zero.
All targets are checked before dispatch. Up to 4 hosts run concurrently (16 max).
--total-timeout includes queueing, connection and commands, and retains partial
results. A nonzero probe does not mean the host is offline; inspect complete,
probes[].exitCode and outcome. --agent-mode reuses eligible readonly connections.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
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
			probes := remote.StatusProbes()
			commands := make([]string, len(probes))
			for i, p := range probes {
				commands[i] = p.Command
			}
			results, err := a.collectQueries(audit.OpStatus, commands, dur, budget, parallel, true)
			if err != nil {
				return err
			}
			views := make([]statusView, len(results))
			for i, r := range results {
				v := statusView{Host: r.Host, Group: r.Group, Env: r.Env, Connected: r.Connected, Complete: r.Complete, StdoutSuppressed: r.StdoutSuppressed, Error: r.Error, Guidance: r.Guidance, Warnings: r.Warnings, Facts: map[string]any{}, Notes: []string{}, Probes: []statusProbe{}}
				// Preserve status's existing contract: individual unavailable probes
				// mark the snapshot incomplete, not the connection or CLI as failed.
				if r.Error != "" {
					v.ExitCode = r.ExitCode
				}
				for j, c := range r.Commands {
					v.Probes = append(v.Probes, statusProbe{Name: probes[j].Name, commandOutput: c})
					if c.Outcome != "completed" || c.ExitCode != 0 || c.Truncated || r.StdoutSuppressed {
						v.Complete = false
						v.Notes = append(v.Notes, probes[j].Name+": unavailable, failed, suppressed or truncated; inspect raw probe")
						continue
					}
					if !parseStatusFact(v.Facts, probes[j].Name, c.Stdout) {
						v.Complete = false
						v.Notes = append(v.Notes, probes[j].Name+": format not recognized; inspect raw probe")
					}
				}
				views[i] = v
			}
			if a.JSON {
				if err := a.emit(map[string]any{"results": views}); err != nil {
					return err
				}
			} else {
				a.printQueries(results)
				for _, v := range views {
					for _, note := range v.Notes {
						fmt.Fprintf(a.Err, "%s: %s\n", v.Host, note)
					}
				}
			}
			final := 0
			for _, v := range views {
				final = preferCode(final, v.ExitCode)
			}
			if final != 0 {
				return exitcode.Silent(final)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&timeout, "timeout", "", "per-command timeout (default 15s); also bounds SSH connect")
	cmd.Flags().StringVar(&total, "total-timeout", "", "total budget including queue and SSH connect (default 30s)")
	cmd.Flags().IntVar(&parallel, "parallel", 4, "hosts checked concurrently (1-4; at most 16 hosts)")
	return cmd
}

func parseStatusFact(facts map[string]any, name, text string) bool {
	if strings.TrimSpace(text) == "" {
		return false
	}
	switch name {
	case "hostname":
		facts["hostname"] = strings.TrimSpace(text)
	case "uptime":
		facts["uptime"] = strings.TrimSpace(text)
	case "load":
		fields := strings.Fields(text)
		if len(fields) < 3 {
			return false
		}
		load := make([]float64, 3)
		for i := range load {
			n, err := strconv.ParseFloat(fields[i], 64)
			if err != nil || n < 0 {
				return false
			}
			load[i] = n
		}
		facts["loadAverage"] = load
	case "memory":
		mem, swap, ok := metrics.ParseFree(text)
		if !ok || mem.Used > mem.Total {
			return false
		}
		memory := map[string]any{"totalBytes": mem.Total, "usedBytes": mem.Used, "usedPercent": mem.Percent}
		for _, line := range strings.Split(text, "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 7 && strings.EqualFold(strings.TrimSuffix(fields[0], ":"), "mem") {
				if avail, err := strconv.ParseUint(fields[6], 10, 64); err == nil && avail <= mem.Total {
					memory["availableBytes"] = avail
				}
			}
			if len(fields) >= 3 && strings.EqualFold(strings.TrimSuffix(fields[0], ":"), "swap") {
				facts["swap"] = map[string]any{"totalBytes": swap.Total, "usedBytes": swap.Used, "usedPercent": swap.Percent}
			}
		}
		facts["memory"] = memory
	case "disk":
		facts["disks"] = metrics.ParseDF(text)
		facts["diskLimit"] = 8
	case "listen":
		facts["listeningPortsRaw"] = strings.TrimSpace(text)
	default:
		return false
	}
	return true
}
