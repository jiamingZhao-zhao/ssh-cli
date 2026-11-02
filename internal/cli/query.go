package cli

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/exitcode"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/guard"
)

type queryResult struct {
	Host             string          `json:"host"`
	Group            string          `json:"group"`
	Env              string          `json:"env"`
	Connected        bool            `json:"connected"`
	Complete         bool            `json:"complete"`
	StdoutSuppressed bool            `json:"stdoutSuppressed,omitempty"`
	ExitCode         int             `json:"exitCode"`
	Error            string          `json:"error,omitempty"`
	Guidance         *guidance       `json:"guidance,omitempty"`
	Warnings         []string        `json:"warnings,omitempty"`
	Commands         []commandOutput `json:"commands"`
}

// Admit every command on every host before dispatch. Parallel workers only
// collect; output and audit are serialized after joining, keeping JSON valid.
func (a *App) collectQueries(op string, commands []string, perCommand, total time.Duration, parallel int, readonly bool) ([]queryResult, error) {
	if len(commands) == 0 || len(commands) > 16 {
		return nil, exitcode.New(exitcode.Usage, "provide 1..16 commands")
	}
	if parallel < 1 || parallel > guard.MaxParallel {
		return nil, exitcode.New(exitcode.Usage, "--parallel must be from 1 to %d", guard.MaxParallel)
	}
	if perCommand <= 0 || total <= 0 {
		return nil, exitcode.New(exitcode.Usage, "query timeouts must be positive")
	}
	meta := a.auditMeta(op, strings.Join(commands, "; "), "", "")
	cfg, hosts, err := a.loadSelection()
	if err != nil {
		a.auditSelectionError(meta, hosts, err)
		return nil, err
	}
	if len(hosts) > guard.MaxBatchHosts {
		return nil, exitcode.New(exitcode.Usage, "at most %d hosts", guard.MaxBatchHosts)
	}
	plan, err := a.plan(cfg, hosts, meta, func(eff guard.Effective) guard.Decision {
		parts := make([]guard.Decision, 0, len(commands))
		for _, c := range commands {
			if readonly {
				parts = append(parts, guard.DecideQuery(eff, c))
			} else {
				parts = append(parts, guard.Decide(eff, c))
			}
		}
		return guard.Merge(parts...)
	})
	if err != nil {
		return nil, err
	}
	for _, p := range plan {
		if err := a.confirmPlanned(meta, p); err != nil {
			return nil, err
		}
	}
	if err := a.prepareQueryReuse(plan); err != nil {
		return nil, err
	}
	ctx := a.OperationContext
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, total)
	defer cancel()
	results := make([]queryResult, len(plan))
	errors := make([]error, len(plan))
	started := make([]time.Time, len(plan))
	slots := make(chan struct{}, parallel)
	var wg sync.WaitGroup
	for i, p := range plan {
		wg.Add(1)
		go func(i int, p planned) {
			defer wg.Done()
			res := queryResult{Host: p.host.Alias, Group: p.host.Group, Env: p.host.EnvName, Commands: []commandOutput{}, StdoutSuppressed: p.eff.NoDataOut}
			started[i] = time.Now()
			select {
			case slots <- struct{}{}:
				defer func() { <-slots }()
				op := a.queryCopy(ctx)
				// Each host has private buffers, including daemon warnings.
				var warnings strings.Builder
				op.Err = &warnings
				res.Commands, errors[i] = op.runCommands(p, commands, perCommand)
				if warnings.Len() > 0 {
					res.Warnings = append(res.Warnings, strings.TrimSpace(warnings.String()))
				}
			case <-ctx.Done():
				errors[i] = ctx.Err()
			}
			res.Complete = len(res.Commands) == len(commands) && errors[i] == nil
			for _, c := range res.Commands {
				res.Connected = res.Connected || c.Connection.Connected
				if c.Outcome == "completed" {
					res.ExitCode = preferCode(res.ExitCode, c.ExitCode)
				}
			}
			if errors[i] != nil {
				res.Error, res.ExitCode = errors[i].Error(), exitcode.From(errors[i])
				if res.ExitCode == exitcode.Usage {
					res.ExitCode = exitcode.Connect
				}
				hint := errorGuidance(res.ExitCode, res.Error)
				res.Guidance = &hint
			}
			// Missing probes are never silently represented as successful zeros.
			for len(res.Commands) < len(commands) {
				res.Commands = append(res.Commands, commandOutput{Command: commands[len(res.Commands)], ExitCode: exitcode.Connect, Outcome: "not_started", Error: "not started after deadline or prior transport failure", Connection: connectionInfo{Mode: "none", Outcome: "not_started"}})
			}
			results[i] = res
		}(i, p)
	}
	wg.Wait()
	for i, p := range plan {
		for _, row := range results[i].Commands {
			entry := meta
			entry.command = row.Command
			code := row.ExitCode
			var runErr error
			if row.Error != "" {
				runErr = fmt.Errorf("%s", row.Error)
			}
			if runErr != nil {
				code = exitcode.Connect
			}
			summary := summarizeOutputs(row.Stdout, row.Stderr, row.Truncated, row.Error)
			if p.eff.NoDataOut {
				summary = guard.OutflowDiscarded
			}
			if err := a.auditHost(entry, p, started[i], code, runErr, summary); err != nil {
				return results, err
			}
		}
	}
	return results, nil
}

func queryExit(results []queryResult) error {
	final := 0
	for _, r := range results {
		final = preferCode(final, r.ExitCode)
	}
	if final != 0 {
		return exitcode.Silent(final)
	}
	return nil
}

func (a *App) printQueries(results []queryResult) {
	for _, r := range results {
		fmt.Fprintf(a.Out, "[%s · %s]\n", r.Host, r.Env)
		if r.StdoutSuppressed {
			fmt.Fprintln(a.Err, guard.OutflowDiscarded)
		}
		for _, warning := range r.Warnings {
			fmt.Fprintln(a.Err, warning)
		}
		for _, c := range r.Commands {
			fmt.Fprintf(a.Out, "$ %s\n%s", c.Command, c.Stdout)
			if c.Stderr != "" {
				fmt.Fprint(a.Err, c.Stderr)
			}
			if c.Error != "" {
				fmt.Fprintln(a.Err, c.Error)
			}
			if c.Truncated {
				fmt.Fprintln(a.Err, "warning: output truncated; narrow the query")
			}
		}
		if r.Error != "" {
			fmt.Fprintf(a.Err, "%s: %s\n", r.Host, r.Error)
		}
	}
}
