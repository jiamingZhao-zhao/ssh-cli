package cli

import (
	"bytes"
	"context"
	"strings"
	"time"
)

type commandOutput struct {
	Command  string `json:"command"`
	ExitCode int    `json:"exitCode"`
	Stdout   string `json:"stdout,omitempty"`
	Stderr   string `json:"stderr,omitempty"`
}

// runCommands dials once and runs each command. A remote non-zero status is
// returned in the slice. Transport failures abort the rest.
func (a *App) runCommands(p planned, commands []string, timeout time.Duration) ([]commandOutput, error) {
	client, err := a.dial(p.host)
	if err != nil {
		return nil, err
	}
	defer client.Close()
	out := make([]commandOutput, 0, len(commands))
	for _, command := range commands {
		ctx := context.Background()
		var cancel context.CancelFunc
		if timeout > 0 {
			ctx, cancel = context.WithTimeout(context.Background(), timeout)
		}
		var stdout, stderr bytes.Buffer
		code, runErr := client.Run(ctx, command, &stdout, &stderr, nil)
		if cancel != nil {
			cancel()
		}
		if runErr != nil {
			return out, sshWrapRun(runErr)
		}
		out = append(out, commandOutput{Command: command, ExitCode: code, Stdout: stdout.String(), Stderr: stderr.String()})
	}
	return out, nil
}

func (a *App) auditHost(meta auditMeta, p planned, started time.Time, code int, runErr error, summary string) error {
	hostMeta := meta
	hostMeta.started = started
	st, exitCode := statusOf(code, runErr)
	reason := ""
	if runErr != nil && summary == "" {
		summary = runErr.Error()
	}
	return a.logRemote(hostMeta, p.host, p.dec, st, exitCode, summary, reason)
}

func joinSummary(parts []string) string {
	var b strings.Builder
	for _, p := range parts {
		p = strings.TrimRight(p, "\n")
		if p == "" {
			continue
		}
		if b.Len() > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(p)
	}
	return b.String()
}

func (a *App) confirmPlanned(meta auditMeta, p planned) error {
	if !p.dec.NeedsConfirm {
		return nil
	}
	if err := confirmAlias(p.host.Alias, a.Yes); err != nil {
		a.logDenial(meta, p.host, &p.dec, err.Error())
		return err
	}
	return nil
}
