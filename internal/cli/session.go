package cli

import (
	"bytes"
	"context"
	"io"
	"strings"
	"time"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/exitcode"
)

type commandOutput struct {
	Truncated  bool           `json:"truncated,omitempty"`
	Outcome    string         `json:"outcome"`
	Error      string         `json:"error,omitempty"`
	Connection connectionInfo `json:"connection"`
	Command    string         `json:"command"`
	ExitCode   int            `json:"exitCode"`
	Stdout     string         `json:"stdout,omitempty"`
	Stderr     string         `json:"stderr,omitempty"`
}

// runCommands dials once and runs each command. A remote non-zero status is
// returned in the slice. Transport failures abort the rest.
func (a *App) runCommands(p planned, commands []string, timeout time.Duration) ([]commandOutput, error) {
	ctx := a.OperationContext
	if ctx == nil {
		ctx = context.Background()
	}
	start := time.Now()
	var clientRun func(context.Context, string, io.Writer, io.Writer) (int, error)
	var connection connectionInfo
	if !a.UseDaemon {
		client, err := a.dial(p.host, timeout)
		if err != nil {
			return nil, err
		}
		defer client.Close()
		connection = connectionInfo{Mode: "direct", Connected: true, ConnectMS: time.Since(start).Milliseconds()}
		clientRun = func(ctx context.Context, command string, out, errout io.Writer) (int, error) {
			return client.Run(ctx, command, out, errout, nil)
		}
	}
	out := make([]commandOutput, 0, len(commands))
	for _, command := range commands {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		commandCtx := ctx
		var cancel context.CancelFunc
		if timeout > 0 {
			commandCtx, cancel = context.WithTimeout(ctx, timeout)
		}
		var stdout, stderr bytes.Buffer
		var outDst, errDst io.Writer = &stdout, &stderr
		if p.eff.NoDataOut {
			outDst, errDst = io.Discard, io.Discard
		}
		outLimit := &outputLimiter{dst: outDst, maxLine: a.MaxLineBytes, maxTotal: a.MaxOutputBytes}
		errLimit := &outputLimiter{dst: errDst, maxLine: a.MaxLineBytes, maxTotal: a.MaxOutputBytes}
		info := connection
		started := time.Now()
		var code int
		var runErr error
		if a.UseDaemon {
			caller := a.queryCopy(commandCtx)
			code, runErr = caller.runViaDaemonObserved(p, command, outLimit, errLimit, timeout, &info)
		} else {
			info.Reused = len(out) > 0
			if info.Reused {
				info.ConnectMS = 0
			}
			code, runErr = clientRun(commandCtx, command, outLimit, errLimit)
			info.ExecutionMS = time.Since(started).Milliseconds()
			info.Outcome = executionOutcome(runErr)
		}
		if cancel != nil {
			cancel()
		}
		row := commandOutput{Command: command, ExitCode: code, Stdout: stdout.String(), Stderr: stderr.String(), Truncated: outLimit.cut || errLimit.cut, Outcome: info.Outcome, Connection: info}
		if runErr != nil {
			row.Error = runErr.Error()
			row.ExitCode = exitcode.Connect
			out = append(out, row)
			return out, sshWrapRun(runErr)
		}
		out = append(out, row)
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
