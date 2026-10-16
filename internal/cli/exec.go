package cli

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/audit"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/exitcode"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/guard"
)

func (a *App) execCmd() *cobra.Command {
	var timeout string
	var script string
	var fromStdin bool
	var allowOutflow bool
	var parallel int
	var forwardStdin bool
	cmd := &cobra.Command{
		Use:   "exec [--] <command>",
		Short: "Run a remote command",
		Long: `Run a command on the selected host.

Transmission depends on how many arguments follow --.

  One argument is a remote shell script and is sent unchanged. The remote
  login shell parses it once, so pipes, redirects and quotes in that string
  are shell syntax:
    ssh-cli exec -H main -- "df -h / | head"
    ssh-cli exec -H main -- "curl -d '{\"k\":\"v\"}' http://127.0.0.1/api"

  Two or more arguments are an argv array. ssh-cli POSIX-single-quotes any
  element that the shell would otherwise reinterpret, then joins them. The
  remote login shell parses that line once and executes the restored argv.
  Quotes, spaces and metacharacters inside an argument are data, not syntax,
  and are not parsed a second time:
    ssh-cli exec -H main -- sh -c 'mkdir -p /a /b'
    ssh-cli exec -H main -- curl -d '{"k":"v"}' http://127.0.0.1/api

  A plain command whose words are all literal is unchanged:
    ssh-cli exec -H main -- systemctl status nginx

--forward-stdin copies local stdin to that remote command (for example
crontab -). It is direct-only: one host, not --daemon, and not combined
with --script or --stdin. --script and --stdin still send a script body.

policy show -H <host> lists the gates before you run a command. It does
not connect.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := a.rejectYesWithoutTTY(); err != nil {
				return err
			}
			sources := 0
			if len(args) > 0 {
				sources++
			}
			if script != "" {
				sources++
			}
			if fromStdin {
				sources++
			}
			if sources != 1 {
				return exitcode.New(exitcode.Usage, "provide exactly one of a command, --script, or --stdin")
			}
			if forwardStdin && (script != "" || fromStdin) {
				return exitcode.New(exitcode.Usage, "--forward-stdin cannot be combined with --script or --stdin")
			}
			if forwardStdin && a.UseDaemon {
				return exitcode.New(exitcode.Usage, "--forward-stdin is not available with --daemon")
			}
			var command string
			var scriptBody string
			remote := ""
			var warnings []string
			switch {
			case script != "":
				body, err := readScriptFile(script)
				if err != nil {
					return exitcode.New(exitcode.Usage, "%s", err.Error())
				}
				scriptBody = body
				command = body
				remote = shellForScript(body)
			case fromStdin:
				b, err := io.ReadAll(io.LimitReader(a.In, 8<<20))
				if err != nil {
					return err
				}
				scriptBody = string(b)
				command = scriptBody
				remote = shellForScript(scriptBody)
			default:
				command = shellCommand(args)
				remote = command
				warnings = a.warnMSYS(args)
			}
			if strings.TrimSpace(command) == "" {
				return exitcode.New(exitcode.Usage, "empty command")
			}
			dur, err := parseTimeout(timeout)
			if err != nil {
				return exitcode.New(exitcode.Usage, "%s", err.Error())
			}
			if parallel < 1 || parallel > guard.MaxParallel {
				return exitcode.New(exitcode.Usage, "--parallel must be from 1 to %d", guard.MaxParallel)
			}
			meta := a.auditMeta(audit.OpExec, command, "", "")
			cfg, hosts, err := a.loadSelection()
			if err != nil {
				a.auditSelectionError(meta, hosts, err)
				return err
			}
			if parallel > 1 && len(hosts) > guard.MaxBatchHosts {
				return exitcode.New(exitcode.Usage, "at most %d hosts", guard.MaxBatchHosts)
			}
			if forwardStdin && (parallel > 1 || len(hosts) != 1) {
				return exitcode.New(exitcode.Usage, "--forward-stdin requires exactly one host and --parallel 1")
			}
			var stdin io.Reader
			if forwardStdin {
				stdin = a.In
			}
			plan, err := a.plan(cfg, hosts, meta, func(eff guard.Effective) guard.Decision {
				return guard.Decide(eff, command)
			})
			if err != nil {
				return err
			}
			return a.runAll(meta, plan, remote, scriptBody, dur, allowOutflow, parallel, stdin, warnings)
		},
	}
	cmd.Flags().StringVar(&timeout, "timeout", "", "command timeout (duration or seconds); also bounds SSH connect")
	cmd.Flags().StringVar(&script, "script", "", "read the remote script from a file")
	cmd.Flags().BoolVar(&fromStdin, "stdin", false, "read the remote script from stdin")
	cmd.Flags().BoolVar(&allowOutflow, "allow-outflow", false, "return stdout and stderr from a noDataOutflow env; requires typing outflow")
	cmd.Flags().BoolVar(&forwardStdin, "forward-stdin", false, "copy local stdin to the remote command (one host; not with --daemon, --script, or --stdin)")
	cmd.Flags().IntVar(&parallel, "parallel", 1, "run up to N selected hosts at once (1-4); above 1, at most 16 hosts")
	return cmd
}

type execResult struct {
	Host             string `json:"host"`
	Group            string `json:"group"`
	Env              string `json:"env"`
	ExitCode         int    `json:"exitCode"`
	Status           string `json:"status"`
	Outcome          string `json:"outcome"`
	RetrySafe        bool   `json:"retrySafe"`
	Stdout           string `json:"stdout,omitempty"`
	Stderr           string `json:"stderr,omitempty"`
	StdoutSuppressed bool   `json:"stdoutSuppressed,omitempty"`
	Notice           string `json:"notice,omitempty"`
	Error            string `json:"error,omitempty"`
}

func (a *App) runAll(meta auditMeta, plan []planned, remote, scriptBody string, timeout time.Duration, allowOutflow bool, parallel int, stdin io.Reader, warnings []string) error {
	if parallel > 1 {
		return a.runParallel(meta, plan, remote, scriptBody, timeout, allowOutflow, parallel, warnings)
	}
	var results []execResult
	final := 0
	for _, p := range plan {
		if p.dec.NeedsConfirm {
			if err := confirmAlias(p.host.Alias, a.Yes); err != nil {
				a.logDenial(meta, p.host, &p.dec, err.Error())
				return err
			}
		}
		suppress, needsOut := guard.ExecOutflow(p.eff.NoDataOut, allowOutflow)
		if needsOut {
			if err := confirmOutflow(a.Yes); err != nil {
				a.logDenial(meta, p.host, &p.dec, err.Error())
				return err
			}
		}
		a.header(p.host)
		res := execResult{Host: p.host.Alias, Group: p.host.Group, Env: p.host.EnvName}
		outCap := &capWriter{max: 4 << 10}
		errCap := &capWriter{max: 4 << 10}
		var stdout, stderr io.Writer
		var outBuf, errBuf bytes.Buffer
		if suppress {
			stdout = io.Discard
			stderr = io.Discard
			res.StdoutSuppressed = true
			res.Notice = guard.OutflowDiscarded
			fmt.Fprintln(a.Err, guard.OutflowDiscarded)
		} else if a.JSON {
			stdout = io.MultiWriter(&outBuf, outCap)
			stderr = io.MultiWriter(&errBuf, errCap)
		} else {
			stdout = io.MultiWriter(a.Out, outCap)
			stderr = io.MultiWriter(a.Err, errCap)
		}
		start := time.Now()
		code, runErr := a.runOne(p, remote, scriptBody, stdout, stderr, stdin, timeout)
		hostMeta := meta
		hostMeta.started = start
		if runErr != nil {
			res.Error = runErr.Error()
			res.ExitCode = exitcode.From(runErr)
			fmt.Fprintf(a.Err, "error: %s: %s\n", p.host.Alias, runErr.Error())
		} else {
			res.ExitCode = code
		}
		if a.JSON {
			res.Stdout = outBuf.String()
			res.Stderr = errBuf.String()
		}
		st, exitCode := statusOf(res.ExitCode, runErr)
		res.Status, res.Outcome = st, executionOutcome(runErr)
		extra := ""
		if runErr != nil {
			extra = runErr.Error()
		}
		summary := summarizeOutputs(outCap.buf.String(), errCap.buf.String(), outCap.cut || errCap.cut, extra)
		if suppress {
			summary = guard.OutflowDiscarded
			if extra != "" {
				summary = guard.OutflowDiscarded + "; " + extra
			}
		}
		if err := a.logRemote(hostMeta, p.host, p.dec, st, exitCode, summary, ""); err != nil {
			return err
		}
		results = append(results, res)
		final = preferCode(final, res.ExitCode)
	}
	if a.JSON {
		body := map[string]any{"results": results}
		if len(warnings) > 0 {
			body["warnings"] = warnings
		}
		if err := a.emit(body); err != nil {
			return err
		}
	}
	if final != 0 {
		return exitcode.Silent(final)
	}
	return nil
}

func (a *App) confirmAll(meta auditMeta, plan []planned, allowOutflow bool) error {
	askedOut := false
	for _, p := range plan {
		if p.dec.NeedsConfirm {
			if err := confirmAlias(p.host.Alias, a.Yes); err != nil {
				a.logDenial(meta, p.host, &p.dec, err.Error())
				return err
			}
		}
		if _, needs := guard.ExecOutflow(p.eff.NoDataOut, allowOutflow); needs && !askedOut {
			if err := confirmOutflow(a.Yes); err != nil {
				a.logDenial(meta, p.host, &p.dec, err.Error())
				return err
			}
			askedOut = true
		}
	}
	return nil
}

func (a *App) runParallel(meta auditMeta, plan []planned, remote, scriptBody string, timeout time.Duration, allowOutflow bool, parallel int, warnings []string) error {
	if err := a.confirmAll(meta, plan, allowOutflow); err != nil {
		return err
	}
	results := make([]execResult, len(plan))
	var mu sync.Mutex
	var auditErr error
	sem := make(chan struct{}, parallel)
	var wg sync.WaitGroup
	for i, p := range plan {
		wg.Add(1)
		go func(i int, p planned) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			res, auditFailure := a.execCaptured(meta, p, remote, scriptBody, timeout, allowOutflow, &mu)
			mu.Lock()
			results[i] = res
			if auditFailure != nil && auditErr == nil {
				auditErr = auditFailure
			}
			mu.Unlock()
		}(i, p)
	}
	wg.Wait()
	if auditErr != nil {
		return auditErr
	}
	if a.JSON {
		body := map[string]any{"results": results}
		if len(warnings) > 0 {
			body["warnings"] = warnings
		}
		if err := a.emit(body); err != nil {
			return err
		}
	}
	final := 0
	for _, res := range results {
		final = preferCode(final, res.ExitCode)
	}
	if final != 0 {
		return exitcode.Silent(final)
	}
	return nil
}

func (a *App) execCaptured(meta auditMeta, p planned, remote, scriptBody string, timeout time.Duration, allowOutflow bool, printMu *sync.Mutex) (execResult, error) {
	suppress, _ := guard.ExecOutflow(p.eff.NoDataOut, allowOutflow)
	res := execResult{Host: p.host.Alias, Group: p.host.Group, Env: p.host.EnvName}
	outCap := &capWriter{max: 4 << 10}
	errCap := &capWriter{max: 4 << 10}
	var stdout, stderr io.Writer
	var outBuf, errBuf bytes.Buffer
	if suppress {
		stdout = io.Discard
		stderr = io.Discard
		res.StdoutSuppressed = true
		res.Notice = guard.OutflowDiscarded
	} else {
		stdout = io.MultiWriter(&outBuf, outCap)
		stderr = io.MultiWriter(&errBuf, errCap)
	}
	start := time.Now()
	code, runErr := a.runOne(p, remote, scriptBody, stdout, stderr, nil, timeout)
	hostMeta := meta
	hostMeta.started = start
	if runErr != nil {
		res.Error = runErr.Error()
		res.ExitCode = exitcode.From(runErr)
	} else {
		res.ExitCode = code
	}
	if a.JSON {
		res.Stdout = outBuf.String()
		res.Stderr = errBuf.String()
	}
	printMu.Lock()
	a.header(p.host)
	if suppress {
		fmt.Fprintln(a.Err, guard.OutflowDiscarded)
	} else if !a.JSON {
		_, _ = a.Out.Write(outBuf.Bytes())
		_, _ = a.Err.Write(errBuf.Bytes())
	}
	if runErr != nil {
		fmt.Fprintf(a.Err, "error: %s: %s\n", p.host.Alias, runErr.Error())
	}
	printMu.Unlock()
	st, exitCode := statusOf(res.ExitCode, runErr)
	res.Status, res.Outcome = st, executionOutcome(runErr)
	extra := ""
	if runErr != nil {
		extra = runErr.Error()
	}
	summary := summarizeOutputs(outCap.buf.String(), errCap.buf.String(), outCap.cut || errCap.cut, extra)
	if suppress {
		summary = guard.OutflowDiscarded
		if extra != "" {
			summary = guard.OutflowDiscarded + "; " + extra
		}
	}
	if err := a.logRemote(hostMeta, p.host, p.dec, st, exitCode, summary, ""); err != nil {
		return res, err
	}
	return res, nil
}

// A transport failure cannot prove that a command never reached the host.
// Even a completed nonzero command may have produced side effects.
func executionOutcome(err error) string {
	if err != nil {
		return "unknown"
	}
	return "completed"
}

func (a *App) runOne(p planned, remote, scriptBody string, stdout, stderr io.Writer, stdin io.Reader, timeout time.Duration) (int, error) {
	if a.OperationContext != nil {
		if err := a.OperationContext.Err(); err != nil {
			return 0, err
		}
	}
	if a.UseDaemon {
		if scriptBody != "" {
			return 0, exitcode.New(exitcode.Usage, "--daemon accepts literal exec commands, not --stdin/--script")
		}
		return a.runViaDaemon(p, remote, stdout, stderr, timeout)
	}
	client, err := a.dial(p.host, timeout)
	if err != nil {
		return 0, err
	}
	defer client.Close()
	ctx := context.Background()
	if a.OperationContext != nil {
		ctx = a.OperationContext
	}
	var cancel context.CancelFunc
	if timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	if scriptBody != "" {
		stdin = strings.NewReader(scriptBody)
	}
	code, err := client.Run(ctx, remote, stdout, stderr, stdin)
	if err != nil {
		return 0, sshWrapRun(err)
	}
	return code, nil
}

func sshWrapRun(err error) error {
	if err == nil {
		return nil
	}
	if strings.Contains(strings.ToLower(err.Error()), "timed out") {
		return exitcode.New(exitcode.Connect, "%s", err.Error())
	}
	return exitcode.New(exitcode.Connect, "%s", err.Error())
}

func parseTimeout(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" || s == "0" {
		return 0, nil
	}
	if d, err := time.ParseDuration(s); err == nil {
		return d, nil
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("invalid timeout %q", s)
	}
	return time.Duration(n) * time.Second, nil
}
