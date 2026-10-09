package cli

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"
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
	cmd := &cobra.Command{
		Use:   "exec [--] <command>",
		Short: "Run a remote command",
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
			var command string
			var scriptBody string
			remote := ""
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
				command = strings.Join(args, " ")
				remote = command
			}
			if strings.TrimSpace(command) == "" {
				return exitcode.New(exitcode.Usage, "empty command")
			}
			dur, err := parseTimeout(timeout)
			if err != nil {
				return exitcode.New(exitcode.Usage, "%s", err.Error())
			}
			meta := a.auditMeta(audit.OpExec, command, "", "")
			cfg, hosts, err := a.loadSelection()
			if err != nil {
				a.auditSelectionError(meta, hosts, err)
				return err
			}
			plan, err := a.plan(cfg, hosts, meta, func(eff guard.Effective) guard.Decision {
				return guard.Decide(eff, command)
			})
			if err != nil {
				return err
			}
			return a.runAll(meta, plan, remote, scriptBody, dur)
		},
	}
	cmd.Flags().StringVar(&timeout, "timeout", "", "command timeout (duration or seconds); also bounds SSH connect")
	cmd.Flags().StringVar(&script, "script", "", "read the remote script from a file")
	cmd.Flags().BoolVar(&fromStdin, "stdin", false, "read the remote script from stdin")
	return cmd
}

type execResult struct {
	Host     string `json:"host"`
	Group    string `json:"group"`
	Env      string `json:"env"`
	ExitCode int    `json:"exitCode"`
	Stdout   string `json:"stdout,omitempty"`
	Stderr   string `json:"stderr,omitempty"`
	Error    string `json:"error,omitempty"`
}

func (a *App) runAll(meta auditMeta, plan []planned, remote, scriptBody string, timeout time.Duration) error {
	var results []execResult
	final := 0
	for _, p := range plan {
		if p.dec.NeedsConfirm {
			if err := confirmAlias(p.host.Alias, a.Yes); err != nil {
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
		if a.JSON {
			stdout = io.MultiWriter(&outBuf, outCap)
			stderr = io.MultiWriter(&errBuf, errCap)
		} else {
			stdout = io.MultiWriter(a.Out, outCap)
			stderr = io.MultiWriter(a.Err, errCap)
		}
		start := time.Now()
		code, runErr := a.runOne(p, remote, scriptBody, stdout, stderr, timeout)
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
		extra := ""
		if runErr != nil {
			extra = runErr.Error()
		}
		summary := summarizeOutputs(outCap.buf.String(), errCap.buf.String(), outCap.cut || errCap.cut, extra)
		if err := a.logRemote(hostMeta, p.host, p.dec, st, exitCode, summary, ""); err != nil {
			return err
		}
		results = append(results, res)
		final = preferCode(final, res.ExitCode)
	}
	if a.JSON {
		if err := a.emit(map[string]any{"results": results}); err != nil {
			return err
		}
	}
	if final != 0 {
		return exitcode.Silent(final)
	}
	return nil
}

func (a *App) runOne(p planned, remote, scriptBody string, stdout, stderr io.Writer, timeout time.Duration) (int, error) {
	client, err := a.dial(p.host, timeout)
	if err != nil {
		return 0, err
	}
	defer client.Close()
	ctx := context.Background()
	var cancel context.CancelFunc
	if timeout > 0 {
		ctx, cancel = context.WithTimeout(context.Background(), timeout)
		defer cancel()
	}
	var stdin io.Reader
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
