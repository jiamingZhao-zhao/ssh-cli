package cli

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/audit"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/exitcode"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/remote"
	"github.com/spf13/cobra"
)

var logName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9@._+-]{0,127}$`)

func logCommand(file, unit, container, grep, since string, lines int, now time.Time) (string, error) {
	return logSnapshotCommand(file, unit, container, grep, since, "", lines, now)
}

func logSnapshotCommand(file, unit, container, grep, since, until string, lines int, now time.Time) (string, error) {
	if lines < 1 || lines > 5000 {
		return "", fmt.Errorf("--lines must be 1..5000")
	}
	n := 0
	for _, s := range []string{file, unit, container} {
		if s != "" {
			n++
		}
	}
	if n != 1 {
		return "", fmt.Errorf("provide exactly one file path, --unit or --container")
	}
	if len(grep) > 1024 || strings.ContainsAny(grep, "\x00\r\n") {
		return "", fmt.Errorf("--grep must be a single literal line, at most 1024 bytes")
	}
	if file != "" && (since != "" || until != "") {
		return "", fmt.Errorf("remote time filters support journal/container logs only")
	}
	start, err := logBoundary(since, now)
	if err != nil {
		return "", err
	}
	end, err := logBoundary(until, now)
	if err != nil {
		return "", err
	}
	var command string
	switch {
	case unit != "":
		if !logName.MatchString(unit) {
			return "", fmt.Errorf("invalid unit name")
		}
		args := []string{"journalctl", "--no-pager", "-n", strconv.Itoa(lines), "-u", unit}
		if !start.IsZero() {
			args = append(args, "--since", start.UTC().Format(time.RFC3339Nano))
		}
		if !end.IsZero() {
			args = append(args, "--until", end.UTC().Format(time.RFC3339Nano))
		}
		command = shellCommand(args)
	case container != "":
		if !logName.MatchString(container) {
			return "", fmt.Errorf("invalid container name")
		}
		args := []string{"docker", "logs", "--tail", strconv.Itoa(lines)}
		if !start.IsZero() {
			args = append(args, "--since", start.UTC().Format(time.RFC3339Nano))
		}
		if !end.IsZero() {
			args = append(args, "--until", end.UTC().Format(time.RFC3339Nano))
		}
		args = append(args, container)
		command = shellCommand(args) + " 2>&1"
	default:
		path, err := remote.ValidateRemotePath(file)
		if err != nil {
			return "", err
		}
		if strings.HasSuffix(path, ".gz") {
			command = shellCommand([]string{"zcat", "--", path}) + " | " + shellCommand([]string{"tail", "-n", strconv.Itoa(lines)})
		} else {
			command = shellCommand([]string{"tail", "-n", strconv.Itoa(lines), "--", path})
		}
	}
	if grep != "" {
		command += " | " + shellCommand([]string{"grep", "-F", "--", grep})
	}
	return command, nil
}

func (a *App) logsCmd() *cobra.Command {
	var unit, container, grep, pattern, since, until, offset, timeout string
	var redact bool
	var lines int
	cmd := &cobra.Command{Use: "logs [file]", Short: "Read a bounded log snapshot from a file, unit or container", Args: cobra.MaximumNArgs(1),
		Long: `Read recent lines (default 200, max 5000). Use --grep for a literal
or --regex for a Go regular expression. --since and --until accept timestamps
with offsets (RFC3339) or durations ago such as 15m. For files the window applies
only to the recent lines and recognizes timestamp prefixes YYYY-MM-DD HH:MM:SS
and RFC3339, optionally in brackets. Naive timestamps use --file-offset (UTC by
default). Continuation lines inherit the prior timestamp; regex matches lines.
--agent-mode (or --redact) masks common authentication headers before retaining
or auditing any output. Redaction and local filters use direct SSH.
.gz files are decompressed and tailed within the timeout. Never follows logs.
Pipeline exit status alone cannot prove upstream log retrieval succeeded;
inspect stderr and transport outcomes as well. Policies and noDataOutflow apply.`,
		Example: `  ssh-cli logs -H app --unit nginx --since 15m --grep error --agent-mode
  ssh-cli logs -H app /var/log/app.log --lines 2000 --since 10m --until 5m --file-offset +08:00 --regex 'ERROR|timeout' --agent-mode`,
		RunE: func(cmd *cobra.Command, args []string) error {
			file := ""
			if len(args) > 0 {
				file = args[0]
			}
			now := time.Now()
			start, err := logBoundary(since, now)
			if err != nil {
				return exitcode.New(exitcode.Usage, "--since: %s", err)
			}
			end, err := logBoundary(until, now)
			if err != nil || !start.IsZero() && !end.IsZero() && end.Before(start) {
				return exitcode.New(exitcode.Usage, "--until must be a valid timestamp or duration and cannot precede --since")
			}
			if grep != "" && pattern != "" || len(pattern) > 1024 || len(grep) > 1024 || strings.ContainsAny(grep+pattern, "\x00\r\n") {
				return exitcode.New(exitcode.Usage, "specify at most one single-line --grep or --regex (at most 1024 bytes)")
			}
			if cmd.Flags().Changed("file-offset") && (file == "" || since == "" && until == "") {
				return exitcode.New(exitcode.Usage, "--file-offset requires a file and --since or --until")
			}
			remoteGrep, remoteSince, remoteUntil := grep, since, until
			redact = redact || a.AgentProfile
			if redact || pattern != "" || file != "" && (since != "" || until != "") {
				if a.UseDaemon || a.RequestAuto {
					return exitcode.New(exitcode.Usage, "redacted or locally filtered logs require direct SSH; remove --daemon or --auto-daemon")
				}
				zone, err := time.Parse("-07:00", offset)
				if err != nil || len(offset) != 6 || zone.Format("-07:00") != offset && offset != "-00:00" {
					return exitcode.New(exitcode.Usage, "--file-offset must be a UTC offset such as +08:00")
				}
				if grep != "" {
					pattern = regexp.QuoteMeta(grep)
				}
				var filter *regexp.Regexp
				if pattern != "" {
					filter, err = regexp.Compile(pattern)
					if err != nil {
						return exitcode.New(exitcode.Usage, "invalid --regex: %s", err)
					}
				}
				_, seconds := zone.Zone()
				a.logOutput = &logOutputOptions{redact: redact, filter: filter, zone: time.FixedZone(offset, seconds)}
				if file != "" {
					a.logOutput.since, a.logOutput.until = start, end
					remoteSince, remoteUntil = "", ""
				}
				a.Direct, remoteGrep = true, ""
				if a.MaxOutputBytes == 0 {
					a.MaxOutputBytes = 1 << 20
				}
			}
			command, err := logSnapshotCommand(file, unit, container, remoteGrep, remoteSince, remoteUntil, lines, now)
			if err != nil {
				return exitcode.New(exitcode.Usage, "%s", err)
			}
			dur, err := parseTimeout(timeout)
			if err != nil {
				return exitcode.New(exitcode.Usage, "%s", err)
			}
			if dur == 0 {
				dur = 15 * time.Second
			}
			results, err := a.collectQueries(audit.OpExec, []string{command}, dur, dur, 4, true)
			if err != nil {
				return err
			}
			if a.JSON {
				if err := a.emit(map[string]any{"results": results, "windowLines": lines, "filterScope": "recent_lines", "since": since, "until": until, "redactionEnabled": redact, "pipelineStatusUnverified": remoteGrep != "" || strings.HasSuffix(file, ".gz")}); err != nil {
					return err
				}
			} else {
				a.printQueries(results)
			}
			return queryExit(results)
		},
	}
	cmd.Flags().StringVar(&unit, "unit", "", "systemd unit (alternative to file/container)")
	cmd.Flags().StringVar(&container, "container", "", "Docker container (alternative to file/unit)")
	cmd.Flags().StringVar(&grep, "grep", "", "literal substring filter after selecting recent lines")
	cmd.Flags().StringVar(&pattern, "regex", "", "regular expression filter after selecting recent lines")
	cmd.Flags().StringVar(&since, "since", "", "inclusive time window start: duration ago or RFC3339")
	cmd.Flags().StringVar(&until, "until", "", "inclusive time window end: duration ago or RFC3339")
	cmd.Flags().StringVar(&offset, "file-offset", "+00:00", "UTC offset for plain file timestamps without a timezone")
	cmd.Flags().BoolVar(&redact, "redact", false, "mask common authentication headers (always on in agent mode)")
	cmd.Flags().IntVar(&lines, "lines", 200, "recent lines to read (1..5000)")
	cmd.Flags().StringVar(&timeout, "timeout", "", "whole request budget including connection (default 15s)")
	return cmd
}
