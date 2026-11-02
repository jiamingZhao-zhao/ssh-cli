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
	stamp := ""
	if since != "" {
		if file != "" {
			return "", fmt.Errorf("--since supports journal/container logs only; file timestamp formats are not guessed")
		}
		if d, err := time.ParseDuration(since); err == nil {
			if d <= 0 || d > 30*24*time.Hour {
				return "", fmt.Errorf("--since duration must be positive and at most 720h")
			}
			stamp = now.Add(-d).UTC().Format(time.RFC3339)
		} else {
			t, err := time.Parse(time.RFC3339, since)
			if err != nil || t.After(now) {
				return "", fmt.Errorf("--since requires a past RFC3339 timestamp or duration such as 15m")
			}
			stamp = t.UTC().Format(time.RFC3339)
		}
	}
	var command string
	switch {
	case unit != "":
		if !logName.MatchString(unit) {
			return "", fmt.Errorf("invalid unit name")
		}
		args := []string{"journalctl", "--no-pager", "-n", strconv.Itoa(lines), "-u", unit}
		if stamp != "" {
			args = append(args, "--since", stamp)
		}
		command = shellCommand(args)
	case container != "":
		if !logName.MatchString(container) {
			return "", fmt.Errorf("invalid container name")
		}
		args := []string{"docker", "logs", "--tail", strconv.Itoa(lines)}
		if stamp != "" {
			args = append(args, "--since", stamp)
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
	var unit, container, grep, since, timeout string
	var lines int
	cmd := &cobra.Command{Use: "logs [file]", Short: "Read a bounded log snapshot from a file, unit or container", Args: cobra.MaximumNArgs(1),
		Long: `Read recent lines (default 200, max 5000), optionally filter by literal
--grep. Filtering happens after the recent-line window; no match does not prove
the full log has no match. --since accepts 15m or RFC3339 for unit/container logs.
Files have arbitrary timestamp formats, so --since is rejected for file reads.
.gz files are decompressed and tailed within the timeout. Never follows logs.
Pipeline exit status alone cannot prove upstream log retrieval succeeded;
inspect stderr and transport outcomes as well. Policies and noDataOutflow apply.`,
		Example: `  ssh-cli logs -H app --unit nginx --since 15m --grep error --agent-mode`,
		RunE: func(cmd *cobra.Command, args []string) error {
			file := ""
			if len(args) > 0 {
				file = args[0]
			}
			command, err := logCommand(file, unit, container, grep, since, lines, time.Now())
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
				if err := a.emit(map[string]any{"results": results, "windowLines": lines, "filterScope": "recent_lines", "since": since, "pipelineStatusUnverified": grep != "" || strings.HasSuffix(file, ".gz")}); err != nil {
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
	cmd.Flags().StringVar(&since, "since", "", "time window for unit/container: duration or RFC3339")
	cmd.Flags().IntVar(&lines, "lines", 200, "recent lines to read (1..5000)")
	cmd.Flags().StringVar(&timeout, "timeout", "", "whole request budget including connection (default 15s)")
	return cmd
}
