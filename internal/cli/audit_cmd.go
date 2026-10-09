package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/audit"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/exitcode"
)

func (a *App) auditCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Read the local audit log",
		Long: `Read the append-only JSONL audit log under the config directory (audit/YYYY-MM-DD.jsonl).

exec, upload, and download write a record even when policy denies the attempt, the command times out, or the remote exit code is non-zero. The optional UI is not required.

--host, --group, --env, and --json are the global flags.`,
	}
	cmd.AddCommand(a.auditList(), a.auditShow(), a.auditTail(), a.auditStats(), a.auditCleanup())
	return cmd
}

func (a *App) auditList() *cobra.Command {
	var since, until, status, op string
	var page, pageSize int
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List audit records",
		RunE: func(cmd *cobra.Command, _ []string) error {
			f, err := a.auditFilter(since, until, status, op)
			if err != nil {
				return err
			}
			if page > 0 || pageSize > 0 {
				pg, err := audit.QueryPage(a.Dir, f, page, pageSize)
				if err != nil {
					return exitcode.New(exitcode.Usage, "%s", err.Error())
				}
				if a.JSON {
					return a.emit(pg)
				}
				if len(pg.Records) == 0 {
					fmt.Fprintf(a.Out, "no audit records (page %d, %d match)\n", pg.Page, pg.Total)
					return nil
				}
				for _, rec := range pg.Records {
					printAuditRecord(a.Out, rec, false)
				}
				fmt.Fprintf(a.Out, "page %d, %d of %d\n", pg.Page, len(pg.Records), pg.Total)
				return nil
			}
			if a.JSON {
				return a.auditListJSON(f)
			}
			n := 0
			err = audit.List(a.Dir, f, func(rec audit.Record) error {
				printAuditRecord(a.Out, rec, false)
				n++
				return nil
			})
			if err != nil {
				return exitcode.New(exitcode.Usage, "%s", err.Error())
			}
			if n == 0 {
				fmt.Fprintln(a.Out, "no audit records")
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&since, "since", "", "include records at or after this time (RFC3339, YYYY-MM-DD, or a duration like 24h)")
	cmd.Flags().StringVar(&until, "until", "", "exclude records at or after this time (a YYYY-MM-DD includes that whole day)")
	cmd.Flags().StringVar(&status, "status", "", "filter by status: ok, denied, timeout, auth, connect, or error")
	cmd.Flags().StringVar(&op, "op", "", "filter by op: exec, upload, download, relay, policy_check, session, config_change, status, service, keys")
	cmd.Flags().IntVar(&page, "page", 0, "1-based page when set; newest records are page 1")
	cmd.Flags().IntVar(&pageSize, "page-size", 0, "page size (default 50, max 200) when --page is set")
	return cmd
}

func (a *App) auditStats() *cobra.Command {
	return &cobra.Command{
		Use:   "stats",
		Short: "Show audit file count, bytes, and entry count",
		RunE: func(cmd *cobra.Command, _ []string) error {
			st, err := audit.Stat(a.Dir)
			if err != nil {
				return exitcode.New(exitcode.Usage, "%s", err.Error())
			}
			if a.JSON {
				return a.emit(st)
			}
			fmt.Fprintf(a.Out, "files=%d entries=%d bytes=%d\n", st.Files, st.Entries, st.Bytes)
			return nil
		},
	}
}

func (a *App) auditCleanup() *cobra.Command {
	return &cobra.Command{
		Use:   "cleanup",
		Short: "Delete audit entries older than 30 days",
		Long:  `Delete audit entries older than 30 days. Newer entries are refused. The scan streams each file and does not load the log into memory.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			res, err := audit.Cleanup(a.Dir, audit.MinAge, time.Now())
			if err != nil {
				return exitcode.New(exitcode.Usage, "%s", err.Error())
			}
			if a.JSON {
				return a.emit(res)
			}
			fmt.Fprintf(a.Out, "removed=%d kept=%d files_deleted=%d bytes_freed=%d cutoff=%s\n",
				res.Removed, res.Kept, res.FilesDeleted, res.BytesFreed, res.Cutoff.Format(time.RFC3339))
			return nil
		},
	}
}

func (a *App) auditShow() *cobra.Command {
	return &cobra.Command{
		Use:   "show <id>",
		Short: "Show one audit record by id",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			rec, err := audit.Show(a.Dir, args[0])
			if err != nil {
				return exitcode.New(exitcode.Usage, "%s", err.Error())
			}
			if a.JSON {
				return a.emit(rec)
			}
			printAuditRecord(a.Out, rec, true)
			return nil
		},
	}
}

func (a *App) auditTail() *cobra.Command {
	var n int
	var follow bool
	cmd := &cobra.Command{
		Use:   "tail",
		Short: "Show the newest audit records",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := context.Background()
			if follow {
				var stop context.CancelFunc
				ctx, stop = signal.NotifyContext(context.Background(), os.Interrupt)
				defer stop()
			}
			err := audit.Tail(ctx, a.Dir, n, follow, func(rec audit.Record) error {
				if a.JSON {
					b, err := marshalAudit(rec)
					if err != nil {
						return err
					}
					_, err = a.Out.Write(append(b, '\n'))
					return err
				}
				printAuditRecord(a.Out, rec, false)
				return nil
			})
			if err != nil {
				return exitcode.New(exitcode.Usage, "%s", err.Error())
			}
			return nil
		},
	}
	cmd.Flags().IntVarP(&n, "lines", "n", 10, "how many records to show")
	cmd.Flags().BoolVarP(&follow, "follow", "f", false, "wait for new records until interrupted")
	return cmd
}

func (a *App) auditFilter(since, until, status, op string) (audit.Filter, error) {
	if status != "" && !audit.ValidStatus(status) {
		return audit.Filter{}, exitcode.New(exitcode.Usage, "invalid --status %q", status)
	}
	if op != "" && !audit.ValidOp(op) {
		return audit.Filter{}, exitcode.New(exitcode.Usage, "invalid --op %q", op)
	}
	f := audit.Filter{
		Hosts:  append([]string(nil), a.Hosts...),
		Groups: append([]string(nil), a.Groups...),
		Env:    a.Env,
		Status: status,
		Op:     op,
	}
	if since != "" {
		t, err := audit.ParseBound(since, false)
		if err != nil {
			return audit.Filter{}, exitcode.New(exitcode.Usage, "%s", err.Error())
		}
		f.Since, f.HasSince = t, true
	}
	if until != "" {
		t, err := audit.ParseBound(until, true)
		if err != nil {
			return audit.Filter{}, exitcode.New(exitcode.Usage, "%s", err.Error())
		}
		f.Until, f.HasUntil = t, true
	}
	return f, nil
}

func (a *App) auditListJSON(f audit.Filter) error {
	if _, err := io.WriteString(a.Out, "{\"records\":["); err != nil {
		return err
	}
	first := true
	err := audit.List(a.Dir, f, func(rec audit.Record) error {
		if !first {
			if _, err := io.WriteString(a.Out, ","); err != nil {
				return err
			}
		}
		first = false
		b, err := marshalAudit(rec)
		if err != nil {
			return err
		}
		_, err = a.Out.Write(b)
		return err
	})
	if _, werr := io.WriteString(a.Out, "]}\n"); werr != nil && err == nil {
		err = werr
	}
	if err != nil {
		return exitcode.New(exitcode.Usage, "%s", err.Error())
	}
	return nil
}

func marshalAudit(rec audit.Record) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(rec); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

func printAuditRecord(w io.Writer, rec audit.Record, full bool) {
	exit := "-"
	if rec.ExitCode != nil {
		exit = strconv.Itoa(*rec.ExitCode)
	}
	fmt.Fprintf(w, "%s  %s  %s  %s  %s/%s  exit=%s  %dms  high_risk=%t  denied_by_policy=%t  actor=%s  id=%s\n",
		rec.Time, rec.Status, rec.Op, rec.Host, emptyDash(rec.Env), emptyDash(rec.Group), exit, rec.DurationMS,
		rec.HighRisk, rec.DeniedByPolicy, emptyDash(rec.Actor), rec.ID)
	if rec.Command != "" {
		fmt.Fprintf(w, "  command: %s\n", oneLine(rec.Command))
	}
	if rec.Src != "" || rec.Dst != "" {
		fmt.Fprintf(w, "  path: %s -> %s\n", rec.Src, rec.Dst)
	}
	if rec.Reason != "" {
		fmt.Fprintf(w, "  reason: %s\n", oneLine(rec.Reason))
	}
	summary := rec.ResultSummary
	if !full {
		summary = oneLine(summary)
		if len(summary) > 160 {
			summary = summary[:160] + "..."
		}
	}
	if summary != "" && summary != oneLine(rec.Reason) && summary != rec.Reason {
		if full {
			fmt.Fprintf(w, "  result:\n%s\n", rec.ResultSummary)
		} else {
			fmt.Fprintf(w, "  result: %s\n", summary)
		}
	}
}

func emptyDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}
