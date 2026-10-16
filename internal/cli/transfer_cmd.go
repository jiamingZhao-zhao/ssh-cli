package cli

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"strings"
	"time"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/audit"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/exitcode"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/guard"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/transfer"
)

func (a *App) uploadCmd() *cobra.Command {
	var backup bool
	var confirmOverwrite bool
	cmd := &cobra.Command{
		Use:   "upload <local> <remote>",
		Short: "Upload a file or directory over SFTP",
		Long: `Upload a file or directory over SFTP.

An existing remote file is replaced without a prompt. --backup copies that
file to <path>.ssh-cli.bak first (a second backup in the same second gets a
unix-time suffix). --confirm-overwrite requires the host-alias confirmation
before a replacement; without a TTY that exits 253.

--json adds bytes, durationMs and sha256. sha256 covers regular-file contents
in upload plan order, not directory names or modes. backups lists copy paths
when --backup wrote any.`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.transfer("upload", args[0], args[1], uploadOpts{backup: backup, confirmOverwrite: confirmOverwrite})
		},
	}
	cmd.Flags().BoolVar(&backup, "backup", false, "copy an existing remote file to <path>.ssh-cli.bak before replacing it")
	cmd.Flags().BoolVar(&confirmOverwrite, "confirm-overwrite", false, "require host-alias confirmation before replacing a remote file")
	return cmd
}

func (a *App) downloadCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "download <remote> <local>",
		Short: "Download a file or directory over SFTP",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.transfer("download", args[0], args[1], uploadOpts{})
		},
	}
}

type uploadOpts struct {
	backup           bool
	confirmOverwrite bool
}

func (a *App) transfer(kind, src, dst string, up uploadOpts) error {
	if err := a.rejectYesWithoutTTY(); err != nil {
		return err
	}
	local, remote := src, dst
	if kind == "download" {
		remote, local = src, dst
	}
	warnings := a.warnMSYS([]string{remote})
	meta := a.auditMeta(kind, "", src, dst)
	cfg, hosts, err := a.loadSelection()
	if err != nil {
		a.auditSelectionError(meta, hosts, err)
		return err
	}
	plan, err := a.plan(cfg, hosts, meta, func(eff guard.Effective) guard.Decision {
		return guard.DecideCapability(eff, kind, remote)
	})
	if err != nil {
		return err
	}
	final := 0
	type result struct {
		Host       string   `json:"host"`
		Group      string   `json:"group"`
		Env        string   `json:"env"`
		Error      string   `json:"error,omitempty"`
		Bytes      int64    `json:"bytes,omitempty"`
		DurationMS int64    `json:"durationMs,omitempty"`
		SHA256     string   `json:"sha256,omitempty"`
		Backups    []string `json:"backups,omitempty"`
	}
	var results []result
	for _, p := range plan {
		if p.dec.NeedsConfirm {
			if err := confirmAlias(p.host.Alias, a.Yes); err != nil {
				a.logDenial(meta, p.host, &p.dec, err.Error())
				return err
			}
		}
		a.header(p.host)
		start := time.Now()
		client, err := a.dial(p.host, 0)
		hostMeta := meta
		hostMeta.started = start
		res := result{Host: p.host.Alias, Group: p.host.Group, Env: p.host.EnvName}
		if err != nil {
			res.Error = err.Error()
			fmt.Fprintf(a.Err, "error: %s: %s\n", p.host.Alias, err.Error())
			st, code := statusOf(0, err)
			final = preferCode(final, code)
			results = append(results, res)
			if logErr := a.logRemote(hostMeta, p.host, p.dec, st, code, err.Error(), err.Error()); logErr != nil {
				return logErr
			}
			continue
		}
		log := func(msg string) { fmt.Fprintf(a.Err, "warning: %s\n", msg) }
		var policyErr error
		var stats transfer.UploadStats
		if kind == "upload" {
			already := p.dec.NeedsConfirm
			confirmedOverwrite := false
			err = transfer.UploadWithOptions(client.Raw(), local, remote, log, transfer.UploadOptions{
				Protected: p.eff.Protected,
				Backup:    up.backup,
				Stats:     &stats,
				OnOverwrite: func(remotePath string) error {
					if !up.confirmOverwrite || confirmedOverwrite {
						return nil
					}
					if cerr := confirmAlias(p.host.Alias, a.Yes); cerr != nil {
						a.logDenial(hostMeta, p.host, &p.dec, cerr.Error())
						return cerr
					}
					confirmedOverwrite = true
					return nil
				},
				Check: func(remotePath string, protected []string) error {
					eff := p.eff
					eff.Protected = protected
					d := guard.DecideCapability(eff, "upload", remotePath)
					if !d.Allowed {
						policyErr = exitcode.New(exitcode.Denied, "%s", decisionReason(d))
						a.logDenial(hostMeta, p.host, &d, decisionReason(d))
						return policyErr
					}
					if d.NeedsConfirm && !already {
						if cerr := confirmAlias(p.host.Alias, a.Yes); cerr != nil {
							policyErr = cerr
							a.logDenial(hostMeta, p.host, &d, cerr.Error())
							return cerr
						}
						already = true
					}
					return nil
				}})
			if policyErr != nil {
				client.Close()
				return policyErr
			}
			var denied *exitcode.Error
			if errors.As(err, &denied) && denied.Code == exitcode.Denied {
				client.Close()
				return err
			}
		} else {
			err = transfer.Download(client.Raw(), remote, local, log)
		}
		client.Close()
		code := 0
		st := audit.StatusOK
		summary := kind + " ok"
		reason := ""
		if err != nil {
			res.Error = err.Error()
			fmt.Fprintf(a.Err, "error: %s: %s\n", p.host.Alias, err.Error())
			code = exitcode.Connect
			st = audit.StatusError
			msg := strings.ToLower(err.Error())
			if strings.Contains(msg, "timed out") || strings.Contains(msg, "i/o timeout") || strings.Contains(msg, "deadline exceeded") {
				st = audit.StatusTimeout
			}
			summary = err.Error()
			reason = err.Error()
			final = preferCode(final, code)
		} else if !a.JSON {
			fmt.Fprintf(a.Err, "%s ok: %s\n", kind, p.host.Alias)
		}
		if kind == "upload" && err == nil {
			res.Bytes = stats.Bytes
			res.DurationMS = time.Since(start).Milliseconds()
			res.SHA256 = stats.SHA256
			res.Backups = stats.Backups
			if !a.JSON && len(stats.Backups) > 0 {
				fmt.Fprintf(a.Err, "backup: %s\n", strings.Join(stats.Backups, ", "))
			}
		}
		results = append(results, res)
		if logErr := a.logRemote(hostMeta, p.host, p.dec, st, code, summary, reason); logErr != nil {
			return logErr
		}
	}
	if a.JSON {
		body := map[string]any{"op": kind, "results": results}
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
