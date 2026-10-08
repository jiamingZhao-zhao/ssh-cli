package cli

import (
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
	return &cobra.Command{
		Use:   "upload <local> <remote>",
		Short: "Upload a file or directory over SFTP",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.transfer("upload", args[0], args[1])
		},
	}
}

func (a *App) downloadCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "download <remote> <local>",
		Short: "Download a file or directory over SFTP",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.transfer("download", args[0], args[1])
		},
	}
}

func (a *App) transfer(kind, src, dst string) error {
	if err := a.rejectYesWithoutTTY(); err != nil {
		return err
	}
	local, remote := src, dst
	if kind == "download" {
		remote, local = src, dst
	}
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
		Host  string `json:"host"`
		Group string `json:"group"`
		Env   string `json:"env"`
		Error string `json:"error,omitempty"`
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
		client, err := a.dial(p.host)
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
		if kind == "upload" {
			err = transfer.Upload(client.Raw(), local, remote, log)
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
		results = append(results, res)
		if logErr := a.logRemote(hostMeta, p.host, p.dec, st, code, summary, reason); logErr != nil {
			return logErr
		}
	}
	if a.JSON {
		if err := a.emit(map[string]any{"op": kind, "results": results}); err != nil {
			return err
		}
	}
	if final != 0 {
		return exitcode.Silent(final)
	}
	return nil
}
