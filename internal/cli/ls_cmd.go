package cli

import (
	"errors"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/audit"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/exitcode"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/guard"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/transfer"
)

func (a *App) lsCmd() *cobra.Command {
	var timeout string
	cmd := &cobra.Command{
		Use:   "ls [path]",
		Short: "List a remote directory",
		Long: `ls lists one remote directory over SFTP. The default path is the login
directory. The read does not create, rename, or delete anything.

The command is allowed when policy allows ls. noDataOutflow refuses the
listing, the same way it refuses download. A missing path is an error for
that host and does not change the remote tree.

Output is capped at 2000 entries. The attempt is audited as op list with
source cli.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := "."
			if len(args) == 1 {
				path = args[0]
			}
			return a.listRemote(path, timeout)
		},
	}
	cmd.Flags().StringVar(&timeout, "timeout", "", "SSH connect timeout (duration or seconds; default 20s)")
	return cmd
}

func (a *App) listRemote(pathFlag, timeout string) error {
	if err := a.rejectYesWithoutTTY(); err != nil {
		return err
	}
	remotePath, err := transfer.CleanListPath(pathFlag)
	if err != nil {
		return exitcode.New(exitcode.Usage, "%s", err.Error())
	}
	dur, err := parseTimeout(timeout)
	if err != nil {
		return exitcode.New(exitcode.Usage, "%s", err.Error())
	}
	meta := a.auditMeta(audit.OpList, "ls", remotePath, "")
	cfg, hosts, err := a.loadSelection()
	if err != nil {
		a.auditSelectionError(meta, hosts, err)
		return err
	}
	plan, err := a.plan(cfg, hosts, meta, func(eff guard.Effective) guard.Decision {
		return listDecision(eff)
	})
	if err != nil {
		return err
	}
	type view struct {
		Host      string               `json:"host"`
		Group     string               `json:"group"`
		Env       string               `json:"env"`
		Path      string               `json:"path,omitempty"`
		Parent    string               `json:"parent,omitempty"`
		Entries   []transfer.FileEntry `json:"entries"`
		Truncated bool                 `json:"truncated,omitempty"`
		Error     string               `json:"error,omitempty"`
	}
	views := make([]view, 0, len(plan))
	final := 0
	for _, p := range plan {
		if err := a.confirmPlanned(meta, p); err != nil {
			return err
		}
		a.header(p.host)
		start := time.Now()
		client, dialErr := a.dial(p.host, dur)
		v := view{Host: p.host.Alias, Group: p.host.Group, Env: p.host.EnvName, Entries: []transfer.FileEntry{}}
		var runErr error
		if dialErr != nil {
			runErr = dialErr
			v.Error = dialErr.Error()
		} else {
			listing, err := transfer.List(client.Raw(), remotePath)
			_ = client.Close()
			if err != nil {
				runErr = err
				v.Error = err.Error()
			} else {
				v.Path = listing.Path
				v.Parent = listing.Parent
				v.Entries = listing.Entries
				v.Truncated = listing.Truncated
				if !a.JSON {
					fmt.Fprintf(a.Out, "# %s\n", listing.Path)
					for _, e := range listing.Entries {
						kind := e.Mode
						if e.Dir {
							kind = "dir"
						} else if e.Link {
							kind = "link"
						}
						fmt.Fprintf(a.Out, "%s\t%d\t%s\t%s\n", kind, e.Size, e.MTime, e.Name)
					}
					if listing.Truncated {
						fmt.Fprintf(a.Err, "note: listing truncated at 2000 entries\n")
					}
				}
			}
		}
		if runErr != nil && !a.JSON {
			fmt.Fprintf(a.Err, "error: %s: %s\n", p.host.Alias, runErr.Error())
		}
		summary := fmt.Sprintf("path=%s entries=%d", v.Path, len(v.Entries))
		if v.Error != "" {
			summary = v.Error
		}
		code := 0
		if runErr != nil {
			var tool *exitcode.Error
			if errors.As(runErr, &tool) {
				code = tool.Code
			} else {
				code = 1
			}
		}
		if err := a.auditHost(meta, p, start, code, runErr, summary); err != nil {
			return err
		}
		views = append(views, v)
		if runErr != nil {
			final = preferCode(final, code)
		}
	}
	if a.JSON {
		if err := a.emit(map[string]any{"results": views}); err != nil {
			return err
		}
	}
	if final != 0 {
		return exitcode.Silent(final)
	}
	return nil
}

func listDecision(eff guard.Effective) guard.Decision {
	dec := guard.Decide(eff, "ls")
	if eff.NoDataOut {
		dec.Allowed = false
		dec.NeedsConfirm = false
		dec.Findings = append(dec.Findings, guard.Finding{
			Layer: "env", Kind: "deny", Detail: "noDataOutflow forbids listing remote files",
		})
	}
	return dec
}
