package cli

import (
	"fmt"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/audit"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/config"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/exitcode"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/guard"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/remote"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/sshclient"
)

func (a *App) keysCmd() *cobra.Command {
	var path string
	var timeout string
	cmd := &cobra.Command{
		Use:   "keys",
		Short: "List remote authorized keys or local known_hosts",
		Long: `keys reads an authorized_keys file on the selected hosts and prints
SHA256 fingerprints. The default path is .ssh/authorized_keys, relative to
the login home. The path is a single literal (no shell syntax, no "..").

cat and ls are checked by the policy engine. The attempt is audited.

keys known list and keys known remove manage the local TOFU known_hosts
file. Removing an entry does not accept a mismatched key while that entry
still exists. After it is removed, the next connection trusts the first key
it sees. A later different key is still rejected.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return a.keysRemote(path, timeout)
		},
	}
	cmd.Flags().StringVar(&path, "path", ".ssh/authorized_keys", "remote authorized_keys path (literal, no ~ expansion)")
	cmd.Flags().StringVar(&timeout, "timeout", "", "per-command timeout (duration or seconds; default 15s)")
	cmd.AddCommand(a.keysKnown())
	return cmd
}

func (a *App) keysRemote(pathFlag, timeout string) error {
	if err := a.rejectYesWithoutTTY(); err != nil {
		return err
	}
	remotePath, err := remote.ValidateRemotePath(pathFlag)
	if err != nil {
		return exitcode.New(exitcode.Usage, "%s", err.Error())
	}
	dur, err := parseTimeout(timeout)
	if err != nil {
		return exitcode.New(exitcode.Usage, "%s", err.Error())
	}
	if dur == 0 {
		dur = 15 * time.Second
	}
	listCmd := remote.ListCommand(remotePath)
	catCmd := remote.CatCommand(remotePath)
	meta := a.auditMeta(audit.OpKeys, listCmd+"; "+catCmd, "", remotePath)
	cfg, hosts, err := a.loadSelection()
	if err != nil {
		a.auditSelectionError(meta, hosts, err)
		return err
	}
	plan, err := a.plan(cfg, hosts, meta, func(eff guard.Effective) guard.Decision {
		return guard.Merge(guard.Decide(eff, listCmd), guard.Decide(eff, catCmd))
	})
	if err != nil {
		return err
	}
	type view struct {
		Host     string                 `json:"host"`
		Group    string                 `json:"group"`
		Env      string                 `json:"env"`
		Path     string                 `json:"path"`
		MTime    string                 `json:"mtime,omitempty"`
		ExitCode int                    `json:"exitCode"`
		Keys     []remote.AuthorizedKey `json:"keys"`
		Warnings []string               `json:"warnings,omitempty"`
		Error    string                 `json:"error,omitempty"`
	}
	views := make([]view, 0, len(plan))
	final := 0
	for _, p := range plan {
		if err := a.confirmPlanned(meta, p); err != nil {
			return err
		}
		a.header(p.host)
		start := time.Now()
		outputs, runErr := a.runCommands(p, []string{listCmd, catCmd}, dur)
		v := view{Host: p.host.Alias, Group: p.host.Group, Env: p.host.EnvName, Path: remotePath, Keys: []remote.AuthorizedKey{}}
		summary := ""
		if runErr != nil {
			v.Error = runErr.Error()
			v.ExitCode = exitcode.From(runErr)
			fmt.Fprintf(a.Err, "error: %s: %s\n", p.host.Alias, runErr.Error())
			summary = runErr.Error()
		} else {
			if len(outputs) > 0 {
				v.MTime = remote.ParseListMTime(outputs[0].Stdout)
			}
			if len(outputs) > 1 {
				v.ExitCode = outputs[1].ExitCode
				keys, warnings := remote.ParseAuthorizedKeys([]byte(outputs[1].Stdout))
				v.Keys = keys
				v.Warnings = warnings
				if !a.JSON {
					if v.MTime != "" {
						fmt.Fprintf(a.Out, "mtime %s\n", v.MTime)
					}
					if v.ExitCode != 0 {
						fmt.Fprintf(a.Err, "error: %s: cat exited %d\n", p.host.Alias, v.ExitCode)
					}
					for _, k := range keys {
						fmt.Fprintf(a.Out, "%d\t%s\t%s\t%s\n", k.Line, k.Type, k.Fingerprint, k.Comment)
					}
					for _, w := range warnings {
						fmt.Fprintf(a.Err, "warning: %s: %s\n", p.host.Alias, w)
					}
				}
				summary = summarizeOutputs(outputs[1].Stdout, outputs[1].Stderr, false, v.MTime)
			}
		}
		if err := a.auditHost(meta, p, start, v.ExitCode, runErr, summary); err != nil {
			return err
		}
		views = append(views, v)
		final = preferCode(final, v.ExitCode)
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

func (a *App) keysKnown() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "known",
		Short: "List or remove local TOFU known_hosts entries",
		Long: `known_hosts is the local trust store. The first key seen for a host is
stored. A different key is refused until that entry is removed. remove does
not pin or skip a new key; the next connection records whatever key the
server presents first.`,
	}
	cmd.AddCommand(a.keysKnownList(), a.keysKnownRemove())
	return cmd
}

func (a *App) keysKnownList() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List known_hosts fingerprints",
		RunE: func(cmd *cobra.Command, _ []string) error {
			entries, err := sshclient.ListKnownHosts(filepath.Join(a.Dir, config.KnownHostsName))
			if err != nil {
				return exitcode.New(exitcode.Usage, "%s", err.Error())
			}
			if a.JSON {
				return a.emit(map[string]any{"knownHosts": entries})
			}
			rows := make([][]string, len(entries))
			for i, e := range entries {
				rows[i] = []string{e.Marker, e.KeyType, e.Fingerprint, e.Comment}
			}
			a.table([]string{"MARKER", "TYPE", "FINGERPRINT", "COMMENT"}, rows)
			return nil
		},
	}
}

func (a *App) keysKnownRemove() *cobra.Command {
	return &cobra.Command{
		Use:   "remove <marker>",
		Short: "Remove a known_hosts entry by host marker",
		Long:  "marker is the hostname field as stored, or host, host:port, or [host]:port. Removing the entry lets the next connection trust the first key it sees. It does not weaken a key that is still stored.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			n, err := sshclient.RemoveKnownHost(filepath.Join(a.Dir, config.KnownHostsName), args[0])
			if err != nil {
				return exitcode.New(exitcode.Usage, "%s", err.Error())
			}
			if a.JSON {
				return a.emit(map[string]any{"removed": n, "marker": args[0]})
			}
			fmt.Fprintf(a.Out, "removed %d\n", n)
			return nil
		},
	}
}
