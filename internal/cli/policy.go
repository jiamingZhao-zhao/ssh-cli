package cli

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/exitcode"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/guard"
)

func (a *App) policyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Show the effective policy for a host",
		Long: `Show the merged policy for a host, explain one command, and edit named policies.

policy add and policy edit write hosts.yaml through the same store as the localhost UI.
Signing those edits (policy HMAC) is not part of this version.`,
	}
	cmd.AddCommand(a.policyShow(), a.policyExplain(), a.policyList(), a.policyAdd(), a.policyEdit(), a.policyRemove())
	return cmd
}

func (a *App) policyShow() *cobra.Command {
	return &cobra.Command{
		Use:   "show",
		Short: "Show the merged policy for the selected host(s)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, hosts, err := a.loadSelection()
			if err != nil {
				return err
			}
			type view struct {
				Host         string             `json:"host"`
				Group        string             `json:"group"`
				Env          string             `json:"env"`
				Mode         string             `json:"mode"`
				ModeClamped  bool               `json:"modeClamped"`
				Allow        []string           `json:"allow,omitempty"`
				AllowAll     bool               `json:"allowUniversal"`
				AllowEmpty   bool               `json:"allowEmpty"`
				Deny         []string           `json:"deny,omitempty"`
				Confirm      []string           `json:"confirm,omitempty"`
				Capabilities guard.Capabilities `json:"capabilities"`
				Protected    []string           `json:"protectedPaths,omitempty"`
				Warnings     []string           `json:"warnings,omitempty"`
				BuiltinDeny  []string           `json:"builtinDeny"`
			}
			views := make([]view, 0, len(hosts))
			for _, h := range hosts {
				eff, err := guard.Resolve(cfg, h, false)
				if err != nil {
					return exitcode.New(exitcode.Usage, "%s", err.Error())
				}
				views = append(views, view{
					Host: h.Alias, Group: h.Group, Env: h.EnvName,
					Mode: string(eff.Mode), ModeClamped: eff.Clamped,
					Allow: eff.Allow, AllowAll: eff.AllowAll, AllowEmpty: eff.AllowEmpty,
					Deny: eff.Deny, Confirm: eff.Confirm, Capabilities: eff.Caps(),
					Protected: eff.Protected, Warnings: eff.Warnings,
					BuiltinDeny: []string{
						"rm -rf of filesystem root",
						"mkfs",
						"dd onto a disk device",
						"redirect onto a disk device",
						"chmod/chown of filesystem root",
						"fork bomb",
					},
				})
			}
			if a.JSON {
				return a.emit(map[string]any{"policies": views})
			}
			for i, v := range views {
				if i > 0 {
					fmt.Fprintln(a.Out)
				}
				fmt.Fprintf(a.Out, "host %s  group %s  env %s\n", v.Host, v.Group, v.Env)
				fmt.Fprintf(a.Out, "mode %s\n", v.Mode)
				if v.AllowAll {
					fmt.Fprintln(a.Out, "allow (universal)")
				} else if v.AllowEmpty {
					fmt.Fprintln(a.Out, "allow (empty intersection)")
				} else {
					fmt.Fprintf(a.Out, "allow %s\n", strings.Join(v.Allow, ", "))
				}
				if len(v.Deny) == 0 {
					fmt.Fprintln(a.Out, "deny (none beyond built-in)")
				} else {
					fmt.Fprintf(a.Out, "deny %s\n", strings.Join(v.Deny, ", "))
				}
				fmt.Fprintf(a.Out, "builtin-deny %s\n", strings.Join(v.BuiltinDeny, ", "))
				if len(v.Confirm) == 0 {
					fmt.Fprintln(a.Out, "confirm (none)")
				} else {
					fmt.Fprintf(a.Out, "confirm %s\n", strings.Join(v.Confirm, ", "))
				}
				fmt.Fprintf(a.Out, "capabilities upload=%t download=%t relay=%s forward=%t\n",
					v.Capabilities.Upload, v.Capabilities.Download, v.Capabilities.Relay, v.Capabilities.Forward)
				if len(v.Protected) > 0 {
					fmt.Fprintf(a.Out, "protected %s\n", strings.Join(v.Protected, ", "))
				}
				for _, w := range v.Warnings {
					fmt.Fprintf(a.Out, "warning: %s\n", w)
				}
			}
			return nil
		},
	}
}

func (a *App) policyExplain() *cobra.Command {
	return &cobra.Command{
		Use:   "explain -- <command>",
		Short: "Explain which rule allows or denies a command",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return exitcode.New(exitcode.Usage, "pass a command after --")
			}
			command := strings.Join(args, " ")
			cfg, hosts, err := a.loadSelection()
			if err != nil {
				return err
			}
			type view struct {
				Host         string          `json:"host"`
				Group        string          `json:"group"`
				Env          string          `json:"env"`
				Command      string          `json:"command"`
				Allowed      bool            `json:"allowed"`
				NeedsConfirm bool            `json:"needsConfirm"`
				Mode         string          `json:"mode"`
				Commands     []string        `json:"commands,omitempty"`
				Findings     []guard.Finding `json:"findings,omitempty"`
			}
			views := make([]view, 0, len(hosts))
			denied := false
			for _, h := range hosts {
				eff, err := guard.Resolve(cfg, h, false)
				if err != nil {
					return exitcode.New(exitcode.Usage, "%s", err.Error())
				}
				dec := guard.Decide(eff, command)
				if !dec.Allowed {
					denied = true
				}
				views = append(views, view{
					Host: h.Alias, Group: h.Group, Env: h.EnvName, Command: command,
					Allowed: dec.Allowed, NeedsConfirm: dec.NeedsConfirm, Mode: dec.Mode,
					Commands: dec.Commands, Findings: dec.Findings,
				})
			}
			if a.JSON {
				if err := a.emit(map[string]any{"explanations": views}); err != nil {
					return err
				}
			} else {
				for i, v := range views {
					if i > 0 {
						fmt.Fprintln(a.Out)
					}
					result := "ALLOW"
					if !v.Allowed {
						result = "DENY"
					} else if v.NeedsConfirm {
						result = "CONFIRM"
					}
					fmt.Fprintf(a.Out, "host %s  group %s  env %s  mode %s\n", v.Host, v.Group, v.Env, v.Mode)
					fmt.Fprintf(a.Out, "command: %s\n", v.Command)
					fmt.Fprintf(a.Out, "result: %s\n", result)
					if len(v.Commands) > 0 {
						fmt.Fprintf(a.Out, "inspected: %s\n", strings.Join(v.Commands, " | "))
					}
					for _, f := range v.Findings {
						fmt.Fprintf(a.Out, "- %s %s: %s\n", f.Layer, f.Kind, f.Detail)
					}
				}
			}
			if denied {
				return exitcode.Silent(exitcode.Denied)
			}
			return nil
		},
	}
}
