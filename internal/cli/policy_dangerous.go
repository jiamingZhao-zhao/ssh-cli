package cli

import (
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/catalog"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/config"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/exitcode"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/guard"
)

func (a *App) policyDangerous() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "dangerous",
		Short: "Show the dangerous-command catalog and its enforcement switch",
		Long: `Show the suggested dangerous-command catalog.

The catalog does not block commands until it is enabled and at least one rule
or extra deny pattern is selected. With no --env list, an enabled ruleset
applies to prod only. Other environments stay unrestricted unless named.
Prod readonly ceilings, confirm gates, protected paths, and audit are separate
and stay in effect either way.

policy dangerous set --enable --rule rm-root
policy dangerous set --enable --all
policy dangerous set --enable --all --env prod --env test
policy dangerous set --disable`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.Load(a.Dir)
			if err != nil {
				return exitcode.New(exitcode.Usage, "%s", err.Error())
			}
			report := guard.DescribeDangerous(cfg, "")
			if a.JSON {
				return a.emit(map[string]any{"dangerousCommands": report})
			}
			writeDangerousGlobal(a.Out, report)
			return nil
		},
	}
	cmd.AddCommand(a.policyDangerousSet())
	return cmd
}

func (a *App) policyDangerousSet() *cobra.Command {
	var (
		enable     bool
		disable    bool
		envs       []string
		rules      []string
		all        bool
		deny       []string
		clearRules bool
		clearDeny  bool
		clearEnvs  bool
	)
	cmd := &cobra.Command{
		Use:   "set",
		Short: "Enable or configure dangerous-command enforcement",
		Long: `Turn the dangerous-command catalog on or change which rules it enforces.

--enable without a rule stores the switch but still blocks nothing until a
catalog id or an extra --deny pattern is selected. The default scope is prod.
Pass --env for each environment that should enforce the list; omitting --env
leaves the saved scope unchanged, and a missing scope stays prod-only.
--disable keeps the saved list and stops enforcement. Shrinking that
enforcement requires the confirmation phrase "dangerous".`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if enable && disable {
				return exitcode.New(exitcode.Usage, "use only one of --enable and --disable")
			}
			draft := catalog.DangerousDraft{}
			if enable {
				on := true
				draft.Enable = &on
			}
			if disable {
				off := false
				draft.Enable = &off
			}
			if cmd.Flags().Changed("env") {
				draft.HasEnvs = true
				draft.Envs = splitList(envs)
			}
			if cmd.Flags().Changed("rule") {
				draft.HasRules = true
				draft.Rules = splitList(rules)
			}
			if cmd.Flags().Changed("deny") {
				draft.HasDeny = true
				draft.Deny = splitList(deny)
			}
			draft.AllRules = all
			draft.ClearRules = clearRules
			draft.ClearDeny = clearDeny
			draft.ClearEnvs = clearEnvs
			return a.withConfirm(func(phrase string) error {
				draft.HumanConfirm = phrase
				return catalog.SetDangerous(a.Dir, draft)
			})
		},
	}
	cmd.Flags().BoolVar(&enable, "enable", false, "turn enforcement on")
	cmd.Flags().BoolVar(&disable, "disable", false, "turn enforcement off and keep the saved list")
	cmd.Flags().StringArrayVar(&envs, "env", nil, "environment that enforces the list (repeatable; replaces the env list)")
	cmd.Flags().StringArrayVar(&rules, "rule", nil, "catalog id to enforce (repeatable; replaces the rule list)")
	cmd.Flags().BoolVar(&all, "all", false, "select every catalog rule")
	cmd.Flags().StringArrayVar(&deny, "deny", nil, "extra deny pattern (repeatable; replaces the extra list)")
	cmd.Flags().BoolVar(&clearRules, "clear-rules", false, "remove selected catalog rules")
	cmd.Flags().BoolVar(&clearDeny, "clear-deny", false, "remove extra deny patterns")
	cmd.Flags().BoolVar(&clearEnvs, "clear-envs", false, "restore the default prod-only scope")
	return cmd
}

func writeDangerous(w io.Writer, rep guard.DangerousReport) {
	scope := strings.Join(rep.Scope, ",")
	if rep.ScopeDefault {
		scope += " (default)"
	}
	fmt.Fprintf(w, "dangerous enabled=%t scope=%s enforced-here=%t\n", rep.Enabled, scope, rep.EnforcedHere)
	if len(rep.Active) == 0 {
		fmt.Fprintln(w, "dangerous-active (none)")
	} else {
		fmt.Fprintf(w, "dangerous-active %s\n", strings.Join(rep.Active, ", "))
	}
	switch {
	case len(rep.ExtraDeny) > 0:
		fmt.Fprintf(w, "dangerous-extra %s\n", strings.Join(rep.ExtraDeny, ", "))
	case len(rep.ConfiguredExtra) > 0:
		fmt.Fprintf(w, "dangerous-extra (not enforced here) %s\n", strings.Join(rep.ConfiguredExtra, ", "))
	default:
		fmt.Fprintln(w, "dangerous-extra (none)")
	}
	for _, item := range rep.Catalog {
		state := "inactive"
		switch {
		case item.Active:
			state = "active"
		case item.Selected:
			state = "selected"
		}
		fmt.Fprintf(w, "dangerous-catalog %s [%s] %s\n", item.ID, state, item.Summary)
	}
}

func writeDangerousGlobal(w io.Writer, rep guard.DangerousReport) {
	scope := strings.Join(rep.Scope, ", ")
	if rep.ScopeDefault {
		scope += " (default, prod only)"
	}
	fmt.Fprintf(w, "enabled %t\n", rep.Enabled)
	fmt.Fprintf(w, "scope %s\n", scope)
	selected := selectedIDs(rep)
	if len(selected) == 0 {
		fmt.Fprintln(w, "rules (none)")
	} else {
		fmt.Fprintf(w, "rules %s\n", strings.Join(selected, ", "))
	}
	if len(rep.ConfiguredExtra) == 0 {
		fmt.Fprintln(w, "extra (none)")
	} else {
		fmt.Fprintf(w, "extra %s\n", strings.Join(rep.ConfiguredExtra, ", "))
	}
	if rep.Enabled && len(selected) == 0 && len(rep.ConfiguredExtra) == 0 {
		fmt.Fprintln(w, "enforcement off until a catalog rule or extra deny pattern is selected")
	} else if !rep.Enabled {
		fmt.Fprintln(w, "enforcement off until enabled")
	} else {
		fmt.Fprintf(w, "enforcement on for %s\n", strings.Join(rep.Scope, ", "))
	}
	fmt.Fprintln(w, "catalog (suggested; inactive until enabled and selected):")
	for _, item := range rep.Catalog {
		mark := "suggested"
		if item.Selected {
			mark = "selected"
		}
		fmt.Fprintf(w, "  %s [%s] %s\n", item.ID, mark, item.Summary)
	}
}

func selectedIDs(rep guard.DangerousReport) []string {
	var ids []string
	for _, item := range rep.Catalog {
		if item.Selected {
			ids = append(ids, item.ID)
		}
	}
	return ids
}
