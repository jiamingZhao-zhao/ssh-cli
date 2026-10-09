package cli

import (
	"fmt"
	"sort"

	"github.com/spf13/cobra"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/catalog"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/config"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/exitcode"
)

func (a *App) groupCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "group", Short: "Manage groups"}
	cmd.AddCommand(a.groupAdd(), a.groupList(), a.groupEdit(), a.groupRemove(), a.groupSetEnv())
	return cmd
}

func (a *App) groupAdd() *cobra.Command {
	var policy string
	var envName string
	var label string
	var paths []string
	cmd := &cobra.Command{
		Use:   "add <name>",
		Short: "Add a group with exactly one env label",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if envName == "" {
				return exitcode.New(exitcode.Usage, "--env is required")
			}
			return catalogErr(catalog.AddGroup(a.Dir, catalog.GroupDraft{
				Name:           args[0],
				Env:            envName,
				Label:          label,
				Policy:         policy,
				ProtectedPaths: splitList(paths),
			}))
		},
	}
	cmd.Flags().StringVar(&envName, "env", "", "env label (required, exactly one)")
	cmd.Flags().StringVar(&label, "label", "", "display label (for example a Chinese name)")
	cmd.Flags().StringVar(&policy, "policy", "", "named policy")
	cmd.Flags().StringArrayVar(&paths, "protected-path", nil, "protected remote path (repeatable)")
	return cmd
}

func (a *App) groupEdit() *cobra.Command {
	var policy string
	var label string
	var paths []string
	var clearPolicy bool
	var clearPaths bool
	cmd := &cobra.Command{
		Use:   "edit <name>",
		Short: "Edit a group's display label, named policy, or protected paths",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			draft := catalog.GroupDraft{Name: args[0], ClearPolicy: clearPolicy}
			if cmd.Flags().Changed("label") {
				draft.HasLabel = true
				draft.Label = label
			}
			if cmd.Flags().Changed("policy") {
				draft.HasPolicy = true
				draft.Policy = policy
			}
			if clearPaths {
				draft.HasPaths = true
			} else if cmd.Flags().Changed("protected-path") {
				draft.HasPaths = true
				draft.ProtectedPaths = splitList(paths)
			}
			return a.withConfirm(func(phrase string) error {
				draft.HumanConfirm = phrase
				return catalog.EditGroup(a.Dir, draft)
			})
		},
	}
	cmd.Flags().StringVar(&label, "label", "", "display label (empty clears it)")
	cmd.Flags().StringVar(&policy, "policy", "", "named policy (empty clears it)")
	cmd.Flags().StringArrayVar(&paths, "protected-path", nil, "protected remote path (repeatable; replaces the list)")
	cmd.Flags().BoolVar(&clearPolicy, "clear-policy", false, "remove the named policy")
	cmd.Flags().BoolVar(&clearPaths, "clear-protected-paths", false, "remove protected paths")
	return cmd
}

func (a *App) groupList() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List groups",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.Load(a.Dir)
			if err != nil {
				return exitcode.New(exitcode.Usage, "%s", err.Error())
			}
			names := make([]string, 0, len(cfg.Groups))
			for name, g := range cfg.Groups {
				if a.Env != "" && (g == nil || g.Env != a.Env) {
					continue
				}
				names = append(names, name)
			}
			sort.Strings(names)
			type view struct {
				Name   string   `json:"name"`
				Label  string   `json:"label,omitempty"`
				Env    string   `json:"env"`
				Policy string   `json:"policy,omitempty"`
				Hosts  int      `json:"hosts"`
				Paths  []string `json:"protectedPaths,omitempty"`
			}
			views := make([]view, 0, len(names))
			for _, name := range names {
				g := cfg.Groups[name]
				views = append(views, view{Name: name, Label: g.Label, Env: g.Env, Policy: g.Policy, Hosts: len(g.Hosts), Paths: g.ProtectedPaths})
			}
			if a.JSON {
				return a.emit(map[string]any{"groups": views})
			}
			rows := make([][]string, len(views))
			for i, v := range views {
				rows[i] = []string{v.Name, v.Label, v.Env, v.Policy, fmt.Sprintf("%d", v.Hosts)}
			}
			a.table([]string{"NAME", "LABEL", "ENV", "POLICY", "HOSTS"}, rows)
			return nil
		},
	}
}

func (a *App) groupRemove() *cobra.Command {
	return &cobra.Command{
		Use:   "remove <name>",
		Short: "Remove an empty group",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return catalogErr(catalog.RemoveGroup(a.Dir, args[0]))
		},
	}
}

func (a *App) groupSetEnv() *cobra.Command {
	return &cobra.Command{
		Use:   "set-env <name> <env>",
		Short: "Change a group's env label",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			var prev string
			err := a.withConfirm(func(phrase string) error {
				p, e := catalog.SetGroupEnvConfirmed(a.Dir, args[0], args[1], phrase, "")
				if e == nil {
					prev = p
				}
				return e
			})
			if err != nil {
				return err
			}
			if prev == "prod" && args[1] != "prod" {
				fmt.Fprintf(a.Err, "warning: group %s env changed from prod to %s\n", args[0], args[1])
			}
			return nil
		},
	}
}

func (a *App) envCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "env", Short: "Manage env label definitions"}
	cmd.AddCommand(a.envAdd(), a.envList(), a.envEdit(), a.envRemove())
	return cmd
}

func (a *App) envAdd() *cobra.Command {
	var label, color, maxMode, defPol string
	var noOut bool
	cmd := &cobra.Command{
		Use:   "add <name>",
		Short: "Define an env label",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return catalogErr(catalog.AddEnv(a.Dir, catalog.EnvDraft{
				Name:          args[0],
				Label:         label,
				Color:         color,
				MaxMode:       maxMode,
				DefaultPolicy: defPol,
				NoDataOutflow: noOut,
			}))
		},
	}
	cmd.Flags().StringVar(&label, "label", "", "display label")
	cmd.Flags().StringVar(&color, "color", "", "color name (red, orange, yellow, green)")
	cmd.Flags().StringVar(&maxMode, "max-mode", "", "mode ceiling: readonly, standard, or admin")
	cmd.Flags().StringVar(&defPol, "default-policy", "", "named policy applied to every group in this env")
	cmd.Flags().BoolVar(&noOut, "no-data-outflow", false, "forbid download, cross-env relay, and exec stdout/stderr unless --allow-outflow")
	_ = cmd.MarkFlagRequired("max-mode")
	return cmd
}

func (a *App) envEdit() *cobra.Command {
	var label, color, maxMode, defPol string
	var noOut, allowOut, clearPol bool
	cmd := &cobra.Command{
		Use:   "edit <name>",
		Short: "Edit an env label",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if noOut && allowOut {
				return exitcode.New(exitcode.Usage, "use only one of --no-data-outflow and --allow-data-outflow")
			}
			draft := catalog.EnvDraft{Name: args[0], ClearDefaultPolicy: clearPol}
			if cmd.Flags().Changed("label") {
				draft.HasLabel = true
				draft.Label = label
			}
			if cmd.Flags().Changed("color") {
				draft.HasColor = true
				draft.Color = color
			}
			if cmd.Flags().Changed("max-mode") {
				draft.HasMaxMode = true
				draft.MaxMode = maxMode
			}
			if cmd.Flags().Changed("default-policy") {
				draft.HasDefaultPolicy = true
				draft.DefaultPolicy = defPol
			}
			if noOut || allowOut {
				draft.HasNoDataOutflow = true
				draft.NoDataOutflow = noOut
			}
			return a.withConfirm(func(phrase string) error {
				draft.HumanConfirm = phrase
				return catalog.EditEnv(a.Dir, draft)
			})
		},
	}
	cmd.Flags().StringVar(&label, "label", "", "display label")
	cmd.Flags().StringVar(&color, "color", "", "color name")
	cmd.Flags().StringVar(&maxMode, "max-mode", "", "mode ceiling: readonly, standard, or admin")
	cmd.Flags().StringVar(&defPol, "default-policy", "", "named default policy (empty clears it)")
	cmd.Flags().BoolVar(&clearPol, "clear-default-policy", false, "remove the default policy")
	cmd.Flags().BoolVar(&noOut, "no-data-outflow", false, "forbid download, cross-env relay, and exec stdout/stderr unless --allow-outflow")
	cmd.Flags().BoolVar(&allowOut, "allow-data-outflow", false, "allow data outflow")
	return cmd
}

func (a *App) envList() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List env labels",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.Load(a.Dir)
			if err != nil {
				return exitcode.New(exitcode.Usage, "%s", err.Error())
			}
			names := make([]string, 0, len(cfg.Envs))
			for name := range cfg.Envs {
				names = append(names, name)
			}
			sort.Strings(names)
			type view struct {
				Name          string `json:"name"`
				Label         string `json:"label,omitempty"`
				Color         string `json:"color,omitempty"`
				MaxMode       string `json:"maxMode"`
				DefaultPolicy string `json:"defaultPolicy,omitempty"`
				NoDataOutflow bool   `json:"noDataOutflow,omitempty"`
				Builtin       bool   `json:"builtin,omitempty"`
			}
			views := make([]view, 0, len(names))
			for _, name := range names {
				e := cfg.Envs[name]
				views = append(views, view{
					Name: name, Label: e.Label, Color: e.Color, MaxMode: string(e.MaxMode),
					DefaultPolicy: e.DefaultPolicy, NoDataOutflow: e.NoDataOutflow,
					Builtin: config.IsBuiltinEnv(name),
				})
			}
			if a.JSON {
				return a.emit(map[string]any{"envs": views})
			}
			rows := make([][]string, len(views))
			for i, v := range views {
				locked := ""
				if v.Builtin {
					locked = "yes"
				}
				rows[i] = []string{v.Name, v.Label, v.Color, v.MaxMode, v.DefaultPolicy, locked}
			}
			a.table([]string{"NAME", "LABEL", "COLOR", "MAX_MODE", "DEFAULT_POLICY", "BUILTIN"}, rows)
			return nil
		},
	}
}

func (a *App) envRemove() *cobra.Command {
	return &cobra.Command{
		Use:   "remove <name>",
		Short: "Remove an env label that no group uses",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return catalogErr(catalog.RemoveEnv(a.Dir, args[0]))
		},
	}
}
