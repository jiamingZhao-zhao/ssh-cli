package cli

import (
	"fmt"
	"sort"

	"github.com/spf13/cobra"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/config"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/exitcode"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/guard"
)

func (a *App) groupCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "group", Short: "Manage groups"}
	cmd.AddCommand(a.groupAdd(), a.groupList(), a.groupRemove(), a.groupSetEnv())
	return cmd
}

func (a *App) groupAdd() *cobra.Command {
	var policy string
	var envName string
	var paths []string
	cmd := &cobra.Command{
		Use:   "add <name>",
		Short: "Add a group with exactly one env label",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			if !config.ValidName(name) {
				return exitcode.New(exitcode.Usage, "invalid group name %q", name)
			}
			if envName == "" {
				return exitcode.New(exitcode.Usage, "--env is required")
			}
			return config.Update(a.Dir, func(cfg *config.Config) error {
				if _, ok := cfg.Groups[name]; ok {
					return exitcode.New(exitcode.Usage, "group %q already exists", name)
				}
				if _, ok := cfg.Envs[envName]; !ok {
					return exitcode.New(exitcode.Usage, "unknown env %q", envName)
				}
				if policy != "" && !guard.KnownPolicy(cfg, policy) {
					return exitcode.New(exitcode.Usage, "unknown policy %q", policy)
				}
				if cfg.Groups == nil {
					cfg.Groups = map[string]*config.Group{}
				}
				cfg.Groups[name] = &config.Group{
					Env:            envName,
					Policy:         policy,
					ProtectedPaths: splitList(paths),
					Hosts:          map[string]*config.Host{},
				}
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&envName, "env", "", "env label (required, exactly one)")
	cmd.Flags().StringVar(&policy, "policy", "", "named policy")
	cmd.Flags().StringArrayVar(&paths, "protected-path", nil, "protected remote path (repeatable)")
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
				Env    string   `json:"env"`
				Policy string   `json:"policy,omitempty"`
				Hosts  int      `json:"hosts"`
				Paths  []string `json:"protectedPaths,omitempty"`
			}
			views := make([]view, 0, len(names))
			for _, name := range names {
				g := cfg.Groups[name]
				views = append(views, view{Name: name, Env: g.Env, Policy: g.Policy, Hosts: len(g.Hosts), Paths: g.ProtectedPaths})
			}
			if a.JSON {
				return a.emit(map[string]any{"groups": views})
			}
			rows := make([][]string, len(views))
			for i, v := range views {
				rows[i] = []string{v.Name, v.Env, v.Policy, fmt.Sprintf("%d", v.Hosts)}
			}
			a.table([]string{"NAME", "ENV", "POLICY", "HOSTS"}, rows)
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
			name := args[0]
			return config.Update(a.Dir, func(cfg *config.Config) error {
				g, ok := cfg.Groups[name]
				if !ok {
					return exitcode.New(exitcode.Usage, "group %q not found", name)
				}
				if len(g.Hosts) > 0 {
					return exitcode.New(exitcode.Usage, "group %q still has %d host(s)", name, len(g.Hosts))
				}
				delete(cfg.Groups, name)
				return nil
			})
		},
	}
}

func (a *App) groupSetEnv() *cobra.Command {
	return &cobra.Command{
		Use:   "set-env <name> <env>",
		Short: "Change a group's env label",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			name, envName := args[0], args[1]
			return config.Update(a.Dir, func(cfg *config.Config) error {
				g, ok := cfg.Groups[name]
				if !ok {
					return exitcode.New(exitcode.Usage, "group %q not found", name)
				}
				if _, ok := cfg.Envs[envName]; !ok {
					return exitcode.New(exitcode.Usage, "unknown env %q", envName)
				}
				if g.Env == "prod" && envName != "prod" {
					fmt.Fprintf(a.Err, "warning: group %s env changed from prod to %s\n", name, envName)
				}
				g.Env = envName
				return nil
			})
		},
	}
}

func (a *App) envCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "env", Short: "Manage env label definitions"}
	cmd.AddCommand(a.envAdd(), a.envList(), a.envRemove())
	return cmd
}

func (a *App) envAdd() *cobra.Command {
	var label, color, maxMode, defPol string
	cmd := &cobra.Command{
		Use:   "add <name>",
		Short: "Define an env label",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			if !config.ValidName(name) {
				return exitcode.New(exitcode.Usage, "invalid env name %q", name)
			}
			mode := config.Mode(maxMode)
			if !mode.Valid() {
				return exitcode.New(exitcode.Usage, "--max-mode must be readonly, standard, or admin")
			}
			return config.Update(a.Dir, func(cfg *config.Config) error {
				if _, ok := cfg.Envs[name]; ok {
					return exitcode.New(exitcode.Usage, "env %q already exists", name)
				}
				if defPol != "" && !guard.KnownPolicy(cfg, defPol) {
					return exitcode.New(exitcode.Usage, "unknown policy %q", defPol)
				}
				if cfg.Envs == nil {
					cfg.Envs = map[string]*config.Env{}
				}
				if label == "" {
					label = name
				}
				cfg.Envs[name] = &config.Env{
					Label: label, Color: color, MaxMode: mode, DefaultPolicy: defPol,
				}
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&label, "label", "", "display label")
	cmd.Flags().StringVar(&color, "color", "", "color name (red, yellow, green)")
	cmd.Flags().StringVar(&maxMode, "max-mode", "", "mode ceiling: readonly, standard, or admin")
	cmd.Flags().StringVar(&defPol, "default-policy", "", "named policy applied to every group in this env")
	_ = cmd.MarkFlagRequired("max-mode")
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
			}
			views := make([]view, 0, len(names))
			for _, name := range names {
				e := cfg.Envs[name]
				views = append(views, view{Name: name, Label: e.Label, Color: e.Color, MaxMode: string(e.MaxMode), DefaultPolicy: e.DefaultPolicy})
			}
			if a.JSON {
				return a.emit(map[string]any{"envs": views})
			}
			rows := make([][]string, len(views))
			for i, v := range views {
				rows[i] = []string{v.Name, v.Label, v.Color, v.MaxMode, v.DefaultPolicy}
			}
			a.table([]string{"NAME", "LABEL", "COLOR", "MAX_MODE", "DEFAULT_POLICY"}, rows)
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
			name := args[0]
			return config.Update(a.Dir, func(cfg *config.Config) error {
				if _, ok := cfg.Envs[name]; !ok {
					return exitcode.New(exitcode.Usage, "env %q not found", name)
				}
				for gname, g := range cfg.Groups {
					if g != nil && g.Env == name {
						return exitcode.New(exitcode.Usage, "env %q is still used by group %q", name, gname)
					}
				}
				delete(cfg.Envs, name)
				return nil
			})
		},
	}
}
