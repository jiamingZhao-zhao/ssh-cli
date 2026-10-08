package ui

import (
	"fmt"
	"sort"
	"strings"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/config"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/guard"
)

// PolicyDraft writes a named policy. Has* fields distinguish omitted from empty.
// Allow nil with HasAllow clears the allow-list back to universal.
type PolicyDraft struct {
	Name    string
	Mode    string
	Allow   *[]string
	Deny    []string
	Confirm []string

	HasMode    bool
	HasAllow   bool
	HasDeny    bool
	HasConfirm bool
}

// EnvDraft edits an env label. maxMode is the ceiling; defaultPolicy is the
// named policy applied at the env layer. Env has no inline allow/deny list.
type EnvDraft struct {
	Name          string
	Label         string
	Color         string
	MaxMode       string
	DefaultPolicy string

	NoDataOutflow bool

	HasLabel         bool
	HasColor         bool
	HasMaxMode       bool
	HasDefaultPolicy bool
	HasNoDataOutflow bool
}

// AddPolicy creates a named policy. Naming a built-in copies that built-in
// first, then applies the draft, so capabilities on the built-in are kept
// unless a later edit replaces the whole object.
func AddPolicy(dir string, in PolicyDraft) error {
	name := strings.TrimSpace(in.Name)
	if !config.ValidName(name) {
		return fmt.Errorf("invalid policy name")
	}
	if in.HasMode {
		if err := checkMode(in.Mode, true); err != nil {
			return err
		}
	}
	return config.Update(dir, func(cfg *config.Config) error {
		if cfg.Policies != nil {
			if _, ok := cfg.Policies[name]; ok {
				return fmt.Errorf("policy %q already exists", name)
			}
		}
		pol := &config.Policy{}
		if b, ok := guard.BuiltinPolicy(name); ok {
			pol = b
		}
		applyPolicy(pol, in)
		if cfg.Policies == nil {
			cfg.Policies = map[string]*config.Policy{}
		}
		cfg.Policies[name] = pol
		return nil
	})
}

// UpdatePolicy edits a policy that is already stored in hosts.yaml.
func UpdatePolicy(dir string, in PolicyDraft) error {
	name := strings.TrimSpace(in.Name)
	if name == "" {
		return fmt.Errorf("policy is required")
	}
	if !in.HasMode && !in.HasAllow && !in.HasDeny && !in.HasConfirm {
		return fmt.Errorf("no changes given")
	}
	if in.HasMode {
		if err := checkMode(in.Mode, true); err != nil {
			return err
		}
	}
	return config.Update(dir, func(cfg *config.Config) error {
		if cfg.Policies == nil {
			return fmt.Errorf("policy %q is not in the config", name)
		}
		pol, ok := cfg.Policies[name]
		if !ok || pol == nil {
			return fmt.Errorf("policy %q is not in the config", name)
		}
		applyPolicy(pol, in)
		return nil
	})
}

// RemovePolicy deletes a stored policy. A custom policy still referenced by an
// env, group, or host is kept. Removing a built-in override restores the
// built-in definition.
func RemovePolicy(dir, name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("policy is required")
	}
	return config.Update(dir, func(cfg *config.Config) error {
		if cfg.Policies == nil {
			return fmt.Errorf("policy %q is not in the config", name)
		}
		if _, ok := cfg.Policies[name]; !ok {
			return fmt.Errorf("policy %q is not in the config", name)
		}
		if _, builtin := guard.BuiltinPolicy(name); !builtin {
			if users := policyUsers(cfg, name); len(users) > 0 {
				return fmt.Errorf("policy %q is still used by %s", name, strings.Join(users, ", "))
			}
		}
		delete(cfg.Policies, name)
		if len(cfg.Policies) == 0 {
			cfg.Policies = nil
		}
		return nil
	})
}

func applyPolicy(pol *config.Policy, in PolicyDraft) {
	if in.HasMode {
		pol.Mode = config.Mode(strings.TrimSpace(in.Mode))
	}
	if in.HasAllow {
		pol.Allow = cloneListPtr(in.Allow)
	}
	if in.HasDeny {
		pol.Deny = append([]string(nil), in.Deny...)
	}
	if in.HasConfirm {
		pol.Confirm = append([]string(nil), in.Confirm...)
	}
}

func policyUsers(cfg *config.Config, name string) []string {
	var users []string
	for ename, e := range cfg.Envs {
		if e != nil && e.DefaultPolicy == name {
			users = append(users, "env "+ename)
		}
	}
	for gname, g := range cfg.Groups {
		if g == nil {
			continue
		}
		if g.Policy == name {
			users = append(users, "group "+gname)
		}
		for alias, h := range g.Hosts {
			if h != nil && h.Policy == name {
				users = append(users, "host "+alias)
			}
		}
	}
	sort.Strings(users)
	return users
}

// AddEnv defines an env label. maxMode is required, matching `env add`.
func AddEnv(dir string, in EnvDraft) error {
	name := strings.TrimSpace(in.Name)
	if config.IsBuiltinEnv(name) {
		return fmt.Errorf("env %q is built-in and cannot be changed", name)
	}
	if !config.ValidName(name) {
		return fmt.Errorf("invalid env name")
	}
	mode := config.Mode(strings.TrimSpace(in.MaxMode))
	if !mode.Valid() {
		return fmt.Errorf("maxMode must be readonly, standard, or admin")
	}
	label := strings.TrimSpace(in.Label)
	if label == "" {
		label = name
	}
	color := strings.TrimSpace(in.Color)
	def := strings.TrimSpace(in.DefaultPolicy)
	return config.Update(dir, func(cfg *config.Config) error {
		if _, ok := cfg.Envs[name]; ok {
			return fmt.Errorf("env %q already exists", name)
		}
		if def != "" && !guard.KnownPolicy(cfg, def) {
			return fmt.Errorf("unknown policy %q", def)
		}
		if cfg.Envs == nil {
			cfg.Envs = map[string]*config.Env{}
		}
		cfg.Envs[name] = &config.Env{
			Label: label, Color: color, MaxMode: mode, DefaultPolicy: def,
			NoDataOutflow: in.NoDataOutflow,
		}
		return nil
	})
}

// UpdateEnv changes an env ceiling and its default named policy.
// Label, color, breakGlass, and noDataOutflow are left as they are unless sent.
func UpdateEnv(dir string, in EnvDraft) error {
	name := strings.TrimSpace(in.Name)
	if name == "" {
		return fmt.Errorf("env is required")
	}
	if config.IsBuiltinEnv(name) {
		return fmt.Errorf("env %q is built-in and cannot be changed", name)
	}
	if !in.HasLabel && !in.HasColor && !in.HasMaxMode && !in.HasDefaultPolicy && !in.HasNoDataOutflow {
		return fmt.Errorf("no changes given")
	}
	if in.HasMaxMode {
		if err := checkMode(in.MaxMode, false); err != nil {
			return err
		}
	}
	return config.Update(dir, func(cfg *config.Config) error {
		env, ok := cfg.Envs[name]
		if !ok || env == nil {
			return fmt.Errorf("env %q not found", name)
		}
		if in.HasLabel {
			env.Label = strings.TrimSpace(in.Label)
		}
		if in.HasColor {
			env.Color = strings.TrimSpace(in.Color)
		}
		if in.HasMaxMode {
			env.MaxMode = config.Mode(strings.TrimSpace(in.MaxMode))
		}
		if in.HasDefaultPolicy {
			def := strings.TrimSpace(in.DefaultPolicy)
			if def != "" && !guard.KnownPolicy(cfg, def) {
				return fmt.Errorf("unknown policy %q", def)
			}
			env.DefaultPolicy = def
		}
		if in.HasNoDataOutflow {
			env.NoDataOutflow = in.NoDataOutflow
		}
		return nil
	})
}

// RemoveEnv deletes an env label that no group uses, matching `env remove`.
func RemoveEnv(dir, name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("env is required")
	}
	if config.IsBuiltinEnv(name) {
		return fmt.Errorf("env %q is built-in and cannot be changed", name)
	}
	return config.Update(dir, func(cfg *config.Config) error {
		if _, ok := cfg.Envs[name]; !ok {
			return fmt.Errorf("env %q not found", name)
		}
		for gname, g := range cfg.Groups {
			if g != nil && g.Env == name {
				return fmt.Errorf("env %q is still used by group %q", name, gname)
			}
		}
		delete(cfg.Envs, name)
		return nil
	})
}

func checkMode(mode string, allowUnset bool) error {
	m := config.Mode(strings.TrimSpace(mode))
	if m == config.ModeUnset && allowUnset {
		return nil
	}
	if !m.Valid() {
		return fmt.Errorf("invalid mode %q", strings.TrimSpace(mode))
	}
	return nil
}
