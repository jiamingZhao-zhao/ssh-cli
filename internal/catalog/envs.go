package catalog

import (
	"fmt"
	"strings"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/config"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/guard"
)

// EnvDraft is an env-label add or edit.
type EnvDraft struct {
	Name               string
	Label              string
	Color              string
	MaxMode            string
	DefaultPolicy      string
	NoDataOutflow      bool
	HasLabel           bool
	HasColor           bool
	HasMaxMode         bool
	HasDefaultPolicy   bool
	ClearDefaultPolicy bool
	HasNoDataOutflow   bool
}

// AddEnv defines an env label. maxMode is required.
func AddEnv(dir string, in EnvDraft) error {
	return config.Update(dir, func(cfg *config.Config) error {
		return addEnv(cfg, in)
	})
}

func addEnv(cfg *config.Config, in EnvDraft) error {
	name := strings.TrimSpace(in.Name)
	if !config.ValidName(name) {
		return fmt.Errorf("invalid env name %q", name)
	}
	mode := config.Mode(strings.TrimSpace(in.MaxMode))
	if !mode.Valid() {
		return fmt.Errorf("maxMode must be readonly, standard, or admin")
	}
	if _, ok := cfg.Envs[name]; ok {
		return fmt.Errorf("env %q already exists", name)
	}
	policy := strings.TrimSpace(in.DefaultPolicy)
	if policy != "" && !guard.KnownPolicy(cfg, policy) {
		return fmt.Errorf("unknown policy %q", policy)
	}
	if cfg.Envs == nil {
		cfg.Envs = map[string]*config.Env{}
	}
	label := strings.TrimSpace(in.Label)
	if label == "" {
		label = name
	}
	cfg.Envs[name] = &config.Env{
		Label:         label,
		Color:         strings.TrimSpace(in.Color),
		MaxMode:       mode,
		DefaultPolicy: policy,
		NoDataOutflow: in.NoDataOutflow,
	}
	return nil
}

// EditEnv changes fields that were set on the draft.
func EditEnv(dir string, in EnvDraft) error {
	return config.Update(dir, func(cfg *config.Config) error {
		return editEnv(cfg, in)
	})
}

func editEnv(cfg *config.Config, in EnvDraft) error {
	name := strings.TrimSpace(in.Name)
	env, ok := cfg.Envs[name]
	if !ok || env == nil {
		return fmt.Errorf("env %q not found", name)
	}
	if !in.HasLabel && !in.HasColor && !in.HasMaxMode && !in.HasDefaultPolicy && !in.ClearDefaultPolicy && !in.HasNoDataOutflow {
		return fmt.Errorf("no changes given")
	}
	if in.ClearDefaultPolicy && in.HasDefaultPolicy && strings.TrimSpace(in.DefaultPolicy) != "" {
		return fmt.Errorf("use only one of default-policy and clear-default-policy")
	}
	if in.HasLabel {
		label := strings.TrimSpace(in.Label)
		if label == "" {
			label = name
		}
		env.Label = label
	}
	if in.HasColor {
		env.Color = strings.TrimSpace(in.Color)
	}
	if in.HasMaxMode {
		mode := config.Mode(strings.TrimSpace(in.MaxMode))
		if !mode.Valid() {
			return fmt.Errorf("maxMode must be readonly, standard, or admin")
		}
		env.MaxMode = mode
	}
	if in.ClearDefaultPolicy || (in.HasDefaultPolicy && strings.TrimSpace(in.DefaultPolicy) == "") {
		env.DefaultPolicy = ""
	} else if in.HasDefaultPolicy {
		policy := strings.TrimSpace(in.DefaultPolicy)
		if !guard.KnownPolicy(cfg, policy) {
			return fmt.Errorf("unknown policy %q", policy)
		}
		env.DefaultPolicy = policy
	}
	if in.HasNoDataOutflow {
		env.NoDataOutflow = in.NoDataOutflow
	}
	return nil
}

// RemoveEnv deletes an env label that no group uses.
func RemoveEnv(dir, name string) error {
	return config.Update(dir, func(cfg *config.Config) error {
		return removeEnv(cfg, name)
	})
}

func removeEnv(cfg *config.Config, name string) error {
	name = strings.TrimSpace(name)
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
}
