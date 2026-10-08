package catalog

import (
	"fmt"
	"strings"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/config"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/guard"
)

// GroupDraft is a group add or edit.
type GroupDraft struct {
	Name           string
	Env            string
	Policy         string
	ProtectedPaths []string
	HasPolicy      bool
	ClearPolicy    bool
	HasPaths       bool
}

// AddGroup creates an empty group. env must already exist.
func AddGroup(dir string, in GroupDraft) error {
	return config.Update(dir, func(cfg *config.Config) error {
		return addGroup(cfg, in)
	})
}

func addGroup(cfg *config.Config, in GroupDraft) error {
	name := strings.TrimSpace(in.Name)
	if !config.ValidName(name) {
		return fmt.Errorf("invalid group name %q", name)
	}
	envName := strings.TrimSpace(in.Env)
	if envName == "" {
		return fmt.Errorf("env is required")
	}
	if _, ok := cfg.Groups[name]; ok {
		return fmt.Errorf("group %q already exists", name)
	}
	if _, ok := cfg.Envs[envName]; !ok {
		return fmt.Errorf("unknown env %q", envName)
	}
	policy := strings.TrimSpace(in.Policy)
	if policy != "" && !guard.KnownPolicy(cfg, policy) {
		return fmt.Errorf("unknown policy %q", policy)
	}
	if cfg.Groups == nil {
		cfg.Groups = map[string]*config.Group{}
	}
	cfg.Groups[name] = &config.Group{
		Env:            envName,
		Policy:         policy,
		ProtectedPaths: cleanList(in.ProtectedPaths),
		Hosts:          map[string]*config.Host{},
	}
	return nil
}

// EditGroup changes policy and protected paths on an existing group.
func EditGroup(dir string, in GroupDraft) error {
	return config.Update(dir, func(cfg *config.Config) error {
		return editGroup(cfg, in)
	})
}

func editGroup(cfg *config.Config, in GroupDraft) error {
	name := strings.TrimSpace(in.Name)
	g, ok := cfg.Groups[name]
	if !ok || g == nil {
		return fmt.Errorf("group %q not found", name)
	}
	if !in.HasPolicy && !in.ClearPolicy && !in.HasPaths {
		return fmt.Errorf("no changes given")
	}
	if in.ClearPolicy && in.HasPolicy && strings.TrimSpace(in.Policy) != "" {
		return fmt.Errorf("use only one of policy and clear-policy")
	}
	if in.ClearPolicy || (in.HasPolicy && strings.TrimSpace(in.Policy) == "") {
		g.Policy = ""
	} else if in.HasPolicy {
		policy := strings.TrimSpace(in.Policy)
		if !guard.KnownPolicy(cfg, policy) {
			return fmt.Errorf("unknown policy %q", policy)
		}
		g.Policy = policy
	}
	if in.HasPaths {
		g.ProtectedPaths = cleanList(in.ProtectedPaths)
	}
	return nil
}

// RemoveGroup deletes an empty group.
func RemoveGroup(dir, name string) error {
	return config.Update(dir, func(cfg *config.Config) error {
		return removeGroup(cfg, name)
	})
}

func removeGroup(cfg *config.Config, name string) error {
	name = strings.TrimSpace(name)
	g, ok := cfg.Groups[name]
	if !ok {
		return fmt.Errorf("group %q not found", name)
	}
	if len(g.Hosts) > 0 {
		return fmt.Errorf("group %q still has %d host(s)", name, len(g.Hosts))
	}
	delete(cfg.Groups, name)
	return nil
}

// SetGroupEnv changes a group's env label and returns the previous env.
// Leaving prod is allowed here; signing that change is a later milestone.
func SetGroupEnv(dir, name, envName string) (string, error) {
	var previous string
	err := config.Update(dir, func(cfg *config.Config) error {
		prev, err := setGroupEnv(cfg, name, envName)
		previous = prev
		return err
	})
	return previous, err
}

func setGroupEnv(cfg *config.Config, name, envName string) (string, error) {
	name = strings.TrimSpace(name)
	envName = strings.TrimSpace(envName)
	g, ok := cfg.Groups[name]
	if !ok || g == nil {
		return "", fmt.Errorf("group %q not found", name)
	}
	if _, ok := cfg.Envs[envName]; !ok {
		return "", fmt.Errorf("unknown env %q", envName)
	}
	previous := g.Env
	g.Env = envName
	return previous, nil
}
