package catalog

import (
	"fmt"
	"strings"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/config"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/confirmgate"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/guard"
)

// GroupDraft is a group add or edit.
type GroupDraft struct {
	Name           string
	Env            string
	Label          string
	Policy         string
	ProtectedPaths []string
	HasLabel       bool
	HasPolicy      bool
	ClearPolicy    bool
	HasPaths       bool

	HumanConfirm string
	Actor        string
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
	label, err := config.CleanLabel(in.Label)
	if err != nil {
		return err
	}
	if cfg.Groups == nil {
		cfg.Groups = map[string]*config.Group{}
	}
	cfg.Groups[name] = &config.Group{
		Env:            envName,
		Label:          label,
		Policy:         policy,
		ProtectedPaths: cleanList(in.ProtectedPaths),
		Hosts:          map[string]*config.Host{},
	}
	return nil
}

// EditGroup changes policy and protected paths on an existing group.
func EditGroup(dir string, in GroupDraft) error {
	var needs []confirmgate.Need
	err := config.Update(dir, func(cfg *config.Config) error {
		n, err := editGroup(dir, cfg, in)
		needs = n
		return err
	})
	if err != nil {
		return err
	}
	confirmgate.RecordOK(dir, in.Actor, needs)
	return nil
}

func editGroup(dir string, cfg *config.Config, in GroupDraft) ([]confirmgate.Need, error) {
	name := strings.TrimSpace(in.Name)
	g, ok := cfg.Groups[name]
	if !ok || g == nil {
		return nil, fmt.Errorf("group %q not found", name)
	}
	if !in.HasLabel && !in.HasPolicy && !in.ClearPolicy && !in.HasPaths {
		return nil, fmt.Errorf("no changes given")
	}
	if in.ClearPolicy && in.HasPolicy && strings.TrimSpace(in.Policy) != "" {
		return nil, fmt.Errorf("use only one of policy and clear-policy")
	}
	var needs []confirmgate.Need
	if in.ClearPolicy || in.HasPolicy {
		next := ""
		if in.HasPolicy && !in.ClearPolicy {
			next = strings.TrimSpace(in.Policy)
		}
		if next != "" && !guard.KnownPolicy(cfg, next) {
			return nil, fmt.Errorf("unknown policy %q", next)
		}
		if confirmgate.NamedWider(cfg, g.Policy, next) {
			needs = append(needs, confirmgate.WidenNeed(name, "group "+name+" policy would widen"))
		}
	}
	nextPaths := g.ProtectedPaths
	if in.HasPaths {
		nextPaths = cleanList(in.ProtectedPaths)
		if confirmgate.ListShrinks(g.ProtectedPaths, nextPaths) {
			needs = append(needs, confirmgate.WidenNeed(name, "group "+name+" protected paths would shrink"))
		}
	}
	if err := confirmgate.Require(dir, in.Actor, in.HumanConfirm, needs); err != nil {
		return nil, err
	}
	if in.HasLabel {
		label, err := config.CleanLabel(in.Label)
		if err != nil {
			return nil, err
		}
		g.Label = label
	}
	if in.ClearPolicy || (in.HasPolicy && strings.TrimSpace(in.Policy) == "") {
		g.Policy = ""
	} else if in.HasPolicy {
		g.Policy = strings.TrimSpace(in.Policy)
	}
	if in.HasPaths {
		g.ProtectedPaths = nextPaths
	}
	return needs, nil
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
// Leaving prod requires the phrase "prod" via SetGroupEnvConfirmed.
func SetGroupEnv(dir, name, envName string) (string, error) {
	return SetGroupEnvConfirmed(dir, name, envName, "", "")
}

// SetGroupEnvConfirmed is SetGroupEnv with the human phrase and audit actor.
func SetGroupEnvConfirmed(dir, name, envName, phrase, actor string) (string, error) {
	var previous string
	var needs []confirmgate.Need
	err := config.Update(dir, func(cfg *config.Config) error {
		prev, n, err := setGroupEnv(dir, cfg, name, envName, phrase, actor)
		previous = prev
		needs = n
		return err
	})
	if err != nil {
		return previous, err
	}
	confirmgate.RecordOK(dir, actor, needs)
	return previous, nil
}

func setGroupEnv(dir string, cfg *config.Config, name, envName, phrase, actor string) (string, []confirmgate.Need, error) {
	name = strings.TrimSpace(name)
	envName = strings.TrimSpace(envName)
	g, ok := cfg.Groups[name]
	if !ok || g == nil {
		return "", nil, fmt.Errorf("group %q not found", name)
	}
	if _, ok := cfg.Envs[envName]; !ok {
		return "", nil, fmt.Errorf("unknown env %q", envName)
	}
	previous := g.Env
	var needs []confirmgate.Need
	if previous == "prod" && envName != "prod" {
		needs = []confirmgate.Need{confirmgate.ProdLeaveNeed(name, envName)}
	}
	if err := confirmgate.Require(dir, actor, phrase, needs); err != nil {
		return previous, nil, err
	}
	g.Env = envName
	return previous, needs, nil
}
