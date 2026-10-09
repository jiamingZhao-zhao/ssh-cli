package ui

import (
	"fmt"
	"strings"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/config"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/confirmgate"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/guard"
)

// GroupDraft is a group add or edit. Has* fields distinguish "omitted" from
// "empty". Allow nil with HasAllow means this layer stays universal; a
// non-nil empty list is an explicit empty allow-list.
type GroupDraft struct {
	Name      string
	Env       string
	Label     string
	Policy    string
	Allow     *[]string
	Deny      []string
	Confirm   []string
	Protected []string

	HasEnv       bool
	HasLabel     bool
	HasPolicy    bool
	HasAllow     bool
	HasDeny      bool
	HasConfirm   bool
	HasProtected bool

	HumanConfirm string
	Actor        string
}

// AddGroup creates an empty group. The group must name an existing env.
// Tags are not stored on the group; hosts carry tags for -t selection.
func AddGroup(dir string, in GroupDraft) error {
	name := strings.TrimSpace(in.Name)
	if !config.ValidName(name) {
		return fmt.Errorf("invalid group name")
	}
	envName := strings.TrimSpace(in.Env)
	if envName == "" {
		return fmt.Errorf("env is required")
	}
	policy := strings.TrimSpace(in.Policy)
	return config.Update(dir, func(cfg *config.Config) error {
		if _, ok := cfg.Groups[name]; ok {
			return fmt.Errorf("group %q already exists", name)
		}
		if _, ok := cfg.Envs[envName]; !ok {
			return fmt.Errorf("unknown env %q", envName)
		}
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
		g := &config.Group{
			Env:    envName,
			Label:  label,
			Policy: policy,
			Hosts:  map[string]*config.Host{},
		}
		if in.HasAllow {
			g.Allow = cloneListPtr(in.Allow)
		}
		if in.HasDeny {
			g.Deny = append([]string(nil), in.Deny...)
		}
		if in.HasConfirm {
			g.Confirm = append([]string(nil), in.Confirm...)
		}
		if in.HasProtected {
			g.ProtectedPaths = append([]string(nil), in.Protected...)
		}
		cfg.Groups[name] = g
		return nil
	})
}

// UpdateGroup edits group metadata. It does not rename the group or touch hosts.
func UpdateGroup(dir string, in GroupDraft) error {
	name := strings.TrimSpace(in.Name)
	if name == "" {
		return fmt.Errorf("group is required")
	}
	if !in.HasEnv && !in.HasLabel && !in.HasPolicy && !in.HasAllow && !in.HasDeny && !in.HasConfirm && !in.HasProtected {
		return fmt.Errorf("no changes given")
	}
	var needs []confirmgate.Need
	err := config.Update(dir, func(cfg *config.Config) error {
		g, ok := cfg.Groups[name]
		if !ok || g == nil {
			return fmt.Errorf("group %q not found", name)
		}
		n, err := uiGroupNeeds(cfg, g, in)
		if err != nil {
			return err
		}
		if err := confirmgate.Require(dir, in.Actor, in.HumanConfirm, n); err != nil {
			return err
		}
		needs = n
		if in.HasEnv {
			envName := strings.TrimSpace(in.Env)
			if envName == "" {
				return fmt.Errorf("env is required")
			}
			if _, ok := cfg.Envs[envName]; !ok {
				return fmt.Errorf("unknown env %q", envName)
			}
			g.Env = envName
		}
		if in.HasLabel {
			label, err := config.CleanLabel(in.Label)
			if err != nil {
				return err
			}
			g.Label = label
		}
		if in.HasPolicy {
			policy := strings.TrimSpace(in.Policy)
			if policy != "" && !guard.KnownPolicy(cfg, policy) {
				return fmt.Errorf("unknown policy %q", policy)
			}
			g.Policy = policy
		}
		if in.HasAllow {
			g.Allow = cloneListPtr(in.Allow)
		}
		if in.HasDeny {
			g.Deny = append([]string(nil), in.Deny...)
		}
		if in.HasConfirm {
			g.Confirm = append([]string(nil), in.Confirm...)
		}
		if in.HasProtected {
			g.ProtectedPaths = append([]string(nil), in.Protected...)
		}
		return nil
	})
	if err != nil {
		return err
	}
	confirmgate.RecordOK(dir, in.Actor, needs)
	return nil
}

func uiGroupNeeds(cfg *config.Config, g *config.Group, in GroupDraft) ([]confirmgate.Need, error) {
	name := strings.TrimSpace(in.Name)
	var needs []confirmgate.Need
	if in.HasEnv {
		envName := strings.TrimSpace(in.Env)
		if g.Env == "prod" && envName != "prod" {
			needs = append(needs, confirmgate.ProdLeaveNeed(name, envName))
		}
	}
	if in.HasPolicy {
		next := strings.TrimSpace(in.Policy)
		if next != "" && !guard.KnownPolicy(cfg, next) {
			return nil, fmt.Errorf("unknown policy %q", next)
		}
		if confirmgate.NamedWider(cfg, g.Policy, next) {
			needs = append(needs, confirmgate.WidenNeed(name, "group "+name+" policy would widen"))
		}
	}
	if in.HasAllow && confirmgate.AllowWidens(g.Allow, in.Allow) {
		needs = append(needs, confirmgate.WidenNeed(name, "group "+name+" allow-list would widen"))
	}
	if in.HasDeny && confirmgate.ListShrinks(g.Deny, in.Deny) {
		needs = append(needs, confirmgate.WidenNeed(name, "group "+name+" deny-list would shrink"))
	}
	if in.HasConfirm && confirmgate.ListShrinks(g.Confirm, in.Confirm) {
		needs = append(needs, confirmgate.WidenNeed(name, "group "+name+" confirm-list would shrink"))
	}
	if in.HasProtected && confirmgate.ListShrinks(g.ProtectedPaths, in.Protected) {
		needs = append(needs, confirmgate.WidenNeed(name, "group "+name+" protected paths would shrink"))
	}
	return needs, nil
}

// RemoveGroup deletes a group that has no hosts, matching `group remove`.
func RemoveGroup(dir, name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("group is required")
	}
	return config.Update(dir, func(cfg *config.Config) error {
		g, ok := cfg.Groups[name]
		if !ok {
			return fmt.Errorf("group %q not found", name)
		}
		if g != nil && len(g.Hosts) > 0 {
			return fmt.Errorf("group %q still has %d host(s)", name, len(g.Hosts))
		}
		delete(cfg.Groups, name)
		return nil
	})
}

// ApplyGroupTags adds and removes tags on every host in the group.
// The group itself has no tags field; -t selects hosts.
func ApplyGroupTags(dir, group string, add, remove []string) error {
	group = strings.TrimSpace(group)
	add = cleanTags(add)
	remove = cleanTags(remove)
	if group == "" {
		return fmt.Errorf("group is required")
	}
	if len(add) == 0 && len(remove) == 0 {
		return fmt.Errorf("no tag changes given")
	}
	return config.Update(dir, func(cfg *config.Config) error {
		g, ok := cfg.Groups[group]
		if !ok || g == nil {
			return fmt.Errorf("group %q not found", group)
		}
		if len(g.Hosts) == 0 {
			return fmt.Errorf("group %q has no hosts; tags belong on hosts, not on the group", group)
		}
		drop := map[string]bool{}
		for _, t := range remove {
			drop[t] = true
		}
		for _, h := range g.Hosts {
			if h == nil {
				continue
			}
			h.Tags = mergeTags(h.Tags, add, drop)
		}
		return nil
	})
}

func mergeTags(have, add []string, drop map[string]bool) []string {
	var next []string
	seen := map[string]bool{}
	for _, t := range have {
		t = strings.TrimSpace(t)
		if t == "" || drop[t] || seen[t] {
			continue
		}
		seen[t] = true
		next = append(next, t)
	}
	for _, t := range add {
		if seen[t] || drop[t] {
			continue
		}
		seen[t] = true
		next = append(next, t)
	}
	return next
}
