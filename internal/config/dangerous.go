package config

import (
	"fmt"
	"strings"
)

// Dangerous-command catalog identifiers. The catalog is a suggestion list.
// Nothing in it is enforced until dangerousCommands.enabled is true and the
// rule (or an extra deny pattern) is selected. An empty env list means prod only.
const (
	DangerRMRoot       = "rm-root"
	DangerMkfs         = "mkfs"
	DangerDDDisk       = "dd-disk"
	DangerRedirectDisk = "redirect-disk"
	DangerChmodRoot    = "chmod-root"
	DangerForkBomb     = "fork-bomb"
)

// DangerousRule is one suggested dangerous command. Selection is opt-in.
type DangerousRule struct {
	ID      string
	Summary string
}

// DangerousCommands is the opt-in enforcement of the dangerous-command catalog.
// A nil value, or enabled false, does not block catalog commands.
// Envs empty means the scope is prod only, including after the user enables rules.
type DangerousCommands struct {
	Enabled bool     `yaml:"enabled,omitempty" json:"enabled"`
	Envs    []string `yaml:"envs,omitempty" json:"envs,omitempty"`
	Rules   []string `yaml:"rules,omitempty" json:"rules,omitempty"`
	Deny    []string `yaml:"deny,omitempty" json:"deny,omitempty"`
}

// DangerousCatalog is the suggested list shipped with the CLI.
// It is not an active deny list.
func DangerousCatalog() []DangerousRule {
	return []DangerousRule{
		{ID: DangerRMRoot, Summary: "rm -rf of filesystem root"},
		{ID: DangerMkfs, Summary: "mkfs"},
		{ID: DangerDDDisk, Summary: "dd onto a disk device"},
		{ID: DangerRedirectDisk, Summary: "redirect onto a disk device"},
		{ID: DangerChmodRoot, Summary: "chmod/chown of filesystem root"},
		{ID: DangerForkBomb, Summary: "fork bomb"},
	}
}

// DangerousRuleIDs returns catalog ids in display order.
func DangerousRuleIDs() []string {
	cat := DangerousCatalog()
	out := make([]string, len(cat))
	for i, rule := range cat {
		out[i] = rule.ID
	}
	return out
}

// KnownDangerousRule reports whether id is in the shipped catalog.
func KnownDangerousRule(id string) bool {
	for _, rule := range DangerousCatalog() {
		if rule.ID == id {
			return true
		}
	}
	return false
}

// Scope returns the environments where an enabled ruleset applies.
// An empty saved list is the default: prod only. The bool is true in that case.
func (d *DangerousCommands) Scope() (envs []string, scopeDefault bool) {
	if d == nil || len(d.Envs) == 0 {
		return []string{"prod"}, true
	}
	return append([]string(nil), d.Envs...), false
}

// InScope reports whether env is covered by the effective scope.
func (d *DangerousCommands) InScope(env string) bool {
	envs, _ := d.Scope()
	for _, name := range envs {
		if name == env {
			return true
		}
	}
	return false
}

// Enforcement is the catalog rules and extra patterns that actually block env.
// It is empty unless enabled, env is in scope, and at least one rule or extra
// pattern is selected.
func (d *DangerousCommands) Enforcement(env string) (rules map[string]bool, extra []string, on bool) {
	if d == nil || !d.Enabled || !d.InScope(env) {
		return nil, nil, false
	}
	rules = map[string]bool{}
	for _, id := range d.Rules {
		if KnownDangerousRule(id) {
			rules[id] = true
		}
	}
	extra = append([]string(nil), d.Deny...)
	if len(rules) == 0 && len(extra) == 0 {
		return nil, nil, false
	}
	return rules, extra, true
}

func (c *Config) normalizeDangerous() {
	if c == nil || c.Dangerous == nil {
		return
	}
	d := c.Dangerous
	d.Envs = uniqueTrimmed(d.Envs)
	d.Rules = uniqueTrimmed(d.Rules)
	d.Deny = uniqueTrimmed(d.Deny)
	if !d.Enabled && len(d.Envs) == 0 && len(d.Rules) == 0 && len(d.Deny) == 0 {
		c.Dangerous = nil
	}
}

func (c *Config) validateDangerous() error {
	if c == nil || c.Dangerous == nil {
		return nil
	}
	d := c.Dangerous
	for _, id := range d.Rules {
		if !KnownDangerousRule(id) {
			return fmt.Errorf("dangerousCommands: unknown rule %q (want %s)", id, strings.Join(DangerousRuleIDs(), ", "))
		}
	}
	for _, env := range d.Envs {
		if _, ok := c.Envs[env]; !ok {
			return fmt.Errorf("dangerousCommands: unknown env %q", env)
		}
	}
	for _, pat := range d.Deny {
		if strings.TrimSpace(pat) == "" {
			return fmt.Errorf("dangerousCommands: empty deny pattern")
		}
	}
	return nil
}

func uniqueTrimmed(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, item := range in {
		item = strings.TrimSpace(item)
		if item == "" || seen[item] {
			continue
		}
		seen[item] = true
		out = append(out, item)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
