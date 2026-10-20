package guard

import (
	"sort"
	"strings"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/config"
)

// DangerousCatalogItem is one suggested rule plus whether this report enforces it.
type DangerousCatalogItem struct {
	ID       string `json:"id"`
	Summary  string `json:"summary"`
	Selected bool   `json:"selected"`
	Active   bool   `json:"active"`
}

// DangerousReport distinguishes the suggested catalog from rules that block
// the environment this report was built for.
type DangerousReport struct {
	Enabled      bool     `json:"enabled"`
	Scope        []string `json:"scope"`
	ScopeDefault bool     `json:"scopeDefault"`
	Env          string   `json:"env,omitempty"`
	InScope      bool     `json:"inScope"`
	EnforcedHere bool     `json:"enforcedHere"`
	Active       []string `json:"active"`
	ExtraDeny    []string `json:"extraDeny"`
	// ConfiguredExtra is the saved extra deny list, including when this env
	// does not enforce it.
	ConfiguredExtra []string               `json:"configuredExtraDeny"`
	Catalog         []DangerousCatalogItem `json:"catalog"`
}

// dangerState is the per-host gating Decide consults.
type dangerState struct {
	enabled      bool
	inScope      bool
	enforcedHere bool
	env          string
	scope        []string
	scopeDefault bool
	rules        map[string]bool
	selected     map[string]bool
	activeExtra  []string
	savedExtra   []string
}

func loadDanger(cfg *config.Config, env string) dangerState {
	var doc *config.DangerousCommands
	if cfg != nil {
		doc = cfg.Dangerous
	}
	scope, scopeDefault := doc.Scope()
	st := dangerState{
		env:          env,
		scope:        scope,
		scopeDefault: scopeDefault,
		selected:     map[string]bool{},
	}
	if doc != nil {
		st.enabled = doc.Enabled
		st.savedExtra = append([]string(nil), doc.Deny...)
		for _, id := range doc.Rules {
			if config.KnownDangerousRule(id) {
				st.selected[id] = true
			}
		}
	}
	if env != "" {
		st.inScope = doc.InScope(env)
		rules, extra, on := doc.Enforcement(env)
		st.rules = rules
		st.activeExtra = extra
		st.enforcedHere = on
	}
	return st
}

func (s dangerState) report() DangerousReport {
	active := make([]string, 0, len(s.rules))
	for id := range s.rules {
		active = append(active, id)
	}
	sort.Strings(active)
	cat := config.DangerousCatalog()
	items := make([]DangerousCatalogItem, len(cat))
	for i, rule := range cat {
		items[i] = DangerousCatalogItem{
			ID:       rule.ID,
			Summary:  rule.Summary,
			Selected: s.selected[rule.ID],
			Active:   s.rules[rule.ID],
		}
	}
	extra := append([]string(nil), s.activeExtra...)
	if extra == nil {
		extra = []string{}
	}
	saved := append([]string(nil), s.savedExtra...)
	if saved == nil {
		saved = []string{}
	}
	rep := DangerousReport{
		Enabled:         s.enabled,
		Scope:           append([]string(nil), s.scope...),
		ScopeDefault:    s.scopeDefault,
		Env:             s.env,
		InScope:         s.inScope,
		EnforcedHere:    s.enforcedHere,
		Active:          active,
		ExtraDeny:       extra,
		ConfiguredExtra: saved,
		Catalog:         items,
	}
	if rep.Active == nil {
		rep.Active = []string{}
	}
	return rep
}

// DescribeDangerous reports catalog versus enforcement for one environment.
// An empty env is the global view: selected rules are listed, and nothing is
// marked active for a host.
func DescribeDangerous(cfg *config.Config, env string) DangerousReport {
	return loadDanger(cfg, env).report()
}

func (e Effective) dangerNote(id string) Finding {
	var detail string
	switch {
	case !e.danger.enabled:
		detail = "catalog rule " + id + " matches but enforcement is off"
	case !e.danger.inScope:
		detail = "catalog rule " + id + " matches but env " + e.danger.env + " is outside the dangerous-command scope (" + strings.Join(e.danger.scope, ", ") + ")"
	default:
		detail = "catalog rule " + id + " matches but is not selected"
	}
	return Finding{Layer: "dangerous", Kind: "catalog", Detail: detail}
}

func (e Effective) extraNote(pattern string) Finding {
	quoted := quote(pattern)
	var detail string
	switch {
	case !e.danger.enabled:
		detail = "configured dangerous pattern " + quoted + " matches but enforcement is off"
	case !e.danger.inScope:
		detail = "configured dangerous pattern " + quoted + " matches but env " + e.danger.env + " is outside the dangerous-command scope (" + strings.Join(e.danger.scope, ", ") + ")"
	default:
		detail = "configured dangerous pattern " + quoted + " matches but is not selected"
	}
	return Finding{Layer: "dangerous", Kind: "catalog", Detail: detail}
}
