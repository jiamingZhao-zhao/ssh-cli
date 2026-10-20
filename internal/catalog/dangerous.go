package catalog

import (
	"fmt"
	"strings"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/config"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/confirmgate"
)

// DangerousDraft updates the opt-in dangerous-command catalog.
// Enable nil leaves the switch unchanged. List flags replace that list.
type DangerousDraft struct {
	Enable     *bool
	Envs       []string
	HasEnvs    bool
	ClearEnvs  bool
	Rules      []string
	HasRules   bool
	ClearRules bool
	AllRules   bool
	Deny       []string
	HasDeny    bool
	ClearDeny  bool

	HumanConfirm string
	Actor        string
}

// SetDangerous writes dangerousCommands. Shrinking enforcement asks for the
// confirmation phrase "dangerous". Adding rules or environments does not.
func SetDangerous(dir string, in DangerousDraft) error {
	var needs []confirmgate.Need
	err := config.Update(dir, func(cfg *config.Config) error {
		n, err := setDangerous(dir, cfg, in)
		needs = n
		return err
	})
	if err != nil {
		return err
	}
	confirmgate.RecordOK(dir, in.Actor, needs)
	return nil
}

func setDangerous(dir string, cfg *config.Config, in DangerousDraft) ([]confirmgate.Need, error) {
	if !in.changed() {
		return nil, fmt.Errorf("no changes given")
	}
	next, err := applyDangerous(cfg.Dangerous, in)
	if err != nil {
		return nil, err
	}
	if err := checkDangerous(cfg, next); err != nil {
		return nil, err
	}
	var needs []confirmgate.Need
	if dangerousWider(cfg.Dangerous, next) {
		needs = []confirmgate.Need{confirmgate.WidenNeed("dangerous", "dangerous-command enforcement would shrink")}
		if err := confirmgate.Require(dir, in.Actor, in.HumanConfirm, needs); err != nil {
			return nil, err
		}
	}
	cfg.Dangerous = next
	return needs, nil
}

func (d DangerousDraft) changed() bool {
	return d.Enable != nil || d.HasEnvs || d.ClearEnvs || d.HasRules || d.ClearRules || d.AllRules || d.HasDeny || d.ClearDeny
}

func applyDangerous(cur *config.DangerousCommands, in DangerousDraft) (*config.DangerousCommands, error) {
	if in.AllRules && in.HasRules {
		return nil, fmt.Errorf("use only one of --all and --rule")
	}
	if in.AllRules && in.ClearRules {
		return nil, fmt.Errorf("use only one of --all and --clear-rules")
	}
	if in.HasRules && in.ClearRules {
		return nil, fmt.Errorf("use only one of --rule and --clear-rules")
	}
	if in.HasEnvs && in.ClearEnvs {
		return nil, fmt.Errorf("use only one of --env and --clear-envs")
	}
	if in.HasDeny && in.ClearDeny {
		return nil, fmt.Errorf("use only one of --deny and --clear-deny")
	}
	next := cloneDanger(cur)
	if in.Enable != nil {
		next.Enabled = *in.Enable
	}
	switch {
	case in.ClearEnvs:
		next.Envs = nil
	case in.HasEnvs:
		next.Envs = cleanList(in.Envs)
	}
	switch {
	case in.AllRules:
		next.Rules = config.DangerousRuleIDs()
	case in.ClearRules:
		next.Rules = nil
	case in.HasRules:
		next.Rules = cleanList(in.Rules)
	}
	switch {
	case in.ClearDeny:
		next.Deny = nil
	case in.HasDeny:
		next.Deny = cleanList(in.Deny)
	}
	if !next.Enabled && len(next.Envs) == 0 && len(next.Rules) == 0 && len(next.Deny) == 0 {
		return nil, nil
	}
	return next, nil
}

func checkDangerous(cfg *config.Config, d *config.DangerousCommands) error {
	if d == nil {
		return nil
	}
	for _, id := range d.Rules {
		if !config.KnownDangerousRule(id) {
			return fmt.Errorf("dangerousCommands: unknown rule %q (want %s)", id, strings.Join(config.DangerousRuleIDs(), ", "))
		}
	}
	for _, env := range d.Envs {
		if cfg == nil || cfg.Envs == nil || cfg.Envs[env] == nil {
			return fmt.Errorf("dangerousCommands: unknown env %q", env)
		}
	}
	return nil
}

func dangerousWider(prev, next *config.DangerousCommands) bool {
	before := dangerCoverage(prev)
	after := dangerCoverage(next)
	for key := range before {
		if _, ok := after[key]; !ok {
			return true
		}
	}
	return false
}

func dangerCoverage(d *config.DangerousCommands) map[string]struct{} {
	out := map[string]struct{}{}
	if d == nil || !d.Enabled {
		return out
	}
	scope, _ := d.Scope()
	if len(d.Rules) == 0 && len(d.Deny) == 0 {
		return out
	}
	for _, env := range scope {
		for _, id := range d.Rules {
			out["rule\x00"+env+"\x00"+id] = struct{}{}
		}
		for _, pat := range d.Deny {
			out["deny\x00"+env+"\x00"+pat] = struct{}{}
		}
	}
	return out
}

func cloneDanger(d *config.DangerousCommands) *config.DangerousCommands {
	if d == nil {
		return &config.DangerousCommands{}
	}
	out := *d
	out.Envs = append([]string(nil), d.Envs...)
	out.Rules = append([]string(nil), d.Rules...)
	out.Deny = append([]string(nil), d.Deny...)
	return &out
}
