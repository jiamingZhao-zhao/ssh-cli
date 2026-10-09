package confirmgate

import (
	"fmt"
	"sort"
	"strings"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/audit"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/config"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/guard"
)

// ConfigNeeds diffs the candidate config against the current one.
// Leaving prod, a wider policy, or a different host target each produce a
// confirmation need. Callers confirm with Require, then save and sign.
func ConfigNeeds(prev, next *config.Config) ([]Need, error) {
	if prev == nil || next == nil {
		return nil, fmt.Errorf("config diff requires both documents")
	}
	var needs []Need
	needs = append(needs, envNeeds(prev, next)...)
	needs = append(needs, policyNeeds(prev, next)...)
	needs = append(needs, groupNeeds(prev, next)...)
	hostNeeds, err := hostDiffNeeds(prev, next)
	if err != nil {
		return nil, err
	}
	needs = append(needs, hostNeeds...)
	return dedupeNeeds(needs), nil
}

func envNeeds(prev, next *config.Config) []Need {
	names := unionKeys(envMap(prev), envMap(next))
	var needs []Need
	for _, name := range names {
		old, newEnv := prev.Envs[name], next.Envs[name]
		if old == nil || newEnv == nil {
			continue
		}
		if old.MaxMode.Valid() && newEnv.MaxMode.Valid() && newEnv.MaxMode.Rank() > old.MaxMode.Rank() {
			needs = append(needs, WidenNeed(name, fmt.Sprintf("env %s maxMode would widen", name)))
		}
		if old.NoDataOutflow && !newEnv.NoDataOutflow {
			needs = append(needs, WidenNeed(name, fmt.Sprintf("env %s noDataOutflow would be disabled", name)))
		}
		oldPol := lookup(prev, strings.TrimSpace(old.DefaultPolicy))
		newPol := lookup(next, strings.TrimSpace(newEnv.DefaultPolicy))
		if strings.TrimSpace(old.DefaultPolicy) != "" && PolicyWider(oldPol, newPol) {
			needs = append(needs, WidenNeed(name, fmt.Sprintf("env %s default policy would widen", name)))
		}
	}
	return needs
}

func policyNeeds(prev, next *config.Config) []Need {
	names := map[string]bool{}
	for name := range prev.Policies {
		names[name] = true
	}
	for name := range next.Policies {
		names[name] = true
	}
	list := make([]string, 0, len(names))
	for name := range names {
		list = append(list, name)
	}
	sort.Strings(list)
	var needs []Need
	for _, name := range list {
		old := policyPtr(prev, name)
		neu := policyPtr(next, name)
		if PolicyWider(old, neu) {
			needs = append(needs, WidenNeed(name, "policy "+name+" would widen"))
		}
	}
	return needs
}

func policyPtr(cfg *config.Config, name string) *config.Policy {
	if cfg == nil || cfg.Policies == nil {
		return nil
	}
	return cfg.Policies[name]
}

func groupNeeds(prev, next *config.Config) []Need {
	if prev.Groups == nil || next.Groups == nil {
		return nil
	}
	names := unionKeys(prev.Groups, next.Groups)
	var needs []Need
	for _, name := range names {
		old, neu := prev.Groups[name], next.Groups[name]
		if old == nil || neu == nil {
			continue
		}
		if old.Env == "prod" && neu.Env != "prod" {
			needs = append(needs, ProdLeaveNeed(name, neu.Env))
		}
		if layerWider(old.Allow, old.Deny, old.Confirm, old.ProtectedPaths, old.Capabilities, neu.Allow, neu.Deny, neu.Confirm, neu.ProtectedPaths, neu.Capabilities) {
			needs = append(needs, WidenNeed(name, "group "+name+" rules would widen"))
		}
		if strings.TrimSpace(old.Policy) != "" && PolicyWider(lookup(prev, old.Policy), lookup(next, neu.Policy)) {
			needs = append(needs, WidenNeed(name, "group "+name+" policy would widen"))
		}
	}
	return needs
}

func hostDiffNeeds(prev, next *config.Config) ([]Need, error) {
	oldIndex := prev.Index()
	newIndex := next.Index()
	names := make([]string, 0)
	seen := map[string]bool{}
	for name := range oldIndex {
		if _, ok := newIndex[name]; ok && !seen[name] {
			seen[name] = true
			names = append(names, name)
		}
	}
	sort.Strings(names)
	var needs []Need
	for _, alias := range names {
		old, neu := oldIndex[alias], newIndex[alias]
		oldEff, err := guard.Resolve(prev, old, false)
		if err != nil {
			return nil, fmt.Errorf("host %s: %w", alias, err)
		}
		newEff, err := guard.Resolve(next, neu, false)
		if err != nil {
			return nil, fmt.Errorf("host %s: %w", alias, err)
		}
		groupChanged := old.Group != neu.Group
		addrChanged := old.Host.Host != neu.Host.Host
		needs = append(needs, HostNeeds(alias, old.Group, neu.Group, old.EnvName, neu.EnvName, old.Host.Host, neu.Host.Host, groupChanged, addrChanged)...)
		if old.Host.ConnFingerprint() != neu.Host.ConnFingerprint() && !hasHostGate(needs, alias) {
			needs = append(needs, Need{
				Kind:   "host_move",
				Phrase: alias,
				Object: alias,
				Reason: fmt.Sprintf("change connection target of host %s", alias),
			})
		}
		if effectiveWidens(oldEff, newEff) {
			needs = append(needs, WidenNeed(alias, fmt.Sprintf("host %s effective permissions would widen", alias)))
		}
	}
	return needs, nil
}

func hasHostGate(needs []Need, alias string) bool {
	for _, n := range needs {
		if n.Object == alias && (n.Kind == "host_move" || n.Kind == "prod_leave") {
			return true
		}
	}
	return false
}

func layerWider(oldAllow *[]string, oldDeny, oldConfirm, oldPaths []string, oldCaps *config.Capabilities, newAllow *[]string, newDeny, newConfirm, newPaths []string, newCaps *config.Capabilities) bool {
	return PolicyWider(
		&config.Policy{Allow: oldAllow, Deny: oldDeny, Confirm: oldConfirm, ProtectedPaths: oldPaths, Capabilities: oldCaps},
		&config.Policy{Allow: newAllow, Deny: newDeny, Confirm: newConfirm, ProtectedPaths: newPaths, Capabilities: newCaps},
	)
}

func effectiveWidens(prev, next guard.Effective) bool {
	if next.Mode.Rank() > prev.Mode.Rank() {
		return true
	}
	if AllowWidens(allowView(prev), allowView(next)) {
		return true
	}
	if ListShrinks(prev.Deny, next.Deny) || ListShrinks(prev.Confirm, next.Confirm) || ListShrinks(prev.Protected, next.Protected) {
		return true
	}
	if !prev.Upload && next.Upload {
		return true
	}
	if !prev.Download && next.Download {
		return true
	}
	if !prev.Forward && next.Forward {
		return true
	}
	if relayLoosens(config.RelayMode(prev.Relay), config.RelayMode(next.Relay)) {
		return true
	}
	if prev.NoDataOut && !next.NoDataOut {
		return true
	}
	if prev.ServiceAll {
		return false
	}
	if next.ServiceAll {
		return true
	}
	have := map[string]bool{}
	for _, item := range prev.Service {
		have[item] = true
	}
	for _, item := range next.Service {
		if !have[item] {
			return true
		}
	}
	return false
}

func allowView(e guard.Effective) *[]string {
	if e.AllowAll {
		return nil
	}
	items := append([]string(nil), e.Allow...)
	return &items
}

func envMap(cfg *config.Config) map[string]*config.Env {
	if cfg == nil || cfg.Envs == nil {
		return map[string]*config.Env{}
	}
	return cfg.Envs
}

func unionKeys[V any](a, b map[string]V) []string {
	seen := map[string]bool{}
	for k := range a {
		seen[k] = true
	}
	for k := range b {
		seen[k] = true
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func dedupeNeeds(needs []Need) []Need {
	if len(needs) == 0 {
		return nil
	}
	sort.Slice(needs, func(i, j int) bool {
		if kindRank(needs[i].Kind) != kindRank(needs[j].Kind) {
			return kindRank(needs[i].Kind) < kindRank(needs[j].Kind)
		}
		if needs[i].Object != needs[j].Object {
			return needs[i].Object < needs[j].Object
		}
		return needs[i].Reason < needs[j].Reason
	})
	out := make([]Need, 0, len(needs))
	seen := map[string]bool{}
	for _, n := range needs {
		key := n.Kind + "\x00" + n.Object + "\x00" + n.Reason
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, n)
	}
	return out
}

func kindRank(kind string) int {
	switch kind {
	case "prod_leave":
		return 0
	case "host_move":
		return 1
	default:
		return 2
	}
}

// RecordImport writes one config-change audit line after a committed import.
func RecordImport(dir, actor string, needs []Need) {
	if len(needs) > 0 {
		RecordOK(dir, actor, needs)
		return
	}
	if strings.TrimSpace(actor) == "" {
		actor = audit.Actor()
	}
	_, _ = audit.Append(dir, audit.Record{
		Op: audit.OpConfigChange, Status: audit.StatusOK, Actor: actor,
		Reason: "config import", Command: "config import",
	})
}
