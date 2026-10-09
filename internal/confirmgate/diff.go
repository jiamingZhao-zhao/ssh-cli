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
// Import uses ImportNeeds so a delete in one bundle and a recreate in the next
// still see the credential binding.
func ConfigNeeds(prev, next *config.Config) ([]Need, error) {
	return configNeeds(prev, next, nil)
}

func configNeeds(prev, next *config.Config, extra []credBind) ([]Need, error) {
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
	needs = append(needs, hostReuseNeeds(prev, next, extra)...)
	return dedupeNeeds(needs), nil
}

// DiffSummary is a stable one-line description of host add, remove, and address changes.
func DiffSummary(prev, next *config.Config) string {
	if prev == nil || next == nil {
		return "config import"
	}
	old := prev.Index()
	neu := next.Index()
	var removed, added, moved []string
	for alias, h := range old {
		n, ok := neu[alias]
		if !ok {
			removed = append(removed, alias)
			continue
		}
		if h.Host == nil || n.Host == nil {
			continue
		}
		if h.Host.Host != n.Host.Host || h.Host.PortOrDefault() != n.Host.PortOrDefault() {
			moved = append(moved, alias)
		}
	}
	for alias := range neu {
		if _, ok := old[alias]; !ok {
			added = append(added, alias)
		}
	}
	sort.Strings(removed)
	sort.Strings(added)
	sort.Strings(moved)
	var parts []string
	if len(removed) > 0 {
		parts = append(parts, "removed "+strings.Join(removed, ","))
	}
	if len(added) > 0 {
		parts = append(parts, "added "+strings.Join(added, ","))
	}
	if len(moved) > 0 {
		parts = append(parts, "moved "+strings.Join(moved, ","))
	}
	if len(parts) == 0 {
		return "no host changes"
	}
	return strings.Join(parts, "; ")
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

// hostReuseNeeds catches a new alias, or a host that was removed and added
// again, when it reuses a passwordRef or identity file at a different address.
// Hosts that keep their alias are already covered by hostDiffNeeds.
func hostReuseNeeds(prev, next *config.Config, extra []credBind) []Need {
	type sight struct {
		host  string
		port  int
		env   string
		alias string
	}
	known := map[string][]sight{}
	add := func(kind, value, env, alias string, h *config.Host) {
		value = strings.TrimSpace(value)
		if value == "" || h == nil || strings.TrimSpace(h.Host) == "" {
			return
		}
		key := kind + "\x00" + value
		s := sight{host: strings.TrimSpace(h.Host), port: h.PortOrDefault(), env: env, alias: alias}
		for _, e := range known[key] {
			if e.host == s.host && e.port == s.port && e.env == s.env && e.alias == s.alias {
				return
			}
		}
		known[key] = append(known[key], s)
	}
	if prev != nil {
		for alias, h := range prev.Index() {
			if h.Host == nil {
				continue
			}
			add("passwordRef", h.Host.PasswordRef, h.EnvName, alias, h.Host)
			add("identity", h.Host.Identity, h.EnvName, alias, h.Host)
		}
	}
	for _, b := range extra {
		add(b.Kind, b.Value, b.Env, b.Alias, &config.Host{Host: b.Host, Port: b.Port, User: b.User})
	}
	if next == nil {
		return nil
	}
	prevIndex := map[string]config.ResolvedHost{}
	if prev != nil {
		prevIndex = prev.Index()
	}
	aliases := make([]string, 0)
	nextIndex := next.Index()
	for alias := range nextIndex {
		aliases = append(aliases, alias)
	}
	sort.Strings(aliases)
	var needs []Need
	for _, alias := range aliases {
		if _, ok := prevIndex[alias]; ok {
			continue
		}
		h := nextIndex[alias]
		if h.Host == nil {
			continue
		}
		for _, cred := range []struct{ kind, val string }{
			{"passwordRef", h.Host.PasswordRef},
			{"identity", h.Host.Identity},
		} {
			val := strings.TrimSpace(cred.val)
			if val == "" {
				continue
			}
			sights := known[cred.kind+"\x00"+val]
			if len(sights) == 0 {
				continue
			}
			matched := false
			fromProd := false
			olds := make([]string, 0, len(sights))
			for _, s := range sights {
				if s.host == strings.TrimSpace(h.Host.Host) && s.port == h.Host.PortOrDefault() {
					matched = true
				}
				if s.env == "prod" {
					fromProd = true
				}
				label := s.alias
				if label == "" {
					label = cred.kind
				}
				olds = append(olds, fmt.Sprintf("%s@%s:%d", label, s.host, s.port))
			}
			if matched {
				continue
			}
			sort.Strings(olds)
			reason := fmt.Sprintf("host %s reuses %s %q at %s:%d (known %s)", alias, cred.kind, val, strings.TrimSpace(h.Host.Host), h.Host.PortOrDefault(), strings.Join(olds, ", "))
			if fromProd && h.EnvName != "prod" {
				needs = append(needs, Need{
					Kind: "prod_leave", Phrase: "prod", Object: alias, Reason: reason,
				})
			} else if !hasHostGate(needs, alias) {
				needs = append(needs, Need{
					Kind: "host_move", Phrase: alias, Object: alias, Reason: reason,
				})
			}
			break
		}
	}
	return needs
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
// summary is the host diff (added, removed, moved), including imports that
// did not need a confirmation phrase.
func RecordImport(dir, actor string, needs []Need, summary string) {
	if strings.TrimSpace(summary) == "" {
		summary = "config import"
	} else {
		summary = "config import: " + summary
	}
	if len(needs) > 0 {
		reason := Reasons(needs)
		if summary != "" {
			reason = reason + "; " + summary
		}
		write(dir, actor, audit.StatusOK, false, reason, Object(needs))
		return
	}
	if strings.TrimSpace(actor) == "" {
		actor = audit.Actor()
	}
	source := audit.SourceCLI
	if actor == audit.SourceUI {
		source = audit.SourceUI
	}
	_, _ = audit.Append(dir, audit.Record{
		Op: audit.OpConfigChange, Status: audit.StatusOK, Actor: actor,
		Reason: summary, Command: "config import", Source: source,
	})
}
