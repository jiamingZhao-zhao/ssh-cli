// Package confirmgate requires a human phrase before a config change that
// leaves prod, widens policy, or moves a host / changes its address.
// HMAC can detect tampering; it does not replace this gate.
package confirmgate

import (
	"fmt"
	"strings"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/audit"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/config"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/guard"
)

// Need is one human confirmation required by a change.
type Need struct {
	Kind   string
	Phrase string
	Object string
	Reason string
}

// Error is returned when the supplied phrase does not match.
// The denial is already written to the audit log.
type Error struct {
	Phrase string
	Reason string
}

func (e *Error) Error() string {
	if e == nil {
		return "confirmation required"
	}
	return "type " + e.Phrase + " to confirm: " + e.Reason
}

// Require audits a denial and returns *Error when phrase does not match.
// An empty need list is not a gate.
func Require(dir, actor, phrase string, needs []Need) error {
	if len(needs) == 0 {
		return nil
	}
	want := Phrase(needs)
	reason := Reasons(needs)
	if phrase == want {
		return nil
	}
	write(dir, actor, audit.StatusDenied, true, reason, Object(needs))
	return &Error{Phrase: want, Reason: reason}
}

// RecordOK writes the successful config change. Call it only after the save commits.
func RecordOK(dir, actor string, needs []Need) {
	if len(needs) == 0 {
		return
	}
	write(dir, actor, audit.StatusOK, false, Reasons(needs), Object(needs))
}

func write(dir, actor, status string, denied bool, reason, object string) {
	if strings.TrimSpace(actor) == "" {
		actor = audit.Actor()
	}
	source := audit.SourceCLI
	if actor == audit.SourceUI {
		source = audit.SourceUI
	}
	_, _ = audit.Append(dir, audit.Record{
		Op:             audit.OpConfigChange,
		Status:         status,
		Actor:          actor,
		Command:        object,
		Reason:         reason,
		DeniedByPolicy: denied,
		HighRisk:       true,
		Source:         source,
	})
}

// Phrase is prod when any need says so, otherwise the first phrase.
func Phrase(needs []Need) string {
	phrase := ""
	for _, n := range needs {
		if n.Phrase == "prod" {
			return "prod"
		}
		if phrase == "" {
			phrase = n.Phrase
		}
	}
	return phrase
}

// Reasons joins need reasons for the audit line.
func Reasons(needs []Need) string {
	parts := make([]string, 0, len(needs))
	for _, n := range needs {
		if n.Reason != "" {
			parts = append(parts, n.Reason)
		}
	}
	return strings.Join(parts, "; ")
}

// Object is the first object name.
func Object(needs []Need) string {
	for _, n := range needs {
		if n.Object != "" {
			return n.Object
		}
	}
	return ""
}

// ProdLeaveNeed is the gate for moving a group off prod.
func ProdLeaveNeed(group, next string) Need {
	return Need{
		Kind:   "prod_leave",
		Phrase: "prod",
		Object: group,
		Reason: fmt.Sprintf("change group %s env from prod to %s", group, next),
	}
}

// HostNeeds covers a group move and an address change. Leaving prod wins the phrase.
func HostNeeds(alias, oldGroup, newGroup, oldEnv, newEnv, oldAddr, newAddr string, groupChanged, addrChanged bool) []Need {
	if !groupChanged && !addrChanged {
		return nil
	}
	prodLeave := groupChanged && oldEnv == "prod" && newEnv != "prod"
	if prodLeave {
		reason := fmt.Sprintf("move host %s out of prod", alias)
		if addrChanged && oldAddr != newAddr {
			reason = fmt.Sprintf("move host %s out of prod and change its address", alias)
		}
		return []Need{{
			Kind:   "prod_leave",
			Phrase: "prod",
			Object: alias,
			Reason: reason,
		}}
	}
	reason := fmt.Sprintf("change address of host %s", alias)
	if groupChanged && addrChanged {
		reason = fmt.Sprintf("move host %s to group %s and change its address", alias, newGroup)
	} else if groupChanged {
		reason = fmt.Sprintf("move host %s to group %s", alias, newGroup)
	}
	return []Need{{
		Kind:   "host_move",
		Phrase: alias,
		Object: alias,
		Reason: reason,
	}}
}

// WidenNeed is the gate for a policy or rule that becomes less strict.
func WidenNeed(object, reason string) Need {
	return Need{Kind: "policy_widen", Phrase: object, Object: object, Reason: reason}
}

// PolicyWider reports whether next is less strict than prev.
// A nil next means the named policy was cleared. A nil prev means a policy was added,
// which is not a widen.
func PolicyWider(prev, next *config.Policy) bool {
	if next == nil {
		return prev != nil
	}
	if prev == nil {
		return false
	}
	if modeWidens(prev.Mode, next.Mode) {
		return true
	}
	if allowWidens(prev.Allow, next.Allow) {
		return true
	}
	if listShrinks(prev.Deny, next.Deny) || listShrinks(prev.Confirm, next.Confirm) || listShrinks(prev.ProtectedPaths, next.ProtectedPaths) {
		return true
	}
	return capsWiden(prev.Capabilities, next.Capabilities)
}

// NamedWider compares two policy names in cfg. Clearing a name widens.
// Adding a name onto an empty layer does not.
func NamedWider(cfg *config.Config, oldName, newName string) bool {
	oldName = strings.TrimSpace(oldName)
	newName = strings.TrimSpace(newName)
	if oldName == newName {
		return false
	}
	if newName == "" {
		return oldName != ""
	}
	if oldName == "" {
		return false
	}
	return PolicyWider(lookup(cfg, oldName), lookup(cfg, newName))
}

func lookup(cfg *config.Config, name string) *config.Policy {
	if cfg != nil && cfg.Policies != nil {
		if p, ok := cfg.Policies[name]; ok && p != nil {
			return p
		}
	}
	if p, ok := guard.BuiltinPolicy(name); ok {
		return p
	}
	return nil
}

func modeWidens(old, new config.Mode) bool {
	if old == new || !old.Valid() || !new.Valid() {
		return false
	}
	return new.Rank() > old.Rank()
}

// AllowWidens is true when next is a broader allow-list than prev.
func AllowWidens(prev, next *[]string) bool { return allowWidens(prev, next) }

func allowWidens(prev, next *[]string) bool {
	if prev == nil {
		return false
	}
	if next == nil {
		return true
	}
	for _, n := range *next {
		if !patternCovered(*prev, n) {
			return true
		}
	}
	return false
}

func patternCovered(prev []string, pattern string) bool {
	np := strings.Fields(pattern)
	for _, o := range prev {
		op := strings.Fields(o)
		if len(op) == 0 || len(op) > len(np) {
			continue
		}
		match := true
		for i := range op {
			if op[i] != np[i] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// ListShrinks reports whether next dropped an entry from prev.
func ListShrinks(prev, next []string) bool { return listShrinks(prev, next) }

func listShrinks(prev, next []string) bool {
	if len(prev) == 0 {
		return false
	}
	have := map[string]bool{}
	for _, s := range next {
		have[s] = true
	}
	for _, s := range prev {
		if !have[s] {
			return true
		}
	}
	return false
}

func capsWiden(prev, next *config.Capabilities) bool {
	if prev == nil && next == nil {
		return false
	}
	if next == nil {
		return prev != nil && (boolWidens(prev.Upload, nil) || boolWidens(prev.Download, nil) || boolWidens(prev.Forward, nil) || relayLoosens(prev.Relay, "") || serviceWidens(prev.Service, nil))
	}
	if prev == nil {
		return boolWidens(nil, next.Upload) || boolWidens(nil, next.Download) || boolWidens(nil, next.Forward) || relayLoosens("", next.Relay) || serviceWidens(nil, next.Service)
	}
	return boolWidens(prev.Upload, next.Upload) || boolWidens(prev.Download, next.Download) || boolWidens(prev.Forward, next.Forward) || relayLoosens(prev.Relay, next.Relay) || serviceWidens(prev.Service, next.Service)
}

func boolWidens(prev, next *bool) bool {
	return tri(next) > tri(prev)
}

func tri(v *bool) int {
	if v == nil {
		return 1
	}
	if *v {
		return 2
	}
	return 0
}

func relayLoosens(prev, next config.RelayMode) bool {
	if prev == next {
		return false
	}
	if next == config.RelayAllow && prev != config.RelayAllow {
		return true
	}
	return prev == config.RelayDeny && next == config.RelaySourceOnly
}

func serviceWidens(prev, next *[]string) bool {
	if next == nil && prev != nil {
		return true
	}
	if prev == nil || next == nil {
		return false
	}
	have := map[string]bool{}
	for _, s := range *prev {
		have[s] = true
	}
	for _, s := range *next {
		if !have[s] {
			return true
		}
	}
	return false
}
