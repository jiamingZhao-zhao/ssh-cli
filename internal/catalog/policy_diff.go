package catalog

import (
	"github.com/jiamingZhao-zhao/ssh-cli/internal/config"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/confirmgate"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/guard"
	"reflect"
	"sort"
)

// PoliciesEqual compares policy values without treating reordered rule sets or
// empty deny/confirm/path slices as changes. Nil allow/service still means unset.
func PoliciesEqual(a, b *config.Policy) bool {
	normalize := func(p *config.Policy) *config.Policy {
		if p == nil {
			return nil
		}
		n := *p
		list := func(v []string) []string { r := append([]string{}, v...); sort.Strings(r); return r }
		n.Deny = list(p.Deny)
		n.Confirm = list(p.Confirm)
		n.ProtectedPaths = list(p.ProtectedPaths)
		if p.Allow != nil {
			v := list(*p.Allow)
			n.Allow = &v
		}
		if p.Capabilities != nil {
			c := *p.Capabilities
			n.Capabilities = &c
			if c.Service != nil {
				v := list(*c.Service)
				c.Service = &v
			}
		}
		return &n
	}
	return reflect.DeepEqual(normalize(a), normalize(b))
}

// BuiltinDifference is a preview only. Existing overrides are never migrated.
type BuiltinDifference struct {
	AddedAllow    []string   `json:"addedAllow,omitempty"`
	RemovedAllow  []string   `json:"removedAllow,omitempty"`
	ChangedFields []string   `json:"changedFields,omitempty"`
	RestoreWidens bool       `json:"restoreWidens"`
	Current       PolicyView `json:"current"`
	Builtin       PolicyView `json:"builtin"`
}

func CompareBuiltin(name string, current *config.Policy) *BuiltinDifference {
	builtin, ok := guard.BuiltinPolicy(name)
	if !ok || current == nil {
		return nil
	}
	d := &BuiltinDifference{Current: viewOf(name, "override", current), Builtin: viewOf(name, "builtin", builtin), RestoreWidens: confirmgate.PolicyWider(current, builtin)}
	difference := func(a, b *[]string) []string {
		if a == nil || b == nil {
			return nil
		}
		seen := map[string]bool{}
		for _, s := range *b {
			seen[s] = true
		}
		var out []string
		for _, s := range *a {
			if !seen[s] {
				out = append(out, s)
			}
		}
		sort.Strings(out)
		return out
	}
	d.AddedAllow = difference(builtin.Allow, current.Allow)
	d.RemovedAllow = difference(current.Allow, builtin.Allow)
	a, b := d.Current, d.Builtin
	for _, field := range []struct {
		name string
		a, b any
	}{{"mode", a.Mode, b.Mode}, {"allow", current.Allow, builtin.Allow}, {"deny", a.Deny, b.Deny}, {"confirm", a.Confirm, b.Confirm}, {"protectedPaths", a.ProtectedPaths, b.ProtectedPaths}, {"capabilities", current.Capabilities, builtin.Capabilities}} {
		if !reflect.DeepEqual(field.a, field.b) {
			d.ChangedFields = append(d.ChangedFields, field.name)
		}
	}
	// Whole-policy equality handles harmless list order differences.
	if PoliciesEqual(current, builtin) {
		d.ChangedFields = nil
	}
	return d
}
