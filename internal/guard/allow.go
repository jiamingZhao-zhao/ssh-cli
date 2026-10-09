package guard

import (
	"path"
	"strings"
)

type pattern []string

func (p pattern) String() string { return strings.Join(p, " ") }

func (p pattern) isPrefixOf(q pattern) bool {
	if len(p) > len(q) {
		return false
	}
	for i := range p {
		if p[i] != q[i] {
			return false
		}
	}
	return true
}

func parsePattern(s string) pattern { return strings.Fields(s) }

type allowSet struct {
	universal bool
	patterns  []pattern
}

func (a allowSet) empty() bool { return !a.universal && len(a.patterns) == 0 }

func allowFrom(list *[]string) allowSet {
	if list == nil {
		return allowSet{universal: true}
	}
	out := allowSet{patterns: make([]pattern, 0, len(*list))}
	for _, item := range *list {
		out.patterns = append(out.patterns, parsePattern(item))
	}
	return out
}

func (a allowSet) allows(args []Arg) bool {
	if a.universal {
		return true
	}
	for _, p := range a.patterns {
		if prefixMatch(p, args) {
			return true
		}
	}
	return false
}

func prefixMatch(p pattern, args []Arg) bool {
	if len(p) > len(args) {
		return false
	}
	for i, tok := range p {
		if !args[i].Static || args[i].Value != tok {
			return false
		}
	}
	return true
}

func matchAny(patterns []string, args []Arg) (string, bool) {
	// Deny and confirm match the command basename. Allow stays on the full
	// argv0 so an arbitrary path cannot widen a whitelist entry.
	viewed := basenameArgs(args)
	for _, raw := range patterns {
		if prefixMatch(parsePattern(raw), viewed) {
			return raw, true
		}
	}
	return "", false
}

func basenameArgs(args []Arg) []Arg {
	if len(args) == 0 || !args[0].Static {
		return args
	}
	base := path.Base(args[0].Value)
	if base == args[0].Value {
		return args
	}
	out := make([]Arg, len(args))
	copy(out, args)
	out[0].Value = base
	return out
}

// intersectAllow computes the intersection of allow-sets.
// An unset (universal) set is the identity. The result is empty when no
// command could satisfy every concrete list.
func intersectAllow(sets []allowSet) allowSet {
	var concrete []allowSet
	for _, s := range sets {
		if s.universal {
			continue
		}
		concrete = append(concrete, s)
	}
	if len(concrete) == 0 {
		return allowSet{universal: true}
	}
	for _, s := range concrete {
		if len(s.patterns) == 0 {
			return allowSet{}
		}
	}
	seen := map[string]bool{}
	var union []pattern
	for _, s := range concrete {
		for _, p := range s.patterns {
			k := p.String()
			if seen[k] {
				continue
			}
			seen[k] = true
			union = append(union, p)
		}
	}
	var kept []pattern
	for _, p := range union {
		ok := true
		for _, s := range concrete {
			hit := false
			for _, q := range s.patterns {
				if q.isPrefixOf(p) {
					hit = true
					break
				}
			}
			if !hit {
				ok = false
				break
			}
		}
		if ok {
			kept = append(kept, p)
		}
	}
	if len(kept) == 0 {
		return allowSet{}
	}
	return allowSet{patterns: kept}
}

func (a allowSet) strings() []string {
	if a.universal {
		return nil
	}
	out := make([]string, len(a.patterns))
	for i, p := range a.patterns {
		out[i] = p.String()
	}
	return out
}
