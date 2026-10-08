package guard

import (
	"fmt"
	"strings"
)

// HostDecision is one host's preflight result.
type HostDecision struct {
	Alias    string
	Env      string
	Decision Decision
}

// CrossEnv reports whether the selection spans more than one environment.
func CrossEnv(envs []string) bool {
	seen := map[string]bool{}
	for _, e := range envs {
		seen[e] = true
	}
	return len(seen) > 1
}

// IncludesProd reports whether any selected env is named prod.
func IncludesProd(envs []string) bool {
	for _, e := range envs {
		if e == "prod" {
			return true
		}
	}
	return false
}

// Filter applies the batch rule: any denial aborts the whole batch unless
// skipDenied is set, in which case denied hosts are dropped.
func Filter(decisions []HostDecision, skipDenied bool) ([]HostDecision, error) {
	var denied []HostDecision
	var keep []HostDecision
	for _, d := range decisions {
		if !d.Decision.Allowed {
			denied = append(denied, d)
			continue
		}
		keep = append(keep, d)
	}
	if len(denied) == 0 {
		return keep, nil
	}
	if !skipDenied {
		parts := make([]string, len(denied))
		for i, d := range denied {
			why := "denied"
			if len(d.Decision.Findings) > 0 {
				f := d.Decision.Findings[0]
				why = f.Layer + ": " + f.Detail
			}
			parts[i] = fmt.Sprintf("%s (%s)", d.Alias, why)
		}
		return nil, fmt.Errorf("batch aborted, %d host(s) denied: %s", len(denied), strings.Join(parts, "; "))
	}
	if len(keep) == 0 {
		return nil, fmt.Errorf("every selected host was denied")
	}
	return keep, nil
}
