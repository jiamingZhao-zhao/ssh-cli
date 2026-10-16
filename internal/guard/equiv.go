package guard

import "strings"

// expandLifecycle closes a few operational bypasses of confirm and deny
// patterns. It does not change allow-lists.
//
// docker and podman: a restart pattern also matches stop, start and kill.
// stop or kill also matches restart and the other of stop/kill, but not start
// by itself. start does not expand. `docker container <verb>` is the same
// verb without the container word.
//
// systemctl and apps.sh: restart also matches stop and start. stop also
// matches restart. start does not expand.
//
// The returned detail is the configured pattern when the command matches it
// directly, or "<pattern>; equivalent <match>" when an expanded verb matched.
type lifePattern struct {
	match  string
	detail string
}

func expandLifecycle(patterns []string) []lifePattern {
	var out []lifePattern
	seen := map[string]bool{}
	add := func(match, detail string) {
		if match == "" || seen[match] {
			return
		}
		seen[match] = true
		out = append(out, lifePattern{match: match, detail: detail})
	}
	type extra struct{ match, detail string }
	var extras []extra
	for _, raw := range patterns {
		add(raw, raw)
		fields := canonicalizePattern(strings.Fields(raw))
		canon := strings.Join(fields, " ")
		if canon != raw {
			add(canon, raw)
		}
		if len(fields) < 2 {
			continue
		}
		tail := ""
		if len(fields) > 2 {
			tail = " " + strings.Join(fields[2:], " ")
		}
		for _, verb := range equivalentVerbs(fields[0], fields[1]) {
			match := fields[0] + " " + verb + tail
			extras = append(extras, extra{match: match, detail: raw + "; equivalent " + match})
		}
	}
	for _, item := range extras {
		add(item.match, item.detail)
	}
	return out
}

func canonicalizePattern(fields []string) []string {
	if len(fields) >= 3 && (fields[0] == "docker" || fields[0] == "podman") && fields[1] == "container" {
		out := make([]string, 0, len(fields)-1)
		out = append(out, fields[0])
		out = append(out, fields[2:]...)
		return out
	}
	return fields
}

func equivalentVerbs(tool, verb string) []string {
	switch tool {
	case "docker", "podman":
		switch verb {
		case "restart":
			return []string{"stop", "start", "kill"}
		case "stop":
			return []string{"restart", "kill"}
		case "kill":
			return []string{"restart", "stop"}
		}
	case "systemctl", "apps.sh":
		switch verb {
		case "restart":
			return []string{"stop", "start"}
		case "stop":
			return []string{"restart"}
		}
	}
	return nil
}

func canonicalizeService(args []Arg) []Arg {
	if len(args) < 3 || !args[0].Static || !args[1].Static || !args[2].Static {
		return args
	}
	base := commandBase(args[0].Value)
	if (base == "docker" || base == "podman") && args[1].Value == "container" {
		out := make([]Arg, 0, len(args)-1)
		out = append(out, args[0])
		out = append(out, args[2:]...)
		return out
	}
	return args
}

// EquivalenceNotes describes confirm or deny patterns that also match an
// operational equivalent. The order follows the configured patterns.
func EquivalenceNotes(patterns []string) []string {
	grouped := map[string][]string{}
	var order []string
	for _, item := range expandLifecycle(patterns) {
		source, equiv, ok := strings.Cut(item.detail, "; equivalent ")
		if !ok {
			continue
		}
		if _, seen := grouped[source]; !seen {
			order = append(order, source)
		}
		grouped[source] = append(grouped[source], equiv)
	}
	notes := make([]string, 0, len(order))
	for _, source := range order {
		notes = append(notes, source+" also matches "+strings.Join(grouped[source], ", "))
	}
	return notes
}
