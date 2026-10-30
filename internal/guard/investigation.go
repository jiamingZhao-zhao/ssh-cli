package guard

import "strings"

// These additions are queries, not a blanket whitelist of executable names.
func investigationDeny(name string, args []Arg) string {
	for _, a := range args {
		if !a.Static {
			return "query arguments must be static literals"
		}
	}
	switch name {
	case "hostname":
		for _, a := range args[1:] {
			switch a.Value {
			case "-s", "-f", "-d", "-i", "-I", "-A", "--short", "--fqdn", "--domain", "--ip-address", "--all-ip-addresses", "--all-fqdns":
			default:
				return "hostname only permits query flags"
			}
		}
	case "ip":
		if len(args) < 2 {
			return "ip requires addr/address/route"
		}
		object := args[1].Value
		if object != "addr" && object != "address" && object != "route" {
			return "ip object is not a supported query"
		}
		if len(args) > 2 {
			verb := args[2].Value
			if verb != "show" && verb != "list" && !(object == "route" && verb == "get") {
				return "ip only permits show/list or route get"
			}
		}
		for _, a := range args[2:] {
			if strings.HasPrefix(a.Value, "-") {
				return "ip query options are not supported"
			}
		}
	case "file":
		for _, a := range args[1:] {
			if strings.Contains(a.Value, "C") && strings.HasPrefix(a.Value, "-") || len(a.Value) > 2 && strings.HasPrefix("--compile", a.Value) {
				return "file compilation is a write"
			}
		}
	case "sort":
		for _, a := range args[1:] {
			v := a.Value
			if strings.HasPrefix(v, "--") {
				n, _, _ := strings.Cut(v, "=")
				if len(n) > 2 && (strings.HasPrefix("--output", n) || strings.HasPrefix("--compress-program", n)) {
					return "sort output/program option is not readonly"
				}
			} else if strings.HasPrefix(v, "-") && strings.Contains(v, "o") {
				return "sort output option is not readonly"
			}
		}
	case "find":
		// Allow query predicates with fixed arity; unknown actions fail closed.
		arity := map[string]int{"-name": 1, "-iname": 1, "-path": 1, "-ipath": 1, "-type": 1, "-size": 1, "-mtime": 1, "-mmin": 1, "-user": 1, "-group": 1, "-maxdepth": 1, "-mindepth": 1, "-newer": 1, "-print": 0, "-print0": 0, "-printf": 1, "-ls": 0, "-empty": 0, "-readable": 0, "-writable": 0, "-executable": 0, "-true": 0, "-false": 0, "-a": 0, "-o": 0, "!": 0, "(": 0, ")": 0, "-not": 0, "-and": 0, "-or": 0, "-prune": 0, "-xdev": 0}
		for i := 1; i < len(args); i++ {
			v := args[i].Value
			if !strings.HasPrefix(v, "-") {
				continue
			}
			n, ok := arity[v]
			if !ok {
				return "find predicate/action not allowed: " + v
			}
			if i+n >= len(args) {
				return "find predicate missing operand"
			}
			i += n
		}
	}
	return ""
}
