package guard

import (
	"path"
	"strings"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/config"
)

// semanticDeny tightens commands whose name is allowed but whose arguments
// change the operation. Readonly and standard refuse journalctl mutations and
// pager shell escapes. Admin is unchanged.
func semanticDeny(mode config.Mode, args []Arg) string {
	if len(args) == 0 || !args[0].Static {
		return ""
	}
	name := path.Base(args[0].Value)
	switch name {
	case "journalctl":
		return journalctlDeny(mode, args)
	case "ss":
		return ssDeny(mode, args)
	case "less", "more", "most":
		return pagerDeny(mode, name, args)
	default:
		return ""
	}
}

// ssDeny rejects socket-killing and diag-file options. The readonly allow-list
// names ss, which is not enough: -K/--kill closes sockets and -D/--diag writes
// a dump. Admin is unchanged. A non-static argument is refused outside admin
// because it can hide those flags. Short options that take a value are f, A,
// F, N, and M; D is itself a mutating flag.
func ssDeny(mode config.Mode, args []Arg) string {
	if mode == config.ModeAdmin {
		return ""
	}
	i := 1
	for i < len(args) {
		a := args[i]
		if !a.Static {
			return "ss argument is not a static literal"
		}
		v := a.Value
		if v == "--" {
			for _, rest := range args[i+1:] {
				if !rest.Static {
					return "ss argument is not a static literal"
				}
			}
			return ""
		}
		if v == "-" || !strings.HasPrefix(v, "-") {
			i++
			continue
		}
		if strings.HasPrefix(v, "--") {
			name, _, _ := strings.Cut(v, "=")
			switch name {
			case "--kill":
				return "ss kill flag"
			case "--diag":
				return "ss diag flag"
			}
			i++
			continue
		}
		chars := v[1:]
		k := 0
		step := 1
		for k < len(chars) {
			switch chars[k] {
			case 'K':
				return "ss kill flag"
			case 'D':
				return "ss diag flag"
			case 'f', 'A', 'F', 'N', 'M':
				if k+1 < len(chars) {
					k = len(chars)
					continue
				}
				if i+1 < len(args) {
					if !args[i+1].Static {
						return "ss argument is not a static literal"
					}
					step = 2
				}
				k = len(chars)
			default:
				k++
			}
		}
		i += step
	}
	return ""
}

func journalctlDeny(mode config.Mode, args []Arg) string {
	if mode == config.ModeAdmin {
		return ""
	}
	for _, a := range args[1:] {
		if !a.Static {
			if mode == config.ModeReadonly {
				return "journalctl argument is not a static literal"
			}
			continue
		}
		name, _, _ := strings.Cut(a.Value, "=")
		switch name {
		case "--vacuum-size", "--vacuum-time", "--vacuum-files", "--rotate", "--flush", "--sync", "--relinquish-var", "--setup-keys", "--force":
			return "journalctl mutating flag " + name
		}
	}
	return ""
}

func pagerDeny(mode config.Mode, name string, args []Arg) string {
	if mode == config.ModeAdmin {
		return ""
	}
	for _, a := range args[1:] {
		if !a.Static {
			continue
		}
		if strings.Contains(a.Value, "+!") || a.Value == "--shell" || strings.HasPrefix(a.Value, "--shell=") {
			return name + " shell escape"
		}
	}
	return ""
}
