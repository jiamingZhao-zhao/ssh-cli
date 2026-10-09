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
	case "less", "more", "most":
		return pagerDeny(mode, name, args)
	default:
		return ""
	}
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
