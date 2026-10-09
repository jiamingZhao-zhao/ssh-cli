package guard

import "strings"

// normalizeOps drops known global options that sit in front of the operation
// verb. systemctl --no-pager restart therefore matches systemctl restart.
// The command name itself is left unchanged.
func normalizeOps(args []Arg) []Arg {
	if len(args) == 0 || !args[0].Static {
		return args
	}
	switch commandBase(args[0].Value) {
	case "systemctl":
		return stripLeadingOptions(args, systemctlTakesArg)
	case "docker":
		return stripLeadingOptions(args, dockerTakesArg)
	default:
		return args
	}
}

func commandBase(argv0 string) string {
	base, _ := commandIdentity(argv0)
	return base
}

func stripLeadingOptions(args []Arg, takesArg func(string) bool) []Arg {
	out := []Arg{args[0]}
	i := 1
	for i < len(args) {
		a := args[i]
		if !a.Static || a.Value == "" || a.Value == "-" || !strings.HasPrefix(a.Value, "-") {
			return append(out, args[i:]...)
		}
		if a.Value == "--" {
			return append(out, args[i+1:]...)
		}
		name, _, hasEq := strings.Cut(a.Value, "=")
		if strings.HasPrefix(a.Value, "--") {
			if takesArg(name) && !hasEq {
				if i+1 >= len(args) {
					return append(out, args[i:]...)
				}
				i += 2
				continue
			}
			i++
			continue
		}
		chars := a.Value[1:]
		for j := 0; j < len(chars); j++ {
			opt := "-" + string(chars[j])
			if takesArg(opt) {
				if j+1 < len(chars) {
					i++
					chars = ""
					break
				}
				if i+1 >= len(args) {
					return append(out, args[i:]...)
				}
				i += 2
				chars = ""
				break
			}
		}
		if chars != "" {
			i++
		}
	}
	return out
}

func systemctlTakesArg(name string) bool {
	switch name {
	case "-t", "--type", "-p", "--property", "-s", "--signal", "-H", "--host",
		"-M", "--machine", "-o", "--output", "-n", "--lines", "--job-mode",
		"--root", "--image", "--kill-who", "--kill-mode", "--what", "--message",
		"--preset-mode", "--state":
		return true
	default:
		return false
	}
}

func dockerTakesArg(name string) bool {
	switch name {
	case "-H", "--host", "-c", "--config", "--context", "-l", "--log-level",
		"--tlscacert", "--tlscert", "--tlskey":
		return true
	default:
		return false
	}
}
