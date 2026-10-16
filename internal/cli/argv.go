package cli

import "strings"

// shellCommand is the string a remote login shell will parse once.
//
// One argument is a shell script and is sent unchanged, so pipes, redirects
// and quotes written by the caller stay shell syntax. Two or more arguments
// are an argv array: each element is POSIX-single-quoted when it is not a
// safe literal, then joined with spaces. The remote shell's one parse restores
// that argv and executes it. Characters inside an argument, including quotes,
// spaces and shell metacharacters, are data. They are not parsed again.
//
// Safe literals are left unquoted, so an invocation such as
// `exec -- systemctl restart nginx` is still the string
// `systemctl restart nginx`.
func shellCommand(args []string) string {
	if len(args) == 1 {
		return args[0]
	}
	parts := make([]string, len(args))
	for i, arg := range args {
		parts[i] = quoteShell(arg)
	}
	return strings.Join(parts, " ")
}

func quoteShell(s string) string {
	if shellSafe(s) {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func shellSafe(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '_' || r == '-' || r == '.' || r == '/' || r == '@' || r == '%' || r == '+' || r == '=' || r == ':' || r == ',':
		default:
			return false
		}
	}
	return true
}
