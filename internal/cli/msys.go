package cli

import (
	"fmt"
	"strings"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/transfer"
)

// warnMSYS prints one warning for each argument Git Bash appears to have
// rewritten. The argument is not changed.
func (a *App) warnMSYS(args []string) []string {
	warnings := msysWarnings(args)
	for _, w := range warnings {
		fmt.Fprintf(a.Err, "warning: %s\n", w)
	}
	return warnings
}

func msysWarnings(args []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, arg := range args {
		for _, field := range strings.Fields(arg) {
			guess, ok := transfer.MSYSRewrittenPath(field)
			if !ok {
				continue
			}
			msg := fmt.Sprintf("%s looks like Git Bash rewrote %s; pass //%s or set MSYS_NO_PATHCONV=1", field, guess, strings.TrimPrefix(guess, "/"))
			if seen[msg] {
				continue
			}
			seen[msg] = true
			out = append(out, msg)
		}
	}
	return out
}
