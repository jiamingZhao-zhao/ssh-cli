package cli

import "github.com/jiamingZhao-zhao/ssh-cli/internal/output"

func (a *App) printer() output.Printer {
	return output.New(a.JSON, a.Out, a.Err)
}
