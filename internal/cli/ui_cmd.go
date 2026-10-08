package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"

	"github.com/spf13/cobra"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/exitcode"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/ui"
)

func (a *App) uiCmd() *cobra.Command {
	addr := "127.0.0.1:7788"
	allow := false
	cmd := &cobra.Command{
		Use:   "ui",
		Short: "Start the optional localhost UI",
		Long: `Start a localhost-only web UI for config and the audit timeline.

The page edits envs, groups, hosts, named policies, and local known_hosts
through the same hosts.yaml, known_hosts, and secret store as the CLI.

The default bind is 127.0.0.1:7788. Binding 0.0.0.0 or any other non-loopback
address is refused unless --allow-non-loopback is set, which prints a warning.
The UI has no authentication. Do not expose it to a network.

Not running this command leaves exec, upload, download, and the audit log unchanged.
Stop the UI with Ctrl-C. There is no background daemon.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := ui.CheckBind(addr, allow); err != nil {
				return exitcode.New(exitcode.Usage, "%s", err.Error())
			}
			if allow && ui.WarnNonLoopback(addr) {
				fmt.Fprintf(a.Err, "warning: ssh-cli ui is binding %s outside the loopback interface. This UI has no authentication. Do not expose it to a network.\n", addr)
			}
			fmt.Fprintf(a.Err, "ssh-cli ui listening on http://%s\n", addr)
			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
			defer stop()
			if err := ui.Serve(ctx, addr, a.Dir, allow && ui.WarnNonLoopback(addr)); err != nil {
				return exitcode.New(exitcode.Usage, "%s", err.Error())
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&addr, "addr", "127.0.0.1:7788", "listen address (default 127.0.0.1:7788; loopback only)")
	cmd.Flags().BoolVar(&allow, "allow-non-loopback", false, "allow a non-loopback bind and print a warning; not for public networks")
	return cmd
}
