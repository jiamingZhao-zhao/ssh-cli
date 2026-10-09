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
		Long: `Start a localhost-only web UI for groups, host tags, policy rules, envs, hosts, known_hosts, and the audit timeline.

The page edits the same hosts.yaml, known_hosts, and secret store as the CLI.
Built-in env labels (dev, test, preprod, prod) are shown and cannot be changed.

The default bind is 127.0.0.1:7788. Binding 0.0.0.0 or any other non-loopback
address is refused unless --allow-non-loopback is set. That mode prints a
random bearer token once. Every /api request must send Authorization: Bearer
with that token. Host and Origin checks are not a security boundary on a
non-loopback bind, because a client can set Host: localhost. Prefer an SSH
tunnel to 127.0.0.1. Do not expose the port to a public network.

Not running this command leaves exec, upload, download, and the audit log unchanged.
Stop the UI with Ctrl-C. There is no background daemon.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := ui.CheckBind(addr, allow); err != nil {
				return exitcode.New(exitcode.Usage, "%s", err.Error())
			}
			remote := allow && ui.WarnNonLoopback(addr)
			bearer := ""
			if remote {
				bearer = ui.MintToken()
				fmt.Fprintf(a.Err, "warning: ssh-cli ui is binding %s outside the loopback interface. Every /api request must send Authorization: Bearer. Host and Origin headers are not a security boundary on this bind. Token (shown once): %s\n", addr, bearer)
				fmt.Fprintf(a.Err, "warning: prefer an SSH tunnel to 127.0.0.1. Do not expose this port to a public network.\n")
			}
			fmt.Fprintf(a.Err, "ssh-cli ui listening on http://%s\n", addr)
			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
			defer stop()
			if err := ui.Serve(ctx, addr, a.Dir, remote, bearer); err != nil {
				return exitcode.New(exitcode.Usage, "%s", err.Error())
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&addr, "addr", "127.0.0.1:7788", "listen address (default 127.0.0.1:7788; loopback only)")
	cmd.Flags().BoolVar(&allow, "allow-non-loopback", false, "allow a non-loopback bind; prints a one-time bearer token for /api")
	return cmd
}
