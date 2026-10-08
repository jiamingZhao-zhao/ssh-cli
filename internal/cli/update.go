package cli

import (
	"fmt"
	"os"
	"runtime"

	"github.com/spf13/cobra"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/exitcode"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/update"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/version"
)

func (a *App) updateCmd() *cobra.Command {
	var check, force bool
	var repo string
	cmd := &cobra.Command{
		Use:   "update",
		Short: "Install the latest GitHub release",
		Long: `Download the release asset for this OS and architecture and replace the
current executable. The command is opt-in: ssh-cli never updates itself in
the background.

Asset names (version has no leading v):
  ssh-cli_<version>_<os>_<arch>.tar.gz    Unix, contains ssh-cli
  ssh-cli_<version>_windows_<arch>.zip    Windows, contains ssh-cli.exe
  checksums.txt                           optional sha256sum manifest

When checksums.txt is missing, ssh-cli prints a warning and continues.
A published checksum that does not match is a hard error.

--repo or SSH_CLI_REPO selects owner/name (default jiamingZhao-zhao/ssh-cli).
The latest tag is read from https://github.com/<repo>/releases/latest (the
redirect to /releases/tag/<tag>). Archives and checksums.txt are downloaded
from /releases/download/<tag>/, not the GitHub REST API, so anonymous API
rate limits do not block an update. GITHUB_TOKEN is optional: it is sent to
api.github.com only when that direct lookup fails.
--check prints current and latest without installing.
Installing asks you to type the release version on a TTY. --yes skips that
prompt and is rejected when there is no TTY.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if repo == "" {
				repo = os.Getenv("SSH_CLI_REPO")
			}
			res, err := update.Run(cmd.Context(), update.Options{
				Repo:    repo,
				Current: version.Version,
				GOOS:    runtime.GOOS,
				GOARCH:  runtime.GOARCH,
				Check:   check,
				Force:   force,
				Confirm: func(latest string) error {
					return confirmRelease(latest, a.Yes)
				},
			})
			if err != nil {
				if res.Warning != "" && !a.JSON {
					fmt.Fprintf(a.Err, "warning: %s\n", res.Warning)
				}
				return err
			}
			if a.JSON {
				return a.emit(res)
			}
			if res.Warning != "" {
				fmt.Fprintf(a.Err, "warning: %s\n", res.Warning)
			}
			fmt.Fprintf(a.Out, "current: %s\nlatest: %s\nasset: %s\n", res.Current, res.Latest, res.Asset)
			switch {
			case res.Installed:
				fmt.Fprintf(a.Out, "installed %s\nrestart ssh-cli to use the new binary\n", res.Latest)
			case res.UpdateAvailable:
				fmt.Fprintln(a.Out, "update available")
			case res.Ahead:
				fmt.Fprintln(a.Out, "ahead of latest release")
			default:
				fmt.Fprintln(a.Out, "up to date")
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&check, "check", false, "print current and latest versions without installing")
	cmd.Flags().BoolVar(&force, "force", false, "install even when this build is not older than the release")
	cmd.Flags().StringVar(&repo, "repo", "", "GitHub owner/name (default: SSH_CLI_REPO or jiamingZhao-zhao/ssh-cli)")
	return cmd
}

func confirmRelease(latest string, yes bool) error {
	if yes {
		if !ttyCheck() {
			return exitcode.New(exitcode.Denied, "--yes is only valid on an interactive TTY")
		}
		return nil
	}
	if !ttyCheck() {
		return exitcode.New(exitcode.Denied, "update requires an interactive TTY; use --check to query only")
	}
	f, err := os.OpenFile(devTTY(), os.O_RDWR, 0)
	if err != nil {
		return exitcode.New(exitcode.Denied, "update requires an interactive TTY; use --check to query only")
	}
	defer f.Close()
	return confirmTyped(latest, "release version", f, f)
}
