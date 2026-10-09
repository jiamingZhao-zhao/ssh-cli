// Package cli is the cobra front end for ssh-cli.
package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/config"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/exitcode"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/policyhmac"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/version"
)

// App is one CLI invocation.
type App struct {
	In  io.Reader
	Out io.Writer
	Err io.Writer

	ConfigFlag    string
	JSON          bool
	Yes           bool
	Insecure      bool
	AllowCrossEnv bool
	SkipDenied    bool
	Hosts         []string
	Groups        []string
	Tags          []string
	Env           string
	Dir           string
}

// ttyCheck reports whether an interactive console is available.
// Tests replace it.
var ttyCheck = defaultTTY

func defaultTTY() bool {
	f, err := os.OpenFile(devTTY(), os.O_RDWR, 0)
	if err != nil {
		return false
	}
	defer f.Close()
	return term.IsTerminal(int(f.Fd()))
}

// Execute runs ssh-cli and returns a process status.
func Execute(args []string, in io.Reader, out, errw io.Writer) int {
	if in == nil {
		in = os.Stdin
	}
	if out == nil {
		out = os.Stdout
	}
	if errw == nil {
		errw = os.Stderr
	}
	policyhmac.Install()
	if err := rejectPasswordFlag(args); err != nil {
		fmt.Fprintf(errw, "error: %s\n", err)
		return exitcode.Usage
	}
	args = normalizeArgs(args)
	a := &App{In: in, Out: out, Err: errw}
	root := a.command()
	root.SetArgs(args)
	root.SetOut(out)
	root.SetErr(errw)
	root.SilenceErrors = true
	root.SilenceUsage = true
	err := root.Execute()
	if err == nil {
		return 0
	}
	var silent exitcode.Silent
	if errors.As(err, &silent) {
		return int(silent)
	}
	code := exitcode.From(err)
	if a.JSON {
		enc := json.NewEncoder(out)
		enc.SetEscapeHTML(false)
		_ = enc.Encode(map[string]any{"ok": false, "error": err.Error(), "code": code})
	} else {
		fmt.Fprintf(errw, "error: %s\n", err.Error())
	}
	return code
}

// normalizeArgs accepts the single-dash form -version as --version.
// pflag would otherwise read -version as a bundle of short flags.
func normalizeArgs(args []string) []string {
	out := append([]string(nil), args...)
	for i, a := range out {
		if a == "--" {
			break
		}
		if a == "-version" {
			out[i] = "--version"
		}
	}
	return out
}

func rejectPasswordFlag(args []string) error {
	for _, a := range args {
		if a == "--" {
			return nil
		}
		if a == "--password" || strings.HasPrefix(a, "--password=") {
			return fmt.Errorf("refusing plaintext --password; use --password-stdin or the hidden prompt")
		}
	}
	return nil
}

func (a *App) command() *cobra.Command {
	root := &cobra.Command{
		Use:   "ssh-cli",
		Short: "Encrypted SSH operations CLI",
		Long: `ssh-cli runs remote commands and SFTP transfers with encrypted credentials and a policy engine.

Print this build with "ssh-cli version", "ssh-cli --version", "ssh-cli -V", or "ssh-cli -version".
Install a newer GitHub release with "ssh-cli update" (opt-in; nothing updates in the background).

status, service, and keys use the same host selection and policy engine as exec.
import ssh-ops reads a local YAML or JSON inventory. The localhost UI edits the same hosts.yaml.`,
		Example: `  ssh-cli version
  ssh-cli -h
  ssh-cli update --check
  ssh-cli status -H main
  ssh-cli import ssh-ops --help`,
		Version:       version.String(),
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			// update installs when there is no TTY, so --yes is redundant there
			// and must not fail. Every other command still rejects --yes without a TTY.
			if a.Yes && !ttyCheck() && !nonInteractiveYesOK(cmd) {
				return exitcode.New(exitcode.Denied, "--yes is only valid on an interactive TTY")
			}
			dir, err := config.ResolveDir(a.ConfigFlag)
			if err != nil {
				return exitcode.New(exitcode.Usage, "%s", err.Error())
			}
			a.Dir = dir
			a.Hosts = splitList(a.Hosts)
			a.Groups = splitList(a.Groups)
			a.Tags = splitList(a.Tags)
			return nil
		},
	}
	f := root.PersistentFlags()
	f.StringVar(&a.ConfigFlag, "config", "", "config directory (default: SSH_CLI_HOME, else %APPDATA%\\ssh-cli or ~/.config/ssh-cli)")
	f.BoolVar(&a.JSON, "json", false, "print JSON on stdout")
	f.BoolVar(&a.Yes, "yes", false, "skip confirmation; only valid on an interactive TTY (update installs without a TTY)")
	f.BoolVar(&a.Insecure, "insecure-ignore-host-key", false, "do not verify host keys (escape hatch)")
	f.BoolVar(&a.AllowCrossEnv, "allow-cross-env", false, "allow one operation to target hosts in more than one env")
	f.BoolVar(&a.SkipDenied, "skip-denied", false, "skip hosts denied by policy instead of aborting the batch")
	f.StringArrayVarP(&a.Hosts, "host", "H", nil, "host alias (repeatable or comma-separated)")
	f.StringArrayVarP(&a.Groups, "group", "g", nil, "group name (repeatable or comma-separated)")
	f.StringArrayVarP(&a.Tags, "tag", "t", nil, "tag (repeatable or comma-separated; OR within tags)")
	f.StringVar(&a.Env, "env", "", "restrict the selection to this env")
	// Register --version/-V before Execute so cobra does not add the default -v shorthand.
	// -version is rewritten to --version in normalizeArgs.
	root.Flags().BoolP("version", "V", false, "print version and exit (also: -version)")
	root.SetVersionTemplate("{{.Version}}\n")
	root.CompletionOptions.HiddenDefaultCmd = true

	root.AddCommand(
		a.hostCmd(),
		a.groupCmd(),
		a.envCmd(),
		a.execCmd(),
		a.sessionCmd(),
		a.uploadCmd(),
		a.downloadCmd(),
		a.statusCmd(),
		a.serviceCmd(),
		a.keysCmd(),
		a.importCmd(),
		a.configCmd(),
		a.relayCmd(),
		a.policyCmd(),
		a.auditCmd(),
		a.uiCmd(),
		a.updateCmd(),
		a.versionCmd(),
	)
	return root
}

func (a *App) versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the version",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if a.JSON {
				return a.emit(version.Info())
			}
			fmt.Fprintln(a.Out, version.String())
			return nil
		},
	}
}

func (a *App) emit(v any) error {
	enc := json.NewEncoder(a.Out)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func (a *App) selector() config.Selector {
	return config.Selector{Hosts: a.Hosts, Groups: a.Groups, Tags: a.Tags, Env: a.Env}
}

func splitList(vals []string) []string {
	var out []string
	for _, v := range vals {
		for _, p := range strings.Split(v, ",") {
			p = strings.TrimSpace(p)
			if p != "" {
				out = append(out, p)
			}
		}
	}
	return out
}

func (a *App) rejectYesWithoutTTY() error {
	if a.Yes && !ttyCheck() {
		return exitcode.New(exitcode.Denied, "--yes is only valid on an interactive TTY")
	}
	return nil
}
