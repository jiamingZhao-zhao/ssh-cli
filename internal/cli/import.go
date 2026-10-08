package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/catalog"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/exitcode"
)

const importHelp = `Import hosts, groups, envs, and named policies from a local ssh-ops style
YAML or JSON file. ssh-cli reads the file on disk and does not connect to
any host. Passwords are encrypted into secrets.json and are not written to
hosts.yaml. Delete the inventory after a successful import.

The document is either an object or a list of servers. JSON is accepted
because it is valid YAML. Top-level fields:

  version: 1                  optional; only version 1 is accepted
  default: main               optional alias to make the default host
  policies:                   named policies (mode, allow, deny, confirm, capabilities)
  envs:                       env labels (label, color, maxMode, defaultPolicy)
  groups:                     groups with env, policy, protectedPaths, and hosts
  servers:                    or "hosts": a map or list of servers

A server accepts these fields (aliases in parentheses):

  alias (name, id)            required for a list; the map key is the alias
  host (hostname, address, ip)
  port                        number, default 22
  user (username)
  password (passwd)           encrypted into the secret store; never printed
  passwordRef                 use a secret that is already stored
  identity (identityFile, key) path to a private key, not the key text
  group                       required unless --default-group is set
  env (environment)           used when the group does not already exist
  tags (tag)                  string or list
  policy                      named policy
  auth                        password or key

Example:

  default: main
  envs:
    prod: {label: 生产, color: red, maxMode: readonly, defaultPolicy: readonly}
    dev: {label: 开发, maxMode: admin}
  groups:
    app-prod: {env: prod, policy: readonly}
  servers:
    main:
      host: 192.0.2.10
      user: viewer
      password: "replace-me"
      group: app-prod
      tags: [app]
    dev-1:
      hostname: 192.0.2.30
      username: root
      identity: ~/.ssh/id_ed25519
      group: sandbox
      env: dev

A bare list is also valid:

  - alias: main
    host: 192.0.2.10
    user: root
    password: "replace-me"
    group: app
    env: dev

Groups may nest hosts the same way hosts.yaml does, with a password field
in place of passwordRef. Inline group allow/deny is rejected; put those
rules in a named policy. Unknown secret-like fields (secret, pass,
privateKey) are rejected so they are not dropped silently. Other unknown
host fields are ignored.

Missing envs are created with --max-mode (default standard). Missing groups
use --default-group, or the name "imported". Use --dry-run to print the
plan without writing hosts.yaml or secrets.json.`

func (a *App) importCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "import",
		Short: "Import hosts and groups from a local inventory file",
		Long:  importHelp,
	}
	cmd.AddCommand(a.importSSHOps())
	return cmd
}

func (a *App) importSSHOps() *cobra.Command {
	var dry, skip bool
	var defEnv, defGroup, maxMode string
	cmd := &cobra.Command{
		Use:   "ssh-ops <file>",
		Short: "Import an ssh-ops YAML or JSON inventory",
		Long:  importHelp,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := os.ReadFile(args[0])
			if err != nil {
				return exitcode.New(exitcode.Usage, "%s", err.Error())
			}
			result, err := catalog.Import(a.Dir, data, catalog.ImportOptions{
				DryRun:       dry,
				SkipExisting: skip,
				DefaultEnv:   defEnv,
				DefaultGroup: defGroup,
				MaxMode:      maxMode,
				Warn:         catalog.Options{Warn: a.Err},
			})
			if err != nil {
				return catalogErr(err)
			}
			if a.JSON {
				if err := a.emit(result); err != nil {
					return err
				}
			} else if len(result.Changes) == 0 {
				fmt.Fprintln(a.Out, "no changes")
			} else {
				for _, c := range result.Changes {
					if c.Detail == "" {
						fmt.Fprintf(a.Out, "%s %s\n", c.Action, c.Name)
					} else {
						fmt.Fprintf(a.Out, "%s %s %s\n", c.Action, c.Name, c.Detail)
					}
				}
			}
			if result.PlaintextPasswords > 0 && !dry {
				fmt.Fprintf(a.Err, "imported %d password(s) into the encrypted store; delete the plaintext inventory %s\n", result.PlaintextPasswords, args[0])
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&dry, "dry-run", false, "print the planned changes and write nothing")
	cmd.Flags().BoolVar(&skip, "skip-existing", false, "skip hosts, groups, envs, and policies that already exist")
	cmd.Flags().StringVar(&defEnv, "default-env", "", "env used when an imported group or host does not name one")
	cmd.Flags().StringVar(&defGroup, "default-group", "", "group used when an imported host does not name one")
	cmd.Flags().StringVar(&maxMode, "max-mode", "standard", "maxMode for environments created because they were missing")
	return cmd
}
