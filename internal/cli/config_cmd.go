package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/bundle"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/config"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/exitcode"
)

func (a *App) configCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Export or import hosts, policies, and key references",
		Long: `Export and import hosts, policies, env labels, and key references.

The bundle is YAML with kind ssh-cli-config. It stores passwordRef and identity
paths. It never contains plaintext passwords, secret bytes, or the master key.
Import does not change secrets.json. Built-in envs are restored on load.`,
	}
	cmd.AddCommand(a.configExport(), a.configImport())
	return cmd
}

func (a *App) configExport() *cobra.Command {
	var outPath string
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Write a secret-free config bundle",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.Load(a.Dir)
			if err != nil {
				return exitcode.New(exitcode.Usage, "%s", err.Error())
			}
			data, err := bundle.Export(cfg)
			if err != nil {
				return exitcode.New(exitcode.Usage, "%s", err.Error())
			}
			if outPath == "" || outPath == "-" {
				_, err := a.Out.Write(data)
				return err
			}
			if err := os.WriteFile(outPath, data, 0o600); err != nil {
				return exitcode.New(exitcode.Usage, "%s", err.Error())
			}
			fmt.Fprintf(a.Err, "wrote %s\n", outPath)
			return nil
		},
	}
	cmd.Flags().StringVarP(&outPath, "output", "o", "", "output file (default stdout)")
	return cmd
}

func (a *App) configImport() *cobra.Command {
	return &cobra.Command{
		Use:   "import <file>",
		Short: "Replace hosts and policies from a secret-free bundle",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := os.ReadFile(args[0])
			if err != nil {
				return exitcode.New(exitcode.Usage, "%s", err.Error())
			}
			err = config.Update(a.Dir, func(cfg *config.Config) error {
				return bundle.Apply(cfg, data)
			})
			if err != nil {
				return exitcode.New(exitcode.Usage, "%s", err.Error())
			}
			fmt.Fprintln(a.Out, "imported config bundle")
			return nil
		},
	}
}
