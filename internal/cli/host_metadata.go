package cli

import (
	"fmt"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/config"
	"github.com/spf13/cobra"
	"net"
)

func (a *App) hostMetadata() *cobra.Command {
	var lan, public string
	var roles, entries []string
	cmd := &cobra.Command{Use: "metadata <alias>", Short: "Edit descriptive IPs, roles and served entrypoints (never changes SSH routing)", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		for _, v := range []string{lan, public} {
			if v != "" && net.ParseIP(v) == nil {
				return fmt.Errorf("metadata IP must be an IP literal")
			}
		}
		return config.Update(a.Dir, func(cfg *config.Config) error {
			h, ok := cfg.Find(args[0])
			if !ok {
				return fmt.Errorf("unknown host %s", args[0])
			}
			if cmd.Flags().Changed("lan-ip") {
				h.Host.LANIP = lan
			}
			if cmd.Flags().Changed("public-ip") {
				h.Host.PublicIP = public
			}
			if cmd.Flags().Changed("role") {
				h.Host.Roles = splitList(roles)
			}
			if cmd.Flags().Changed("entrypoint") {
				h.Host.Entrypoints = splitList(entries)
			}
			return nil
		})
	}}
	cmd.Flags().StringVar(&lan, "lan-ip", "", "LAN IP annotation; empty clears")
	cmd.Flags().StringVar(&public, "public-ip", "", "public IP annotation; empty clears")
	cmd.Flags().StringArrayVar(&roles, "role", nil, "descriptive role, repeatable; replaces list")
	cmd.Flags().StringArrayVar(&entries, "entrypoint", nil, "served environment/service label, repeatable; replaces list")
	return cmd
}
