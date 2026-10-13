package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/audit"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/config"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/exitcode"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/guard"
	"github.com/spf13/cobra"
)

// Elevation is a single human-driven command, never a reusable grant available
// to another process. It raises only the environment's implicit readonly default
// to standard; explicit group/host policies, denies and outflow restrictions stay.
func (a *App) elevateCmd() *cobra.Command {
	var ttl, reason string
	cmd := &cobra.Command{Use: "elevate <alias> --ttl 15m --reason <reason> -- <command>", Short: "Run one human-confirmed break-glass command with a bounded lifetime", Args: cobra.MinimumNArgs(2), RunE: func(cmd *cobra.Command, args []string) error {
		if !ttyCheck() || a.Yes {
			return exitcode.New(exitcode.Denied, "elevate requires a typed interactive TTY confirmation; --yes is not accepted")
		}
		if cmd.ArgsLenAtDash() != 1 {
			return exitcode.New(exitcode.Usage, "use elevate <alias> --ttl 15m --reason <reason> -- <command>")
		}
		if strings.TrimSpace(reason) == "" {
			return exitcode.New(exitcode.Usage, "--reason is required")
		}
		cfg, err := config.Load(a.Dir)
		if err != nil {
			return err
		}
		h, ok := cfg.Find(args[0])
		if !ok {
			return exitcode.New(exitcode.Usage, "unknown host %s", args[0])
		}
		duration, err := elevationTTL(h.Env, ttl)
		if err != nil {
			return exitcode.New(exitcode.Denied, "%s", err.Error())
		}
		eff, err := guard.ResolveElevated(cfg, h)
		if err != nil {
			return exitcode.New(exitcode.Denied, "%s", err.Error())
		}
		command := strings.Join(args[1:], " ")
		dec := guard.Decide(eff, command)
		if !dec.Allowed {
			return exitcode.New(exitcode.Denied, "%s", decisionReason(dec))
		}
		fmt.Fprintf(a.Err, "Break glass: %s (%s, %s@%s), max %s\nReason: %s\nCommand: %s\n", h.Alias, h.EnvName, h.Host.User, h.Host.Host, duration, audit.Scrub(reason), audit.Scrub(command))
		if err := confirmAlias("elevate:"+h.Alias, false); err != nil {
			return err
		}
		// Persist admission even when ordinary audit fail-closed mode is disabled.
		if _, err := audit.Append(a.Dir, audit.Record{Op: audit.OpElevate, Host: h.Alias, Group: h.Group, Env: h.EnvName, Command: command, Reason: reason + "; ttl=" + duration.String(), Status: audit.StatusOK, HighRisk: true}); err != nil {
			return exitcode.New(exitcode.Denied, "elevate audit unavailable: %s", err.Error())
		}
		ctx, cancel := signal.NotifyContext(cmd.Context(), os.Interrupt)
		defer cancel()
		ctx, deadline := context.WithTimeout(ctx, duration)
		defer deadline()
		a.OperationContext = ctx
		defer func() { a.OperationContext = nil }()
		meta := a.auditMeta(audit.OpExec, command, "", "")
		return a.runAll(meta, []planned{{host: h, eff: eff, dec: dec}}, command, "", duration, false, 1)
	}}
	cmd.Flags().StringVar(&ttl, "ttl", "15m", "maximum operation duration, bounded by configured breakGlass.maxTtl")
	cmd.Flags().StringVar(&reason, "reason", "", "reason recorded in the audit log")
	var maxTTL string
	var disable bool
	configure := &cobra.Command{Use: "configure <env>", Short: "Explicitly enable or disable single-command break glass", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		if !ttyCheck() || a.Yes {
			return exitcode.New(exitcode.Denied, "elevate configure requires typed TTY confirmation")
		}
		d, err := time.ParseDuration(maxTTL)
		if err != nil || d <= 0 || d > time.Hour {
			return exitcode.New(exitcode.Usage, "--max-ttl must be greater than zero and at most 1h")
		}
		if err := confirmAlias("break-glass:"+args[0], false); err != nil {
			return err
		}
		if _, err := audit.Append(a.Dir, audit.Record{Op: audit.OpElevate, Env: args[0], Status: audit.StatusOK, HighRisk: true, Reason: fmt.Sprintf("configure breakGlass enabled=%t maxTtl=%s", !disable, d)}); err != nil {
			return err
		}
		return config.Update(a.Dir, func(cfg *config.Config) error {
			e := cfg.Envs[args[0]]
			if e == nil {
				return fmt.Errorf("unknown env %s", args[0])
			}
			e.BreakGlass = &config.BreakGlass{Enabled: !disable, MaxTTL: d.String()}
			return nil
		})
	}}
	configure.Flags().StringVar(&maxTTL, "max-ttl", "30m", "maximum TTL (at most 1h)")
	configure.Flags().BoolVar(&disable, "disable", false, "disable break glass")
	cmd.AddCommand(configure)
	return cmd
}

func elevationTTL(env *config.Env, raw string) (time.Duration, error) {
	if env == nil || env.BreakGlass == nil || !env.BreakGlass.Enabled {
		return 0, fmt.Errorf("break glass is disabled for this environment")
	}
	max := 30 * time.Minute
	if env.BreakGlass.MaxTTL != "" {
		var err error
		max, err = time.ParseDuration(env.BreakGlass.MaxTTL)
		if err != nil {
			return 0, err
		}
	}
	d, err := time.ParseDuration(raw)
	if err != nil || max <= 0 || max > time.Hour || d <= 0 || d > max {
		return 0, fmt.Errorf("TTL must be positive and at most %s (absolute limit 1h)", max)
	}
	return d, nil
}
