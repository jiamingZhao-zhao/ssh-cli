package cli

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/audit"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/config"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/exitcode"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/guard"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/transfer"
)

func (a *App) relayCmd() *cobra.Command {
	var from, to string
	cmd := &cobra.Command{
		Use:   "relay",
		Short: "Copy one remote file through this process to another host",
		Long: `Stream one file from --from alias:/path to --to alias:/path.

The bytes stay in this process only for the copy. ssh-cli hashes the stream
and checks sha256sum on the destination, or md5sum when sha256sum is missing.
Relay does not use -H. A protected destination path asks for the destination alias.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if len(a.Hosts)+len(a.Groups)+len(a.Tags) > 0 || a.Env != "" {
				return exitcode.New(exitcode.Usage, "relay selects hosts with --from and --to, not -H")
			}
			srcAlias, srcPath, err := splitEndpoint(from)
			if err != nil {
				return exitcode.New(exitcode.Usage, "--from: %s", err.Error())
			}
			dstAlias, dstPath, err := splitEndpoint(to)
			if err != nil {
				return exitcode.New(exitcode.Usage, "--to: %s", err.Error())
			}
			cfg, err := config.Load(a.Dir)
			if err != nil {
				return exitcode.New(exitcode.Usage, "%s", err.Error())
			}
			src, ok := cfg.Find(srcAlias)
			if !ok {
				return exitcode.New(exitcode.Usage, "unknown host %s", srcAlias)
			}
			dst, ok := cfg.Find(dstAlias)
			if !ok {
				return exitcode.New(exitcode.Usage, "unknown host %s", dstAlias)
			}
			srcEff, err := guard.Resolve(cfg, src, false)
			if err != nil {
				return exitcode.New(exitcode.Usage, "%s", err.Error())
			}
			dstEff, err := guard.Resolve(cfg, dst, false)
			if err != nil {
				return exitcode.New(exitcode.Usage, "%s", err.Error())
			}
			dec := guard.DecideRelay(srcEff, dstEff, src.EnvName, dst.EnvName, dstPath, a.AllowCrossEnv)
			meta := a.auditMeta(audit.OpRelay, "", srcAlias+":"+srcPath, dstAlias+":"+dstPath)
			if !dec.Allowed {
				a.logDenial(meta, dst, &dec, "")
				return exitcode.New(exitcode.Denied, "%s", decisionReason(dec))
			}
			if dec.NeedsConfirm {
				if err := confirmAlias(dst.Alias, a.Yes); err != nil {
					a.logDenial(meta, dst, &dec, err.Error())
					return err
				}
			}
			start := time.Now()
			srcClient, err := a.dial(src, 0)
			if err != nil {
				st, code := statusOf(0, err)
				_ = a.logRemote(meta, src, dec, st, code, err.Error(), err.Error())
				return err
			}
			defer srcClient.Close()
			dstClient, err := a.dial(dst, 0)
			if err != nil {
				st, code := statusOf(0, err)
				_ = a.logRemote(meta, dst, dec, st, code, err.Error(), err.Error())
				return err
			}
			defer dstClient.Close()
			res, err := transfer.Relay(srcClient.Raw(), dstClient.Raw(), srcPath, dstPath)
			meta.started = start
			if err != nil {
				_ = a.logRemote(meta, dst, dec, audit.StatusError, exitcode.Connect, err.Error(), err.Error())
				return exitcode.New(exitcode.Connect, "%s", err.Error())
			}
			summary := fmt.Sprintf("relay %s %d bytes", res.Algo, res.Bytes)
			if err := a.logRemote(meta, dst, dec, audit.StatusOK, 0, summary, ""); err != nil {
				return err
			}
			if a.JSON {
				return a.emit(map[string]any{"op": "relay", "from": from, "to": to, "bytes": res.Bytes, "algo": res.Algo, "sum": res.Sum})
			}
			fmt.Fprintf(a.Out, "relay ok %s %s %d bytes\n", res.Algo, res.Sum, res.Bytes)
			return nil
		},
	}
	cmd.Flags().StringVar(&from, "from", "", "source alias:/remote/path")
	cmd.Flags().StringVar(&to, "to", "", "destination alias:/remote/path")
	_ = cmd.MarkFlagRequired("from")
	_ = cmd.MarkFlagRequired("to")
	return cmd
}

func splitEndpoint(raw string) (alias, path string, err error) {
	raw = strings.TrimSpace(raw)
	alias, path, ok := strings.Cut(raw, ":")
	if !ok || strings.TrimSpace(alias) == "" || strings.TrimSpace(path) == "" {
		return "", "", fmt.Errorf("want alias:/path")
	}
	return strings.TrimSpace(alias), path, nil
}
