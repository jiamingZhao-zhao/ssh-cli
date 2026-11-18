package cli

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/audit"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/config"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/exitcode"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/guard"
	"golang.org/x/crypto/ssh"
)

func inventoryTCPAddress(cfg *config.Config, env string, target netip.Addr, cross bool) bool {
	if target.IsLoopback() {
		return true
	}
	for _, host := range cfg.Index() {
		if host.Host == nil || host.EnvName != env && !cross {
			continue
		}
		for _, value := range []string{host.Host.Host, host.Host.LANIP, host.Host.PublicIP} {
			if address, err := netip.ParseAddr(value); err == nil && address.Unmap() == target.Unmap() {
				return true
			}
		}
	}
	return false
}

func tcpOutcome(err error) string {
	if err == nil {
		return "connected"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	if errors.Is(err, context.Canceled) {
		return "canceled"
	}
	var channel *ssh.OpenChannelError
	if errors.As(err, &channel) {
		if channel.Reason == ssh.Prohibited || channel.Reason == ssh.UnknownChannelType {
			return "ssh_channel_denied"
		}
		if channel.Reason == ssh.ConnectionFailed {
			message := strings.ToLower(channel.Message)
			switch {
			case strings.Contains(message, "connection refused"):
				return "refused"
			case strings.Contains(message, "timed out"):
				return "timeout"
			case strings.Contains(message, "no route to host") || strings.Contains(message, "network is unreachable"):
				return "unreachable"
			}
		}
	}
	return "connect_failed"
}

func (a *App) runTCPCheck(raw string, timeout, budget time.Duration) error {
	if len(a.Hosts) != 1 || len(a.Groups) != 0 || len(a.Tags) != 0 || a.Env != "" || a.UseDaemon || a.RequestAuto || a.Insecure {
		return exitcode.New(exitcode.Usage, "--tcp requires one explicit -H host, direct SSH and verified host keys")
	}
	endpoint, err := netip.ParseAddrPort(raw)
	if err != nil || endpoint.Port() == 0 || endpoint.Addr().Zone() != "" || endpoint.Addr().IsUnspecified() || endpoint.Addr().IsMulticast() {
		return exitcode.New(exitcode.Usage, "--tcp requires one numeric IP and port, e.g. 127.0.0.1:8080 or [::1]:8080")
	}
	endpoint = netip.AddrPortFrom(endpoint.Addr().Unmap(), endpoint.Port())
	meta := a.auditMeta(audit.OpExec, "tcp check "+endpoint.String(), "", "")
	cfg, hosts, err := a.loadSelection()
	if err != nil {
		a.auditSelectionError(meta, hosts, err)
		return err
	}
	if len(hosts) != 1 {
		return exitcode.New(exitcode.Usage, "--tcp requires one source host")
	}
	targetAllowed := inventoryTCPAddress(cfg, hosts[0].EnvName, endpoint.Addr(), a.AllowCrossEnv)
	policyCommand := shellCommand([]string{"nc", "-z", "-n", "-w", "5", endpoint.Addr().String(), strconv.Itoa(int(endpoint.Port()))})
	plan, err := a.plan(cfg, hosts, meta, func(eff guard.Effective) guard.Decision {
		decision := guard.DecideQuery(eff, policyCommand)
		if !targetAllowed || eff.NoDataOut {
			decision.Allowed, decision.NeedsConfirm = false, false
			detail := "TCP destination must be a registered address in the selected environment or loopback"
			if eff.NoDataOut {
				detail = "noDataOutflow forbids returning TCP probe results"
			}
			decision.Findings = append(decision.Findings, guard.Finding{Layer: "tcp", Kind: "deny", Detail: detail})
		}
		return decision
	})
	if err != nil {
		return err
	}
	source := plan[0]
	if err := a.confirmPlanned(meta, source); err != nil {
		return err
	}
	if err := audit.Preflight(a.Dir, audit.SourceCLI, "check --tcp"); err != nil {
		return err
	}
	parent := a.OperationContext
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithTimeout(parent, budget)
	defer cancel()
	started := time.Now()
	client, err := a.queryCopy(ctx).dial(source.host, budget)
	if err != nil {
		if auditErr := a.auditHost(meta, source, started, exitcode.From(err), err, "SSH connection could not be established"); auditErr != nil {
			return auditErr
		}
		return err
	}
	defer client.Close()
	probe, stop := context.WithTimeout(ctx, timeout)
	defer stop()
	startProbe := time.Now()
	conn, probeErr := client.Raw().DialContext(probe, "tcp", endpoint.String())
	if conn != nil {
		_ = conn.Close()
	}
	result := tcpOutcome(probeErr)
	duration := time.Since(startProbe).Milliseconds()
	code := 0
	if probeErr != nil {
		code = exitcode.Connect
	}
	if err := a.auditHost(meta, source, started, code, nil, "TCP check: "+result); err != nil {
		return err
	}
	if a.JSON {
		if err := a.emit(map[string]any{"host": source.host.Alias, "env": source.host.EnvName, "target": endpoint.String(), "tcpStatus": result, "durationMs": duration, "exitCode": code}); err != nil {
			return err
		}
	} else {
		fmt.Fprintf(a.Out, "%s → %s: %s (%d ms)\n", source.host.Alias, endpoint, result, duration)
	}
	if code != 0 {
		return exitcode.Silent(code)
	}
	return nil
}
