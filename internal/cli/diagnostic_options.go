package cli

import (
	"github.com/jiamingZhao-zhao/ssh-cli/internal/config"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/exitcode"
	"strings"
)

func reusablePlan(plan []planned) bool {
	if len(plan) == 0 {
		return false
	}
	for _, p := range plan {
		if p.eff.Mode != config.ModeReadonly || p.dec.NeedsConfirm {
			return false
		}
	}
	return true
}

func (a *App) prepareQueryReuse(plan []planned) error {
	if a.RequestAuto && (a.UseDaemon || a.Insecure || !reusablePlan(plan)) {
		return exitcode.New(exitcode.Denied, "--auto-daemon requires non-confirming readonly targets, verified host keys and no --daemon")
	}
	if a.RequestAuto || a.AgentProfile && !a.Direct && !a.UseDaemon && !a.Insecure && reusablePlan(plan) {
		if err := a.ensureAutoDaemon(); err != nil {
			return err
		}
		a.UseDaemon, a.AutoDaemon = true, true
	}
	return nil
}

type guidance struct {
	Kind       string `json:"kind"`
	NextAction string `json:"nextAction"`
}

func errorGuidance(code int, text string) guidance {
	s := strings.ToLower(text)
	switch {
	case strings.Contains(s, "confirmation") || strings.Contains(s, "interactive tty"):
		return guidance{"confirmation_required", "Ask the user to run the command in their interactive terminal and type the requested host alias or policy name. Do not add --yes or change policy to bypass this gate."}
	case code == exitcode.Denied:
		return guidance{"policy_denied", "Read denials/findings or policy show for this host. Use an allowed query; do not weaken policy automatically."}
	case code == exitcode.HostKey || strings.Contains(s, "host key"):
		return guidance{"host_key_changed", "Verify the host key fingerprint through an independent trusted channel. Do not disable host-key checks or remove a trusted key automatically."}
	case code == exitcode.Auth || strings.Contains(s, "authenticate") || strings.Contains(s, "authentication"):
		return guidance{"authentication_failed", "Ask the user to check the configured credential or selected SSH-agent identity; do not change identities automatically."}
	case code == exitcode.Usage:
		return guidance{"invalid_arguments", "Read this command's --help and correct the arguments; no automatic remote retry."}
	case strings.Contains(s, "jump") || strings.Contains(s, "hop"):
		return guidance{"jump_route_failed", "Check the configured via chain and each hop's reachability, host key and credentials. If dispatch may have occurred, verify remote state first."}
	case strings.Contains(s, "timeout") || strings.Contains(s, "timed out") || strings.Contains(s, "deadline exceeded"):
		return guidance{"timeout", "Check connectivity and command duration. If dispatch may have occurred, verify remote state before retrying."}
	case strings.Contains(s, "no such host") || strings.Contains(s, "name resolution"):
		return guidance{"name_resolution_failed", "Check the configured host address and DNS on the client or jump route."}
	case strings.Contains(s, "connection refused") || strings.Contains(s, "no route to host") || strings.Contains(s, "network is unreachable"):
		return guidance{"network_unreachable", "Check host address, port, network route and SSH service. If dispatch may have occurred, verify remote state first."}
	case code == exitcode.Connect:
		return guidance{"connection_or_execution_unknown", "Check the host and jump route. If dispatch may have occurred, verify remote state before retrying."}
	default:
		return guidance{"operation_failed", "Inspect the result and verify remote state before deciding whether to retry."}
	}
}
