package cli

import (
	"fmt"
	"time"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/exitcode"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/guard"
)

// Replaced in tests to verify startup failure before any remote dispatch.
var prepareImplicitExecDaemon = func(a *App) error {
	if err := a.ensureAutoDaemon(); err != nil {
		return err
	}
	return a.verifyAutoReuseCapabilities()
}

func (a *App) prepareExecReuse(plan []planned, script, fromStdin, forwardStdin, allowOutflow bool, timeout time.Duration) error {
	if allowOutflow && (a.UseDaemon || a.RequestAuto) {
		for _, p := range plan {
			if p.eff.NoDataOut {
				return exitcode.New(exitcode.Usage, "reuse cannot return protected output; use --direct with --allow-outflow and confirm on a TTY")
			}
		}
	}
	if a.RequestAuto {
		if a.UseDaemon || script || fromStdin || forwardStdin || a.Insecure {
			return exitcode.New(exitcode.Usage, "--auto-daemon requires literal exec, verified host keys, and no --daemon/stdin/script")
		}
		if !reusablePlan(plan) {
			return exitcode.New(exitcode.Denied, "--auto-daemon requires non-confirming readonly targets")
		}
		if err := a.ensureAutoDaemon(); err != nil {
			return err
		}
		a.UseDaemon, a.AutoDaemon = true, true
		return nil
	}
	if a.Direct || a.UseDaemon || script || fromStdin || forwardStdin || a.Insecure || allowOutflow ||
		!reusablePlan(plan) || len(plan) > guard.MaxBatchHosts || a.MaxOutputBytes <= 0 ||
		a.MaxOutputBytes > 64<<10 || timeout <= 0 || timeout > time.Hour {
		return nil
	}
	// Startup and compatibility checks do not dispatch commands. Only this
	// stage may fall back; runViaDaemon never retries after sending a request.
	if err := prepareImplicitExecDaemon(a); err != nil {
		if a.OperationContext != nil && a.OperationContext.Err() != nil {
			return a.OperationContext.Err()
		}
		fmt.Fprintf(a.Err, "warning: automatic connection reuse unavailable before dispatch; using direct SSH: %s\n", err)
		return nil
	}
	a.UseDaemon, a.AutoDaemon = true, true
	return nil
}
