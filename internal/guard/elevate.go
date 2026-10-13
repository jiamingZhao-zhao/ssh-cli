package guard

import (
	"fmt"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/config"
)

// ResolveElevated is called only by the typed, single-command CLI entry point.
// It never changes cfg or grants the unrestricted terminal capability.
func ResolveElevated(cfg *config.Config, h config.ResolvedHost) (Effective, error) {
	if h.Env == nil || h.Env.BreakGlass == nil || !h.Env.BreakGlass.Enabled {
		return Effective{}, fmt.Errorf("break glass is disabled")
	}
	env := *h.Env
	if env.MaxMode != config.ModeReadonly {
		return Effective{}, fmt.Errorf("break glass requires a readonly environment")
	}
	env.MaxMode = config.ModeStandard
	if env.DefaultPolicy == "readonly" && cfg.Policies["readonly"] == nil {
		env.DefaultPolicy = "standard"
	}
	h.Env = &env
	return Resolve(cfg, h, false)
}
