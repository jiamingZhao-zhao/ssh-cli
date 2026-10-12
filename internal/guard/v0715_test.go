package guard

import (
	"github.com/jiamingZhao-zhao/ssh-cli/internal/config"
	"testing"
)

func TestRestrictedSocketFlagsAndRootProtection(t *testing.T) {
	eff := Effective{Mode: config.ModeStandard, Upload: true, Protected: []string{"/"}}
	if d := DecideCapability(eff, "upload", "/var/tmp/file"); !d.NeedsConfirm {
		t.Errorf("root protection did not cover descendant: %+v", d)
	}
	if d := DecideTerminal(Effective{Mode: config.ModeAdmin, NoDataOut: true}); d.Allowed {
		t.Error("terminal bypassed noDataOutflow")
	}
}
