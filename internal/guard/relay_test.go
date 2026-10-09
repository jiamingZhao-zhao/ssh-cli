package guard

import (
	"testing"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/config"
)

func TestRelayPolicy(t *testing.T) {
	allow := Effective{Relay: string(config.RelayAllow)}
	source := Effective{Relay: string(config.RelaySourceOnly)}
	deny := Effective{Relay: string(config.RelayDeny)}
	if d := DecideRelay(allow, allow, "dev", "dev", "/tmp/a", false); !d.Allowed || d.NeedsConfirm {
		t.Fatalf("same env allow: %+v", d)
	}
	if d := DecideRelay(allow, source, "dev", "dev", "/tmp/a", false); d.Allowed {
		t.Fatal("source-only destination should be denied")
	}
	if d := DecideRelay(deny, allow, "dev", "dev", "/tmp/a", false); d.Allowed {
		t.Fatal("deny source should be denied")
	}
	if d := DecideRelay(allow, allow, "dev", "test", "/tmp/a", false); d.Allowed {
		t.Fatal("cross env without flag")
	}
	if d := DecideRelay(allow, allow, "dev", "test", "/tmp/a", true); !d.Allowed {
		t.Fatalf("cross env allowed: %+v", d)
	}
	locked := allow
	locked.NoDataOut = true
	if d := DecideRelay(locked, allow, "prod", "dev", "/tmp/a", true); d.Allowed {
		t.Fatal("noDataOutflow cross env")
	}
	protected := allow
	protected.Protected = []string{"/root"}
	if d := DecideRelay(allow, protected, "dev", "dev", "/root/app", false); !d.Allowed || !d.NeedsConfirm {
		t.Fatalf("protected dest: %+v", d)
	}
}
