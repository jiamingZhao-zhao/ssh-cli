package guard

import (
	"strings"
	"testing"
)

func TestReadonlyInvestigation(t *testing.T) {
	cfg, h := prodReadonlyHost("", nil)
	eff := resolve(t, cfg, h, false)
	for _, s := range []string{"docker ps 2>/dev/null", "ls >/dev/null 2>&1", "ls &>/dev/null", "ls 2>&1", "ip addr", "ip route show", "ip route get 192.0.2.1", "hostname -I", "uname -a", "stat /tmp", "file /bin/sh", "which java", "whereis java", "ps -ef | grep nginx | cut -c1-120", "cat /tmp/log | sort | uniq | wc -l", "find /var/log -maxdepth 2 -name '*.log' -print"} {
		if d := Decide(eff, s); !d.Allowed {
			t.Errorf("query %s: %+v", s, d)
		}
	}
	for _, s := range []string{">/tmp/out", "ls; >/tmp/out", "ls >/tmp/out", "ls >&/tmp/out", "ls >/dev/null; rm /tmp/x", "ls >$DEST", "ls >$(touch /tmp/x)", "ip route add default via 192.0.2.1", "ip addr flush dev eth0", "ip -batch /tmp/cmd", "hostname changed", "file -C", "sort -o /tmp/x", "sort --out=/tmp/x", "sort --compress-program=sh", "find / -delete", "find / -exec touch /tmp/x \\;", "find / -execdir sh \\;", "find / -fprint /tmp/x"} {
		if d := Decide(eff, s); d.Allowed {
			t.Errorf("mutation allowed: %s", s)
		}
	}
	d := Decide(eff, "ps -ef | grep nginx; touch /tmp/no")
	found := false
	for _, f := range d.Findings {
		if f.Command == "touch /tmp/no" && strings.Contains(f.Detail, "touch /tmp/no") {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing exact command: %+v", d)
	}
}
