package cli

import (
	"strings"
	"testing"
	"time"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/guard"
)

func TestStatusFactsMissingAndPartial(t *testing.T) {
	facts := map[string]any{}
	if parseStatusFact(facts, "load", "bad") {
		t.Fatal("invalid load accepted")
	}
	if !parseStatusFact(facts, "load", "0.13 0.07 0.05 1/200") {
		t.Fatal("valid load rejected")
	}
	if !parseStatusFact(facts, "memory", "              total used free shared buff/cache available\nMem: 1000 600 100 0 300 350\nSwap: 500 100 400\n") {
		t.Fatal("valid memory rejected")
	}
	mem := facts["memory"].(map[string]any)
	if mem["availableBytes"] != uint64(350) || mem["usedBytes"] != uint64(650) {
		t.Fatalf("bad memory facts: %+v", mem)
	}
	facts = map[string]any{}
	if !parseStatusFact(facts, "memory", "Mem: 1000 600 400\n") {
		t.Fatal("short free output rejected")
	}
	mem = facts["memory"].(map[string]any)
	if _, ok := mem["availableBytes"]; ok {
		t.Fatal("invented available memory")
	}
	if _, ok := facts["swap"]; ok {
		t.Fatal("invented swap")
	}
}

func TestLogQueryEscapingAndReadonly(t *testing.T) {
	now := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	cases := []struct{ file, unit, container, filter, since string }{
		{file: "/var/log/app.log", filter: "error; touch /tmp/no"},
		{file: "/var/log/app.log.gz"},
		{unit: "nginx", since: "15m", filter: "ERROR"},
		{container: "app", since: "15m"},
	}
	for _, tc := range cases {
		command, err := logCommand(tc.file, tc.unit, tc.container, tc.filter, tc.since, 100, now)
		if err != nil {
			t.Fatalf("%+v: %v", tc, err)
		}
		// A semicolon in a literal filter must remain data, not another command.
		decision := guard.DecideQuery(guard.Effective{}, command)
		if !decision.Allowed {
			t.Fatalf("readonly log %s: %+v", command, decision)
		}
		for _, parsed := range decision.Commands {
			if strings.HasPrefix(parsed, "touch ") {
				t.Fatalf("filter injected command: %s", command)
			}
		}
		if tc.filter != "" && !strings.Contains(command, "grep -F") {
			t.Fatalf("missing filter: %s", command)
		}
	}
	for _, tc := range []struct{ file, unit, container, since string }{
		{file: "/tmp/../secret"}, {unit: "nginx;id"}, {container: "--help"}, {file: "/tmp/log", since: "1h"}, {unit: "nginx", since: "-1h"},
	} {
		if _, err := logCommand(tc.file, tc.unit, tc.container, "", tc.since, 100, now); err == nil {
			t.Fatalf("invalid source accepted: %+v", tc)
		}
	}
}
