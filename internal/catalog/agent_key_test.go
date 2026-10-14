package catalog

import (
	"github.com/jiamingZhao-zhao/ssh-cli/internal/config"
	"strings"
	"testing"
)

func TestAgentKeyHostLifecycle(t *testing.T) {
	dir := t.TempDir()
	if err := AddGroup(dir, GroupDraft{Name: "app", Env: "test"}); err != nil {
		t.Fatal(err)
	}
	pin := "SHA256:" + strings.Repeat("A", 43)
	if err := AddHost(dir, HostDraft{Alias: "a", Group: "app", Address: "example", User: "u", Agent: true, AgentKey: pin}, Options{}); err != nil {
		t.Fatal(err)
	}
	if err := UpdateHost(dir, HostDraft{Alias: "a", AgentKey: "bad", HasAgentKey: true}, Options{}); err == nil {
		t.Fatal("malformed selection accepted")
	}
	cfg, err := config.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	h, _ := cfg.Find("a")
	if h.Host.AgentKey != pin {
		t.Fatal("failed edit changed pin")
	}
	if err := UpdateHost(dir, HostDraft{Alias: "a", HasAgentKey: true}, Options{}); err != nil {
		t.Fatal(err)
	}
	cfg, _ = config.Load(dir)
	h, _ = cfg.Find("a")
	if h.Host.AgentKey != "" || h.Host.Auth != "agent" {
		t.Fatal("clear selector changed auth")
	}
	if err := UpdateHost(dir, HostDraft{Alias: "a", AgentKey: pin, HasAgentKey: true}, Options{}); err != nil {
		t.Fatal(err)
	}
	if err := UpdateHost(dir, HostDraft{Alias: "a", HasIdentity: true, Identity: "~/.ssh/key"}, Options{}); err != nil {
		t.Fatal(err)
	}
	cfg, _ = config.Load(dir)
	h, _ = cfg.Find("a")
	if h.Host.AgentKey != "" || h.Host.Auth != "key" {
		t.Fatal("switch auth retained pin")
	}
	if err := UpdateHost(dir, HostDraft{Alias: "a", AgentKey: pin, HasAgentKey: true}, Options{}); err == nil {
		t.Fatal("non-agent edit accepted pin")
	}
}
