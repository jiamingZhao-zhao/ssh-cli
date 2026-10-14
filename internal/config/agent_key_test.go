package config

import (
	"strings"
	"testing"
)

func TestAgentKeyValidationAndRouteIdentity(t *testing.T) {
	pin := "SHA256:" + strings.Repeat("A", 43)
	for _, tc := range []struct {
		auth, key string
		valid     bool
	}{
		{"agent", "", true}, {"agent", pin, true}, {"key", pin, false},
		{"agent", "SHA256:bad", false}, {"agent", pin + "=", false},
		{"agent", strings.Replace(pin, "SHA256:", "MD5:", 1), false},
	} {
		if err := ValidateAgentKey(tc.auth, tc.key); (err == nil) != tc.valid {
			t.Fatalf("%+v: %v", tc, err)
		}
	}
	hop := &Host{Host: "jump", User: "u", Auth: "agent"}
	target := &Host{Host: "target", User: "u", Auth: "agent", Via: "jump"}
	cfg := &Config{Groups: map[string]*Group{"g": {Hosts: map[string]*Host{"jump": hop, "target": target}}}}
	h, _ := cfg.Find("target")
	direct, route := hop.ConnFingerprint(), cfg.SessionFingerprint(h)
	hop.AgentKey = pin
	if direct == hop.ConnFingerprint() || route == cfg.SessionFingerprint(h) {
		t.Fatal("selected jump identity did not invalidate connection")
	}
	hop.AgentKey = ""
	if direct != hop.ConnFingerprint() || route != cfg.SessionFingerprint(h) {
		t.Fatal("empty selector changed legacy connection identity")
	}
}
