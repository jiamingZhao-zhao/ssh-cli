package sshclient

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func TestAgentKeySelectionDoesNotFallBack(t *testing.T) {
	ring := agent.NewKeyring()
	for i := 0; i < 20; i++ {
		_, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if err := ring.Add(agent.AddedKey{PrivateKey: key}); err != nil {
			t.Fatal(err)
		}
	}
	keys, err := ring.List()
	if err != nil {
		t.Fatal(err)
	}
	selected := ssh.FingerprintSHA256(keys[19])
	got, err := selectAgentKeys(keys, selected)
	if err != nil || len(got) != 1 || ssh.FingerprintSHA256(got[0]) != selected {
		t.Fatalf("selection: %v %v", got, err)
	}
	if _, err := selectAgentKeys(keys, "SHA256:"+strings.Repeat("A", 43)); err == nil {
		t.Fatal("missing selected identity must fail")
	}
	if _, err := AgentAuth("not-a-fingerprint"); err == nil {
		t.Fatal("invalid selection accepted")
	}
	if _, err := AgentAuth(selected, selected); err == nil {
		t.Fatal("ambiguous selection accepted")
	}
}
