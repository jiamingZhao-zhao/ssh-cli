package bundle

import (
	"bytes"
	"strings"
	"testing"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/config"
)

func TestExportImportRoundTripWithoutSecrets(t *testing.T) {
	cfg := &config.Config{Version: 1, Default: "box"}
	cfg.Groups = map[string]*config.Group{
		"app": {
			Env: "dev", Label: "应用",
			Hosts: map[string]*config.Host{
				"box": {Host: "192.0.2.10", User: "ops", PasswordRef: "box", Identity: "~/.ssh/id_ed25519"},
			},
		},
	}
	cfg.Policies = map[string]*config.Policy{"tight": {Mode: config.ModeReadonly, Deny: []string{"wget"}}}
	data, err := Export(cfg)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if strings.Contains(text, "password:") || strings.Contains(strings.ToLower(text), "masterkey") {
		t.Fatalf("secret leaked\n%s", text)
	}
	if !strings.Contains(text, "passwordRef:") || !strings.Contains(text, "id_ed25519") {
		t.Fatalf("missing key ref\n%s", text)
	}
	next := &config.Config{Version: 1}
	if err := Apply(next, data); err != nil {
		t.Fatal(err)
	}
	if next.Default != "box" || next.Groups["app"].Hosts["box"].PasswordRef != "box" {
		t.Fatalf("round trip %+v", next.Groups["app"].Hosts["box"])
	}
	if next.Groups["app"].Hosts["box"].Host != "192.0.2.10" {
		t.Fatal("address dropped")
	}
	bad := bytes.ReplaceAll(data, []byte("passwordRef:"), []byte("password:"))
	if err := Apply(&config.Config{Version: 1}, bad); err == nil {
		t.Fatal("plaintext password accepted")
	}
}
