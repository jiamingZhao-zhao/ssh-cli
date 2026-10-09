package policyhmac

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/config"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/secrets"
)

func TestSignAndTamper(t *testing.T) {
	dir := t.TempDir()
	Install()
	t.Cleanup(func() {
		config.VerifyPolicy = func(string, *config.Config) error { return nil }
		config.SignOnSave = func(string, *config.Config) error { return nil }
	})
	cfg := &config.Config{
		Version: 1,
		Policies: map[string]*config.Policy{
			"tight": {Deny: []string{"wget"}},
		},
	}
	if err := config.Save(dir, cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(MacPath(dir)); !os.IsNotExist(err) {
		t.Fatal("signed without a master key")
	}
	if _, err := secrets.MasterMaterial(dir, true); err != nil {
		t.Fatal(err)
	}
	if err := config.Save(dir, cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := config.Load(dir); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, config.FileName)
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(string(body), "wget", "curl", 1)
	if err := os.WriteFile(path, []byte(tampered), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := config.Load(dir); err == nil || !strings.Contains(err.Error(), "policy hmac") {
		t.Fatalf("tamper err %v", err)
	}
	if err := Remove(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := config.Load(dir); err != nil {
		t.Fatal(err)
	}
}
