package policyhmac

import (
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/config"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/secrets"
)

type missRing struct{}

func (missRing) Get(string, string) (string, error) { return "", secrets.ErrNotFound }
func (missRing) Set(string, string, string) error   { return errors.New("no keyring") }

func isolateKey(t *testing.T) {
	t.Helper()
	restore := secrets.SetTestKeyring(missRing{})
	t.Cleanup(restore)
	t.Setenv("SSH_CLI_MASTER_KEY", "")
}

func TestSignAndTamper(t *testing.T) {
	dir := t.TempDir()
	isolateKey(t)
	prevVerify, prevSign, prevBefore := config.VerifyPolicy, config.SignOnSave, config.BeforeSave
	Install()
	t.Cleanup(func() {
		config.VerifyPolicy = prevVerify
		config.SignOnSave = prevSign
		config.BeforeSave = prevBefore
	})
	cfg := &config.Config{
		Version: 1,
		Policies: map[string]*config.Policy{
			"tight": {Deny: []string{"wget"}},
		},
		Groups: map[string]*config.Group{
			"app": {Env: "prod", Hosts: map[string]*config.Host{
				"box": {Host: "192.0.2.10", User: "ops", Auth: "key"},
			}},
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
	if !cfg.PolicySigned {
		t.Fatal("signed config did not record policySigned")
	}
	if _, err := config.Load(dir); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, config.FileName)
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(strings.Replace(string(body), "192.0.2.10", "203.0.113.5", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := config.Load(dir); err == nil || !strings.Contains(err.Error(), "policy hmac") {
		t.Fatalf("address tamper err %v", err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(MacPath(dir)); err != nil {
		t.Fatal(err)
	}
	if _, err := config.Load(dir); !errors.Is(err, ErrMissingMac) {
		t.Fatalf("missing sidecar err %v", err)
	}
	if err := Remove(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := config.Load(dir); err != nil {
		t.Fatal(err)
	}
}

func TestV1MacNeedsResign(t *testing.T) {
	dir := t.TempDir()
	isolateKey(t)
	prevVerify, prevSign, prevBefore := config.VerifyPolicy, config.SignOnSave, config.BeforeSave
	Install()
	t.Cleanup(func() {
		config.VerifyPolicy = prevVerify
		config.SignOnSave = prevSign
		config.BeforeSave = prevBefore
	})
	cfg := &config.Config{
		Version: 1,
		Groups: map[string]*config.Group{
			"app": {Env: "prod", Hosts: map[string]*config.Host{
				"box": {Host: "192.0.2.10", User: "ops"},
			}},
		},
	}
	if err := config.Save(dir, cfg); err != nil {
		t.Fatal(err)
	}
	key, err := secrets.MasterMaterial(dir, true)
	if err != nil {
		t.Fatal(err)
	}
	sum := checksum(domainV1, key, canonicalV1(cfg))
	if err := os.WriteFile(MacPath(dir), []byte("v1\n"+hex.EncodeToString(sum)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := config.Load(dir); !errors.Is(err, ErrNeedsResign) {
		t.Fatalf("v1 err %v", err)
	}
	fresh, err := config.ReadUnverified(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := SignNew(dir, fresh); err != nil {
		t.Fatal(err)
	}
	if err := config.Update(dir, func(cur *config.Config) error {
		cur.PolicySigned = true
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	loaded, err := config.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.PolicySigned {
		t.Fatal("resign did not set policySigned")
	}
}
