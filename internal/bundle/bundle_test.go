package bundle

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/audit"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/config"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/confirmgate"
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

func TestBuiltinNoDataOutflowSurvivesMigrate(t *testing.T) {
	cfg := &config.Config{Version: 1}
	if err := cfg.Normalize(); err != nil {
		t.Fatal(err)
	}
	cfg.Envs["prod"].NoDataOutflow = true
	data, err := Export(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "noDataOutflow: true") {
		t.Fatalf("export dropped noDataOutflow\n%s", data)
	}
	fresh := &config.Config{Version: 1}
	if err := Apply(fresh, data); err != nil {
		t.Fatal(err)
	}
	if err := fresh.Normalize(); err != nil {
		t.Fatal(err)
	}
	prod := fresh.Envs["prod"]
	if prod == nil || !prod.NoDataOutflow || prod.MaxMode != config.ModeReadonly || prod.Label != "生产" {
		t.Fatalf("migrated prod %+v", prod)
	}
}

func TestImportRequiresConfirmBeforeCommit(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{Version: 1, Groups: map[string]*config.Group{
		"app": {Env: "prod", Hosts: map[string]*config.Host{
			"box": {Host: "192.0.2.10", Port: 22, User: "ops", Auth: "key", Identity: "~/.ssh/id_ed25519"},
		}},
	}}
	if err := cfg.Normalize(); err != nil {
		t.Fatal(err)
	}
	if err := config.Save(dir, cfg); err != nil {
		t.Fatal(err)
	}
	data, err := Export(cfg)
	if err != nil {
		t.Fatal(err)
	}
	weaker := strings.Replace(string(data), "env: prod", "env: dev", 1)
	loaded, err := config.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	_, err = ApplyConfirmed(dir, "test", "", loaded, []byte(weaker))
	var ce *confirmgate.Error
	if !errors.As(err, &ce) || ce.Phrase != "prod" {
		t.Fatalf("prod leave: %v", err)
	}
	kept, err := config.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if kept.Groups["app"].Env != "prod" {
		t.Fatalf("import committed without confirmation: %s", kept.Groups["app"].Env)
	}
	var denied bool
	if err := audit.List(dir, audit.Filter{}, func(rec audit.Record) error {
		if rec.Op == audit.OpConfigChange && rec.Status == audit.StatusDenied && strings.Contains(rec.Reason, "prod") {
			denied = true
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !denied {
		t.Fatal("missing concrete denial audit")
	}
	if err := config.Update(dir, func(cur *config.Config) error {
		_, err := ApplyConfirmed(dir, "test", "prod", cur, []byte(weaker))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	confirmgate.RecordImport(dir, "test", []confirmgate.Need{confirmgate.ProdLeaveNeed("app", "dev")})
	after, err := config.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if after.Groups["app"].Env != "dev" {
		t.Fatalf("confirmed import env %s", after.Groups["app"].Env)
	}

	base, err := config.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	current, err := Export(base)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(current), "port: 22") {
		t.Fatalf("expected explicit port\n%s", current)
	}
	withPort := strings.Replace(string(current), "port: 22", "port: 2222", 1)
	_, err = ApplyConfirmed(dir, "test", "", base, []byte(withPort))
	if !errors.As(err, &ce) || ce.Phrase != "box" {
		t.Fatalf("port change confirm: %v", err)
	}
	still, err := config.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if still.Groups["app"].Hosts["box"].PortOrDefault() == 2222 {
		t.Fatal("port changed without confirmation")
	}
}
