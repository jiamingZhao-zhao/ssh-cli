package confirmgate

import (
	"errors"
	"strings"
	"testing"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/audit"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/config"
)

func hostDoc(alias, addr, ref, ident, envName string) *config.Config {
	h := &config.Host{Host: addr, User: "ops", Auth: "password", PasswordRef: ref, Identity: ident}
	return &config.Config{Version: 1, Groups: map[string]*config.Group{
		"app": {Env: envName, Hosts: map[string]*config.Host{alias: h}},
	}}
}

func TestRenameReusesCredentialAtNewAddress(t *testing.T) {
	prev := hostDoc("main", "192.0.2.10", "app.main", "", "prod")
	next := &config.Config{Version: 1, Groups: map[string]*config.Group{
		"lab": {Env: "dev", Hosts: map[string]*config.Host{
			"renamed": {Host: "203.0.113.5", User: "ops", Auth: "password", PasswordRef: "app.main"},
		}},
	}}
	needs, err := ConfigNeeds(prev, next)
	if err != nil {
		t.Fatal(err)
	}
	if Phrase(needs) != "prod" {
		t.Fatalf("phrase %q needs %+v", Phrase(needs), needs)
	}
	if !strings.Contains(Reasons(needs), "reuses passwordRef") {
		t.Fatalf("reason %s", Reasons(needs))
	}
}

func TestSameImportNewHostIsNotAMove(t *testing.T) {
	prev := hostDoc("main", "192.0.2.10", "app.main", "", "prod")
	next := &config.Config{Version: 1, Groups: map[string]*config.Group{
		"app": {Env: "prod", Hosts: map[string]*config.Host{
			"main":  {Host: "192.0.2.10", User: "ops", Auth: "password", PasswordRef: "app.main"},
			"other": {Host: "198.51.100.8", User: "ops", Auth: "key", Identity: "~/.ssh/id_other"},
		}},
	}}
	if err := prev.Normalize(); err != nil {
		t.Fatal(err)
	}
	if err := next.Normalize(); err != nil {
		t.Fatal(err)
	}
	needs, err := ConfigNeeds(prev, next)
	if err != nil {
		t.Fatal(err)
	}
	if len(needs) != 0 {
		t.Fatalf("ordinary add needs %+v", needs)
	}
}

func TestSecondAliasAtSameAddressIsNotAMove(t *testing.T) {
	prev := hostDoc("main", "192.0.2.10", "app.main", "", "prod")
	next := &config.Config{Version: 1, Groups: map[string]*config.Group{
		"app": {Env: "prod", Hosts: map[string]*config.Host{
			"main":  {Host: "192.0.2.10", User: "ops", Auth: "password", PasswordRef: "app.main"},
			"alias": {Host: "192.0.2.10", User: "ops", Auth: "password", PasswordRef: "app.main"},
		}},
	}}
	if err := prev.Normalize(); err != nil {
		t.Fatal(err)
	}
	if err := next.Normalize(); err != nil {
		t.Fatal(err)
	}
	needs, err := ConfigNeeds(prev, next)
	if err != nil {
		t.Fatal(err)
	}
	if len(needs) != 0 {
		t.Fatalf("same address needs %+v", needs)
	}
}

func TestTwoStepImportReusesBinding(t *testing.T) {
	dir := t.TempDir()
	prev := hostDoc("main", "192.0.2.10", "app.main", "", "prod")
	deleted := &config.Config{Version: 1, Groups: map[string]*config.Group{
		"app": {Env: "prod"},
	}}
	needs, err := ImportNeeds(dir, prev, deleted)
	if err != nil {
		t.Fatal(err)
	}
	if len(needs) != 0 {
		t.Fatalf("delete needs %+v", needs)
	}
	RecordImport(dir, "test", nil, DiffSummary(prev, deleted))
	var sawRemove bool
	if err := audit.List(dir, audit.Filter{}, func(rec audit.Record) error {
		if rec.Op == audit.OpConfigChange && strings.Contains(rec.Reason, "removed main") {
			sawRemove = true
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !sawRemove {
		t.Fatal("delete import was not audited")
	}
	reborn := hostDoc("main", "203.0.113.5", "app.main", "", "prod")
	needs, err = ImportNeeds(dir, deleted, reborn)
	if err != nil {
		t.Fatal(err)
	}
	if Phrase(needs) != "main" {
		t.Fatalf("recreate phrase %q needs %+v", Phrase(needs), needs)
	}
	err = Require(dir, "test", "", needs)
	var ce *Error
	if !errors.As(err, &ce) || ce.Phrase != "main" {
		t.Fatalf("confirm %v", err)
	}
	same := hostDoc("main", "192.0.2.10", "app.main", "", "prod")
	needs, err = ImportNeeds(dir, deleted, same)
	if err != nil {
		t.Fatal(err)
	}
	if len(needs) != 0 {
		t.Fatalf("same address recreate needs %+v", needs)
	}
}
