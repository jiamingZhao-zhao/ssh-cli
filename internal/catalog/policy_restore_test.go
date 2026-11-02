package catalog

import (
	"errors"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/config"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/confirmgate"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/guard"
	"os"
	"path/filepath"
	"testing"
)

func TestBuiltinNoopKeepsInheritance(t *testing.T) {
	dir := t.TempDir()
	if err := config.Save(dir, &config.Config{Version: 1}); err != nil {
		t.Fatal(err)
	}
	p, _ := guard.BuiltinPolicy("readonly")
	allow := append([]string{}, (*p.Allow)...)
	for i, j := 0, len(allow)-1; i < j; i, j = i+1, j-1 {
		allow[i], allow[j] = allow[j], allow[i]
	}
	for _, draft := range []PolicyDraft{{Name: "readonly", HasMode: true, Mode: "readonly"}, {Name: "readonly", HasAllow: true, Allow: allow}} {
		if err := EditPolicy(dir, draft); err != nil {
			t.Fatal(err)
		}
		cfg, err := config.Load(dir)
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Policies["readonly"] != nil {
			t.Fatal("unchanged builtin was frozen")
		}
	}
	// An explicitly stored equal override must remain pinned until restored.
	if err := config.Update(dir, func(c *config.Config) error { c.Policies = map[string]*config.Policy{"readonly": p}; return nil }); err != nil {
		t.Fatal(err)
	}
	if err := EditPolicy(dir, PolicyDraft{Name: "readonly", Mode: "readonly", HasMode: true}); err != nil {
		t.Fatal(err)
	}
	cfg, _ := config.Load(dir)
	if cfg.Policies["readonly"] == nil {
		t.Fatal("existing override migrated automatically")
	}
}

func TestBuiltinRestoreChecksWholePolicy(t *testing.T) {
	for _, field := range []string{"allow", "deny", "confirm", "protectedPaths", "capabilities"} {
		t.Run(field, func(t *testing.T) {
			dir := t.TempDir()
			p, _ := guard.BuiltinPolicy("readonly")
			switch field {
			case "allow":
				v := []string{"ls"}
				p.Allow = &v
			case "deny":
				p.Deny = []string{"docker logs"}
			case "confirm":
				p.Confirm = []string{"docker logs"}
			case "protectedPaths":
				p.ProtectedPaths = []string{"/srv/private"}
			case "capabilities":
				b := false
				p.Capabilities.Download = &b
			}
			if err := config.Save(dir, &config.Config{Version: 1, Policies: map[string]*config.Policy{"readonly": p}}); err != nil {
				t.Fatal(err)
			}
			before, _ := os.ReadFile(filepath.Join(dir, config.FileName))
			for _, phrase := range []string{"", "wrong"} {
				err := RemovePolicyConfirmed(dir, "readonly", phrase, "fixture")
				var ce *confirmgate.Error
				if !errors.As(err, &ce) {
					t.Fatalf("widening did not request confirmation: %v", err)
				}
			}
			after, _ := os.ReadFile(filepath.Join(dir, config.FileName))
			if string(before) != string(after) {
				t.Fatal("denied restore changed config")
			}
			cfg, _ := config.Load(dir)
			v := ListPolicies(cfg)
			var diff *BuiltinDifference
			for _, p := range v {
				if p.Name == "readonly" {
					diff = p.BuiltinDifference
				}
			}
			if diff == nil || !diff.RestoreWidens || len(diff.ChangedFields) == 0 {
				t.Fatalf("missing preview: %+v", diff)
			}
			if err := RemovePolicyConfirmed(dir, "readonly", "readonly", "fixture"); err != nil {
				t.Fatal(err)
			}
			cfg, _ = config.Load(dir)
			if cfg.Policies["readonly"] != nil {
				t.Fatal("override retained after confirmed restore")
			}
			// Audit distinguishes denied attempts and the committed restore.
			files, _ := filepath.Glob(filepath.Join(dir, "audit", "*.jsonl"))
			if len(files) == 0 {
				t.Fatal("missing confirmation audit")
			}
		})
	}
}

func TestBuiltinRestoreNarrowingNeedsNoPhrase(t *testing.T) {
	dir := t.TempDir()
	p, _ := guard.BuiltinPolicy("readonly")
	p.Mode = config.ModeAdmin
	if err := config.Save(dir, &config.Config{Version: 1, Policies: map[string]*config.Policy{"readonly": p}}); err != nil {
		t.Fatal(err)
	}
	if err := RemovePolicy(dir, "readonly"); err != nil {
		t.Fatal(err)
	}
}
