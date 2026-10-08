package catalog

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/config"
)

const samplePassword = "s3cret-import"

func TestImportEncryptsPasswordAndDryRunWritesNothing(t *testing.T) {
	dir := t.TempDir()
	body := []byte(`
version: 1
default: main
envs:
  prod:
    label: 生产
    color: red
    maxMode: readonly
    defaultPolicy: readonly
policies:
  tight:
    mode: readonly
    allow: ["df", "uptime"]
    deny: ["shutdown"]
groups:
  app-prod:
    env: prod
    policy: tight
servers:
  main:
    host: 192.0.2.10
    port: 22
    user: viewer
    password: "` + samplePassword + `"
    group: app-prod
    tags: [app, web]
`)
	dry, err := Import(dir, body, ImportOptions{DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if dry.PlaintextPasswords != 1 {
		t.Fatalf("passwords %d", dry.PlaintextPasswords)
	}
	if _, err := os.Stat(filepath.Join(dir, "hosts.yaml")); !os.IsNotExist(err) {
		t.Fatalf("dry-run wrote hosts.yaml: %v", err)
	}
	blob := resultText(dry)
	if strings.Contains(blob, samplePassword) {
		t.Fatal("dry-run result contained the password")
	}
	got, err := Import(dir, body, ImportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(resultText(got), samplePassword) {
		t.Fatal("import result contained the password")
	}
	yamlBytes, err := os.ReadFile(filepath.Join(dir, "hosts.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	secBytes, err := os.ReadFile(filepath.Join(dir, "secrets.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(yamlBytes), samplePassword) || strings.Contains(string(secBytes), samplePassword) {
		t.Fatal("password stored in plaintext")
	}
	if !strings.Contains(string(yamlBytes), "passwordRef:") || !strings.Contains(string(yamlBytes), "tight") {
		t.Fatalf("yaml:\n%s", yamlBytes)
	}
	cfg, err := config.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Default != "main" {
		t.Fatalf("default %q", cfg.Default)
	}
	host, ok := cfg.Find("main")
	if !ok || host.Host.User != "viewer" || host.EnvName != "prod" || len(host.Host.Tags) != 2 {
		t.Fatalf("host %+v", host)
	}
	_, err = Import(dir, body, ImportOptions{})
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("second import: %v", err)
	}
	if _, err := Import(dir, body, ImportOptions{SkipExisting: true}); err != nil {
		t.Fatal(err)
	}
}

func TestImportListAndNestedHosts(t *testing.T) {
	dir := t.TempDir()
	list := []byte(`[{"alias":"main","host":"192.0.2.10","username":"root","password":"` + samplePassword + `","group":"app","env":"dev","tag":"web"}]`)
	if _, err := Import(dir, list, ImportOptions{MaxMode: "admin"}); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	h, ok := cfg.Find("main")
	if !ok || h.Group != "app" || h.EnvName != "dev" || h.Env.MaxMode != config.ModeAdmin {
		t.Fatalf("%+v env %+v", h, h.Env)
	}
	nested := []byte(`
envs:
  dev: {maxMode: admin, label: 开发}
groups:
  sandbox:
    env: dev
    hosts:
      box:
        host: 192.0.2.30
        user: root
        identity: ~/.ssh/id_ed25519
`)
	dir2 := t.TempDir()
	if _, err := Import(dir2, nested, ImportOptions{}); err != nil {
		t.Fatal(err)
	}
	cfg, err = config.Load(dir2)
	if err != nil {
		t.Fatal(err)
	}
	box, ok := cfg.Find("box")
	if !ok || box.Host.Auth != "key" || box.Host.Identity != "~/.ssh/id_ed25519" {
		t.Fatalf("%+v", box.Host)
	}
	raw, _ := os.ReadFile(filepath.Join(dir2, "secrets.json"))
	if strings.Contains(string(raw), "PRIVATE") {
		t.Fatal("identity material stored")
	}
}

func TestImportRejectsDroppedSecrets(t *testing.T) {
	_, err := ParseInventory([]byte("servers:\n  main:\n    host: 192.0.2.10\n    user: root\n    secret: nope\n"))
	if err == nil || !strings.Contains(err.Error(), "secret") {
		t.Fatal(err)
	}
	_, err = ParseInventory([]byte("groups:\n  app:\n    env: dev\n    deny: [rm]\n"))
	if err == nil || !strings.Contains(err.Error(), "named policy") {
		t.Fatal(err)
	}
}

func resultText(r ImportResult) string {
	var b strings.Builder
	for _, c := range r.Changes {
		b.WriteString(c.Action)
		b.WriteByte(' ')
		b.WriteString(c.Name)
		b.WriteByte(' ')
		b.WriteString(c.Detail)
		b.WriteByte('\n')
	}
	return b.String()
}
