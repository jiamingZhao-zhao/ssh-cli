package catalog

import (
	"strings"
	"testing"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/config"
)

func TestGroupDisplayLabel(t *testing.T) {
	dir := t.TempDir()
	if err := AddGroup(dir, GroupDraft{
		Name:  "hunan-test",
		Env:   "test",
		Label: "湖南组测试主机组",
	}); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	g := cfg.Groups["hunan-test"]
	if g == nil || g.Label != "湖南组测试主机组" || g.Env != "test" {
		t.Fatalf("group %+v", g)
	}
	if cfg.Envs["test"].Label != "测试" || cfg.Envs["test"].MaxMode != config.ModeStandard {
		t.Fatalf("builtin env changed: %+v", cfg.Envs["test"])
	}

	if err := EditGroup(dir, GroupDraft{Name: "hunan-test", HasPolicy: true, Policy: "standard"}); err != nil {
		t.Fatal(err)
	}
	cfg, err = config.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Groups["hunan-test"].Label != "湖南组测试主机组" || cfg.Groups["hunan-test"].Policy != "standard" {
		t.Fatalf("policy edit changed label: %+v", cfg.Groups["hunan-test"])
	}

	if err := EditGroup(dir, GroupDraft{Name: "hunan-test", HasLabel: true, Label: "  "}); err != nil {
		t.Fatal(err)
	}
	cfg, err = config.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Groups["hunan-test"].Label != "" {
		t.Fatalf("cleared label = %q", cfg.Groups["hunan-test"].Label)
	}

	err = AddGroup(dir, GroupDraft{Name: "bad-label", Env: "test", Label: "第一行\n第二行"})
	if err == nil || !strings.Contains(err.Error(), "single line") {
		t.Fatalf("newline label: %v", err)
	}
}
