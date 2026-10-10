package history

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/config"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/guard"
)

func TestParseHistFileStaticAndDynamic(t *testing.T) {
	text := "export HISTFILE=~/.my_history\nHISTFILE=\"$HOME/.secret_history\"\nset -gx HISTFILE ~/.from_fish\n"
	// The fish assignment is last and static, so it wins.
	got, note := ParseHistFile(text)
	if got != "~/.from_fish" || note != "" {
		t.Fatalf("got %q note %q", got, note)
	}
	onlyDynamic, note := ParseHistFile("HISTFILE=$HOME/.x\n")
	if onlyDynamic != "" || note == "" {
		t.Fatalf("dynamic path=%q note=%q", onlyDynamic, note)
	}
	if _, ok := SafeHistPath("~/../etc/passwd"); ok {
		t.Fatal("parent segment accepted")
	}
	if _, ok := SafeHistPath("relative_hist"); ok {
		t.Fatal("relative path accepted")
	}
}

func TestNormalizeAndScrub(t *testing.T) {
	bash := "#1600000000\nls\necho password=s3cret\ncurl --token s3cret https://user:pw@example.test/x\n"
	lines := Normalize("~/.bash_history", bash)
	joined := strings.Join(lines, "\n")
	if strings.Contains(joined, "#1600000000") || strings.Contains(joined, "s3cret") || strings.Contains(joined, "pw@") {
		t.Fatalf("bash normalize leaked %q", joined)
	}
	if !strings.Contains(joined, "password=[redacted]") || !strings.Contains(joined, "--token [redacted]") || !strings.Contains(joined, "https://user:[redacted]@") {
		t.Fatalf("bash scrub %q", joined)
	}
	zsh := Normalize("~/.zsh_history", ": 1600000000:0;git status\necho ok\n")
	if len(zsh) != 2 || zsh[0] != "git status" || zsh[1] != "echo ok" {
		t.Fatalf("zsh %#v", zsh)
	}
	fish := Normalize("~/.local/share/fish/fish_history", "- cmd: echo hi\n  when: 1\n- cmd: ls\n")
	if strings.Join(fish, ",") != "echo hi,ls" {
		t.Fatalf("fish %#v", fish)
	}
}

func TestCap(t *testing.T) {
	lines := []string{"one", "two", "three", "four"}
	got, trunc := Cap(lines, 2, 1024)
	if !trunc || strings.Join(got, ",") != "three,four" {
		t.Fatalf("cap %#v %v", got, trunc)
	}
	got, trunc = Cap([]string{strings.Repeat("a", 100)}, 10, 16)
	if !trunc || len(got) != 1 || len(got[0]) > 16 {
		t.Fatalf("byte cap %#v", got)
	}
}

func TestCollectHappyMissingAndUnreadable(t *testing.T) {
	files := map[string]struct {
		code int
		out  string
		err  string
	}{
		"~/.bashrc":                        {code: 1, err: "No such file"},
		"~/.bash_history":                  {code: 0, out: "echo password=s3cret\nls\n"},
		"~/.zsh_history":                   {code: 1, err: "No such file"},
		"~/.local/share/fish/fish_history": {code: 1, err: "No such file"},
	}
	run := func(_ context.Context, command string) (string, string, int, error) {
		if strings.HasPrefix(command, "cat --") {
			return "HISTFILE=~/.bash_history\n", "", 0, nil
		}
		for path, body := range files {
			if strings.HasSuffix(command, " "+path) || strings.HasSuffix(command, " -- "+path) {
				return body.out, body.err, body.code, nil
			}
		}
		return "", "No such file", 1, nil
	}
	res, err := Collect(context.Background(), run, nil, Options{Lines: 10})
	if err != nil || !res.Found || res.Path != "~/.bash_history" || res.Shell != "bash" {
		t.Fatalf("happy %#v %v", res, err)
	}
	if strings.Contains(strings.Join(res.Lines, "\n"), "s3cret") || res.Lines[len(res.Lines)-1] != "ls" {
		t.Fatalf("lines %#v", res.Lines)
	}
	for _, cmd := range res.Commands {
		if strings.Contains(cmd, ">") || strings.Contains(cmd, "history ") || strings.HasPrefix(cmd, "rm") {
			t.Fatalf("not read-only: %s", cmd)
		}
	}

	missing := func(_ context.Context, command string) (string, string, int, error) {
		if strings.HasPrefix(command, "cat --") {
			return "", "No such file", 1, nil
		}
		return "", "No such file or directory", 1, nil
	}
	res, err = Collect(context.Background(), missing, nil, Options{})
	if err != nil || res.Found || res.Status != "empty" || res.Error == "" {
		t.Fatalf("missing %#v %v", res, err)
	}

	unread := func(_ context.Context, command string) (string, string, int, error) {
		if strings.HasPrefix(command, "cat --") {
			return "", "", 1, nil
		}
		if strings.Contains(command, ".bash_history") {
			return "", "tail: cannot open: Permission denied", 1, nil
		}
		return "", "No such file", 1, nil
	}
	res, err = Collect(context.Background(), unread, nil, Options{})
	if err != nil || res.Found || res.Status != "unreadable" || !strings.Contains(res.Error, "Permission denied") {
		t.Fatalf("unreadable %#v %v", res, err)
	}

	boom := func(context.Context, string) (string, string, int, error) {
		return "", "", 0, errors.New("connection reset")
	}
	if _, err := Collect(context.Background(), boom, nil, Options{}); err == nil {
		t.Fatal("transport error swallowed")
	}
}

func TestPolicySkipsProbeButRequiresTail(t *testing.T) {
	cfg := &config.Config{
		Envs: map[string]*config.Env{
			"dev": {MaxMode: config.ModeAdmin, DefaultPolicy: "standard"},
		},
		Policies: map[string]*config.Policy{
			"tails": {Mode: config.ModeReadonly, Allow: list("tail")},
		},
		Groups: map[string]*config.Group{
			"g": {Env: "dev", Policy: "tails", Hosts: map[string]*config.Host{
				"box": {Host: "127.0.0.1", User: "u"},
			}},
		},
	}
	h, ok := cfg.Find("box")
	if !ok {
		t.Fatal("missing host")
	}
	eff, err := guard.Resolve(cfg, h, false)
	if err != nil {
		t.Fatal(err)
	}
	dec := PolicyDecision(eff, 10)
	if !dec.Allowed {
		t.Fatalf("tail-only policy denied history: %#v", dec)
	}
	_ = eff
	cfg.Policies["tails"].Allow = list("uptime")
	eff, err = guard.Resolve(cfg, h, false)
	if err != nil {
		t.Fatal(err)
	}
	dec = PolicyDecision(eff, 10)
	if dec.Allowed {
		t.Fatal("uptime-only policy allowed history")
	}
}

func list(items ...string) *[]string {
	cp := append([]string(nil), items...)
	return &cp
}

func TestPlannedCommandsAreReadOnly(t *testing.T) {
	cmds, err := PlannedCommands(0)
	if err != nil || len(cmds) != 4 {
		t.Fatalf("planned %#v %v", cmds, err)
	}
	if !strings.HasPrefix(cmds[0], "cat -- ") {
		t.Fatalf("probe %s", cmds[0])
	}
	for _, cmd := range cmds[1:] {
		if !strings.HasPrefix(cmd, "tail -n ") || strings.ContainsAny(cmd, "><|&;`$") {
			t.Fatalf("tail %s", cmd)
		}
	}
	if _, err := ClampLines(MaxLines + 1); err == nil {
		t.Fatal("max lines accepted")
	}
}
