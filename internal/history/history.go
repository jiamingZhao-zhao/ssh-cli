// Package history reads a remote user's shell history on a best-effort basis.
// It only builds read commands (cat of rc files, tail of history files). It
// never writes, truncates, or rewrites a history file.
package history

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/audit"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/guard"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/remote"
)

const (
	// DefaultLines is the number of commands returned when the caller does not ask.
	DefaultLines = 100
	// MaxLines is the upper bound for one read.
	MaxLines = 500
	// MaxBytes caps the returned command text.
	MaxBytes = 64 << 10
	// maxProbeBytes caps rc text used only to discover HISTFILE.
	maxProbeBytes = 256 << 10
	maxRawLines   = 1500
)

// ExecFunc runs one remote command. A non-zero code is not an error.
// A non-nil error is a transport failure and aborts the read.
type ExecFunc func(ctx context.Context, command string) (stdout, stderr string, code int, err error)

// GateFunc reports whether command may run. A non-nil error skips that command.
// A nil gate allows every command. The probe is optional; tail reads are not.
type GateFunc func(command string) error

// Options selects how much history to keep.
type Options struct {
	Lines int
}

// Result is a graceful outcome. Lines is empty when nothing was readable.
// Status is ok, empty, unreadable, or denied. Transport failures are returned
// as the error from Collect, not as Status.
type Result struct {
	Found     bool     `json:"found"`
	Status    string   `json:"status"`
	Path      string   `json:"path,omitempty"`
	Shell     string   `json:"shell,omitempty"`
	Lines     []string `json:"lines"`
	Truncated bool     `json:"truncated"`
	Notes     []string `json:"notes,omitempty"`
	Error     string   `json:"error,omitempty"`
	Commands  []string `json:"-"`
}

// ClampLines bounds n to 1..MaxLines. Zero selects DefaultLines.
func ClampLines(n int) (int, error) {
	if n == 0 {
		return DefaultLines, nil
	}
	if n < 0 || n > MaxLines {
		return 0, fmt.Errorf("lines must be from 1 to %d", MaxLines)
	}
	return n, nil
}

// DefaultPaths are the history files tried when HISTFILE is absent or unusable.
func DefaultPaths() []string {
	return []string{
		"~/.bash_history",
		"~/.zsh_history",
		"~/.local/share/fish/fish_history",
	}
}

// RCPaths are read-only files that may assign HISTFILE. Missing files are ignored.
func RCPaths() []string {
	return []string{
		"~/.bashrc",
		"~/.bash_profile",
		"~/.profile",
		"~/.zshrc",
		"~/.zprofile",
		"~/.zshenv",
		"~/.config/fish/config.fish",
	}
}

// ProbeCommand cats rc files so the caller can look for a static HISTFILE.
func ProbeCommand() (string, error) {
	paths := RCPaths()
	for _, p := range paths {
		if _, err := remote.ValidateRemotePath(p); err != nil {
			return "", err
		}
	}
	return "cat -- " + strings.Join(paths, " "), nil
}

// TailCommand reads the last n raw lines of path. path must be a static literal.
func TailCommand(path string, n int) (string, error) {
	if n < 1 {
		n = DefaultLines
	}
	if n > maxRawLines {
		n = maxRawLines
	}
	clean, err := remote.ValidateRemotePath(path)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("tail -n %d -- %s", n, clean), nil
}

// PlannedCommands is the probe plus a tail of each default path.
// Index 0 is the probe. The rest are history reads.
func PlannedCommands(lines int) ([]string, error) {
	n, err := ClampLines(lines)
	if err != nil {
		return nil, err
	}
	raw := rawWindow(n)
	probe, err := ProbeCommand()
	if err != nil {
		return nil, err
	}
	out := []string{probe}
	for _, p := range DefaultPaths() {
		cmd, err := TailCommand(p, raw)
		if err != nil {
			return nil, err
		}
		out = append(out, cmd)
	}
	return out, nil
}

// PolicyDecision allows the read when every default tail is allowed.
// The rc probe is optional: a policy that permits tail but not cat can still
// read the default history files.
func PolicyDecision(eff guard.Effective, lines int) guard.Decision {
	cmds, err := PlannedCommands(lines)
	if err != nil {
		return guard.Decision{Mode: string(eff.Mode), Findings: []guard.Finding{{
			Layer: "usage", Kind: "deny", Detail: err.Error(),
		}}}
	}
	parts := make([]guard.Decision, 0, len(cmds))
	for _, cmd := range cmds[1:] {
		parts = append(parts, guard.Decide(eff, cmd))
	}
	return guard.Merge(parts...)
}

// Collect probes HISTFILE, then tails candidates until one yields commands.
func Collect(ctx context.Context, exec ExecFunc, gate GateFunc, opt Options) (Result, error) {
	n, err := ClampLines(opt.Lines)
	if err != nil {
		return Result{}, err
	}
	res := Result{Status: "empty", Lines: []string{}}
	if exec == nil {
		return res, fmt.Errorf("history exec is required")
	}
	probe, err := ProbeCommand()
	if err != nil {
		return res, err
	}
	histfile := ""
	if allow(gate, probe) {
		stdout, _, _, runErr := exec(ctx, probe)
		if runErr != nil {
			return res, runErr
		}
		res.Commands = append(res.Commands, probe)
		found, note := ParseHistFile(clipBytes(stdout, maxProbeBytes))
		if note != "" {
			res.Notes = append(res.Notes, note)
		}
		histfile = found
	} else {
		res.Notes = append(res.Notes, "HISTFILE probe skipped by policy; using default paths")
	}
	raw := rawWindow(n)
	var sawFile bool
	var emptyPath string
	var sawDenied bool
	var unreadableNote string
	for _, p := range Candidates(histfile) {
		cmd, cmdErr := TailCommand(p, raw)
		if cmdErr != nil {
			res.Notes = append(res.Notes, p+": "+cmdErr.Error())
			continue
		}
		if !allow(gate, cmd) {
			sawDenied = true
			res.Notes = append(res.Notes, p+": denied by policy")
			continue
		}
		stdout, stderr, code, runErr := exec(ctx, cmd)
		if runErr != nil {
			return res, runErr
		}
		res.Commands = append(res.Commands, cmd)
		if code == 0 {
			sawFile = true
			if emptyPath == "" {
				emptyPath = p
			}
			lines := scrubLines(Normalize(p, stdout))
			if len(lines) == 0 {
				res.Notes = append(res.Notes, p+": empty")
				continue
			}
			capped, trunc := Cap(lines, n, MaxBytes)
			res.Found = true
			res.Status = "ok"
			res.Path = p
			res.Shell = ShellKind(p)
			res.Lines = capped
			res.Truncated = trunc
			return res, nil
		}
		note := oneLine(stderr)
		if note == "" {
			note = fmt.Sprintf("exit %d", code)
		}
		if unreadableText(note) {
			unreadableNote = p + ": " + note
			res.Notes = append(res.Notes, unreadableNote)
			continue
		}
		res.Notes = append(res.Notes, p+": "+note)
	}
	if unreadableNote != "" && !sawFile {
		res.Status = "unreadable"
		res.Error = unreadableNote
		return res, nil
	}
	if sawDenied && !sawFile {
		res.Status = "denied"
		res.Error = "denied by policy"
		return res, nil
	}
	res.Status = "empty"
	if emptyPath != "" {
		res.Path = emptyPath
		res.Shell = ShellKind(emptyPath)
		res.Error = "shell history is empty"
		return res, nil
	}
	res.Error = "no shell history file"
	return res, nil
}

func allow(gate GateFunc, command string) bool {
	if gate == nil {
		return true
	}
	return gate(command) == nil
}

// Candidates lists HISTFILE first when it is set, then the defaults, without duplicates.
func Candidates(histfile string) []string {
	var out []string
	seen := map[string]bool{}
	add := func(p string) {
		if p == "" || seen[p] {
			return
		}
		seen[p] = true
		out = append(out, p)
	}
	add(histfile)
	for _, p := range DefaultPaths() {
		add(p)
	}
	return out
}

var (
	bashAssign = regexp.MustCompile(`(?m)^[ \t]*(?:export[ \t]+)?HISTFILE=([^\n#]+)`)
	fishAssign = regexp.MustCompile(`(?m)^[ \t]*set[ \t]+(?:-\S+[ \t]+)*HISTFILE[ \t]+(\S+)`)
	bashStamp  = regexp.MustCompile(`^#\d{9,}$`)
	zshExt     = regexp.MustCompile(`^: \d+:\d+;(.*)$`)
	fishCmd    = regexp.MustCompile(`^[ \t]*-[ \t]*cmd:[ \t]?(.*)$`)
)

// ParseHistFile returns the last static HISTFILE assignment in rc text.
// A dynamic value ($ or backtick) is ignored. note explains that skip when
// no static assignment remains.
func ParseHistFile(text string) (path, note string) {
	type hit struct {
		at  int
		val string
	}
	var hits []hit
	for _, m := range bashAssign.FindAllStringSubmatchIndex(text, -1) {
		if len(m) >= 4 {
			hits = append(hits, hit{at: m[2], val: text[m[2]:m[3]]})
		}
	}
	for _, m := range fishAssign.FindAllStringSubmatchIndex(text, -1) {
		if len(m) >= 4 {
			hits = append(hits, hit{at: m[2], val: text[m[2]:m[3]]})
		}
	}
	if len(hits) == 0 {
		return "", ""
	}
	// Last assignment in the file wins. Insertion order is not position order
	// across the two patterns, so sort by index.
	for i := 1; i < len(hits); i++ {
		j := i
		for j > 0 && hits[j].at < hits[j-1].at {
			hits[j], hits[j-1] = hits[j-1], hits[j]
			j--
		}
	}
	var dynamic bool
	var last string
	for _, h := range hits {
		p, ok := SafeHistPath(h.val)
		if !ok {
			dynamic = true
			continue
		}
		last = p
		dynamic = false
	}
	if last == "" && dynamic {
		return "", "HISTFILE is not a static path; ignored"
	}
	return last, ""
}

// SafeHistPath accepts a single literal ~ or absolute path with no expansions.
func SafeHistPath(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if len(raw) >= 2 {
		if (raw[0] == '\'' && raw[len(raw)-1] == '\'') || (raw[0] == '"' && raw[len(raw)-1] == '"') {
			raw = strings.TrimSpace(raw[1 : len(raw)-1])
		}
	}
	if raw == "" || strings.ContainsAny(raw, "$`") {
		return "", false
	}
	clean, err := remote.ValidateRemotePath(raw)
	if err != nil {
		return "", false
	}
	if !strings.HasPrefix(clean, "~/") && !strings.HasPrefix(clean, "/") && clean != "~" {
		return "", false
	}
	if clean == "~" {
		return "", false
	}
	return clean, true
}

// ShellKind classifies a history path.
func ShellKind(path string) string {
	base := path
	if i := strings.LastIndex(path, "/"); i >= 0 {
		base = path[i+1:]
	}
	switch {
	case strings.Contains(path, "fish"):
		return "fish"
	case strings.Contains(base, "zsh"):
		return "zsh"
	case strings.Contains(base, "bash"):
		return "bash"
	default:
		return "plain"
	}
}

// Normalize turns raw history text into command lines.
func Normalize(path, text string) []string {
	kind := ShellKind(path)
	if kind == "plain" {
		kind = sniff(text)
	}
	var lines []string
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		switch kind {
		case "fish":
			if m := fishCmd.FindStringSubmatch(line); m != nil {
				cmd := strings.TrimSpace(m[1])
				if cmd != "" {
					lines = append(lines, cmd)
				}
			}
		case "zsh":
			if m := zshExt.FindStringSubmatch(line); m != nil {
				cmd := m[1]
				if strings.TrimSpace(cmd) != "" {
					lines = append(lines, cmd)
				}
				continue
			}
			lines = append(lines, line)
		default:
			if bashStamp.MatchString(strings.TrimSpace(line)) {
				continue
			}
			lines = append(lines, line)
		}
	}
	if lines == nil {
		return []string{}
	}
	for i, line := range lines {
		lines[i] = audit.Scrub(line)
	}
	return lines
}

func sniff(text string) string {
	fishN, zshN := 0, 0
	for _, line := range strings.Split(text, "\n") {
		if fishCmd.MatchString(line) {
			fishN++
		}
		if zshExt.MatchString(line) {
			zshN++
		}
	}
	switch {
	case fishN > 0 && fishN >= zshN:
		return "fish"
	case zshN > 0:
		return "zsh"
	default:
		return "bash"
	}
}

func scrubLines(lines []string) []string {
	out := make([]string, len(lines))
	for i, line := range lines {
		out[i] = audit.Scrub(line)
	}
	return out
}

// Cap keeps the last n lines and the last maxBytes of those lines.
func Cap(lines []string, n, maxBytes int) ([]string, bool) {
	if n < 1 {
		n = DefaultLines
	}
	truncated := false
	if len(lines) > n {
		lines = lines[len(lines)-n:]
		truncated = true
	}
	total := 0
	start := 0
	for i := len(lines) - 1; i >= 0; i-- {
		total += len(lines[i]) + 1
		if total > maxBytes && i != len(lines)-1 {
			start = i + 1
			truncated = true
			break
		}
		if total > maxBytes {
			// A single line is still longer than the cap. Keep a clipped copy.
			clipped := clipBytes(lines[i], maxBytes)
			return []string{clipped}, true
		}
	}
	out := append([]string(nil), lines[start:]...)
	if out == nil {
		out = []string{}
	}
	return out, truncated
}

func rawWindow(n int) int {
	raw := n * 3
	if raw < n {
		raw = n
	}
	if raw > maxRawLines {
		raw = maxRawLines
	}
	return raw
}

func unreadableText(s string) bool {
	l := strings.ToLower(s)
	return strings.Contains(l, "permission denied") ||
		strings.Contains(l, "operation not permitted") ||
		strings.Contains(l, "is a directory") ||
		strings.Contains(l, "not a directory")
}

func oneLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

func clipBytes(s string, n int) string {
	if n <= 0 || len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	if cut == 0 {
		cut = n
	}
	return s[:cut]
}
