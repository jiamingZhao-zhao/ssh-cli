// Package audit appends a local, secret-free record of every remote operation.
//
// Files are JSONL, one calendar day per file, under <config>/audit/YYYY-MM-DD.jsonl
// with mode 0600. The UI is not required: callers write here directly.
// Passwords, private keys, and other plaintext secrets are never stored.
package audit

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/fsutil"
)

const (
	// DirName is the audit directory inside the config directory.
	DirName = "audit"

	OpExec         = "exec"
	OpUpload       = "upload"
	OpDownload     = "download"
	OpPolicyCheck  = "policy_check"
	OpStatus       = "status"
	OpService      = "service"
	OpKeys         = "keys"
	OpConfigChange = "config_change"
	OpSession      = "session"
	OpRelay        = "relay"
	OpTerminal     = "terminal"

	// SourceCLI and SourceUI record who drove the operation.
	// cli is the command line and agents. ui is the localhost page.
	// Interactive terminal sessions are ui and do not apply command policy.
	SourceCLI = "cli"
	SourceUI  = "ui"

	// DisplayLayout is the human-facing timestamp form.
	DisplayLayout = "2006-01-02 15:04:05"

	StatusOK      = "ok"
	StatusDenied  = "denied"
	StatusTimeout = "timeout"
	StatusAuth    = "auth"
	StatusConnect = "connect"
	StatusError   = "error"

	// SummaryLimit is the maximum stored stdout/stderr excerpt.
	SummaryLimit = 8 << 10
	// FieldLimit caps command, path, and reason fields.
	FieldLimit = 16 << 10

	actorEnv = "SSH_CLI_ACTOR"
)

// Record is one append-only audit line. JSON names match the on-disk schema.
type Record struct {
	ID             string `json:"id"`
	Time           string `json:"time"`
	Op             string `json:"op"`
	Host           string `json:"host"`
	Group          string `json:"group,omitempty"`
	Env            string `json:"env,omitempty"`
	Command        string `json:"command,omitempty"`
	Src            string `json:"src,omitempty"`
	Dst            string `json:"dst,omitempty"`
	DurationMS     int64  `json:"duration_ms"`
	ExitCode       *int   `json:"exit_code,omitempty"`
	ResultSummary  string `json:"result_summary,omitempty"`
	Status         string `json:"status"`
	HighRisk       bool   `json:"high_risk"`
	DeniedByPolicy bool   `json:"denied_by_policy"`
	Reason         string `json:"reason,omitempty"`
	Actor          string `json:"actor,omitempty"`
	// Source is cli or ui. It is assigned by the process that performed the
	// operation. Callers must not copy it from a request body.
	Source string `json:"source,omitempty"`
}

// Actor returns SSH_CLI_ACTOR, or "cli" when it is unset.
func Actor() string {
	v := strings.TrimSpace(os.Getenv(actorEnv))
	if v == "" {
		return "cli"
	}
	return clip(scrub(v), 128)
}

// ValidStatus reports whether s is a known status filter value.
func ValidStatus(s string) bool {
	switch s {
	case StatusOK, StatusDenied, StatusTimeout, StatusAuth, StatusConnect, StatusError:
		return true
	default:
		return false
	}
}

// ValidOp reports whether s is a known operation filter value.
func ValidOp(s string) bool {
	switch s {
	case OpExec, OpUpload, OpDownload, OpPolicyCheck, OpStatus, OpService, OpKeys, OpConfigChange, OpSession, OpRelay, OpTerminal:
		return true
	default:
		return false
	}
}

// ValidSource reports whether s is cli or ui.
func ValidSource(s string) bool {
	return s == SourceCLI || s == SourceUI
}

// DisplayTime formats a stored RFC3339 stamp as yyyy-MM-dd HH:mm:ss in local time.
func DisplayTime(s string) string {
	t, err := ParseStamp(s)
	if err != nil {
		return s
	}
	return t.In(time.Local).Format(DisplayLayout)
}

// Append scrubs, clips, and writes one JSONL record. It returns the stored record.
func Append(dir string, rec Record) (Record, error) {
	if strings.TrimSpace(dir) == "" {
		return Record{}, fmt.Errorf("audit: empty config dir")
	}
	now := time.Now()
	if strings.TrimSpace(rec.Time) == "" {
		rec.Time = now.Format(time.RFC3339Nano)
	}
	when, err := ParseStamp(rec.Time)
	if err != nil {
		when = now
		rec.Time = now.Format(time.RFC3339Nano)
	}
	if rec.Actor == "" {
		rec.Actor = Actor()
	}
	if rec.Status == "" {
		rec.Status = StatusError
	}
	scrubRecord(&rec)
	rec.Source = canonicalizeSource(rec.Source, rec.Actor)
	if rec.ID == "" {
		rec.ID = newID(when)
	}
	line, err := marshalLine(rec)
	if err != nil {
		return Record{}, err
	}
	auditDir := filepath.Join(dir, DirName)
	if err := os.MkdirAll(auditDir, 0o700); err != nil {
		return Record{}, err
	}
	if err := os.Chmod(auditDir, 0o700); err != nil {
		return Record{}, err
	}
	path := filepath.Join(auditDir, when.Format("2006-01-02")+".jsonl")
	err = fsutil.WithLock(auditDir, func() error {
		f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		if _, err := f.Write(append(line, '\n')); err != nil {
			_ = f.Close()
			return err
		}
		if err := f.Chmod(0o600); err != nil {
			_ = f.Close()
			return err
		}
		if err := f.Sync(); err != nil {
			_ = f.Close()
			return err
		}
		return f.Close()
	})
	if err != nil {
		return Record{}, err
	}
	return rec, nil
}

// ParseStamp parses an RFC3339 or RFC3339Nano timestamp.
func ParseStamp(s string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t, nil
	}
	return time.Parse(time.RFC3339, s)
}

// ParseBound parses a filter bound.
// A duration (24h, 30m) is relative to now. A calendar date is the local day,
// and an until-date includes that whole day.
func ParseBound(s string, until bool) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, fmt.Errorf("empty time")
	}
	if d, err := time.ParseDuration(s); err == nil {
		return time.Now().Add(-d), nil
	}
	if t, err := ParseStamp(s); err == nil {
		return t, nil
	}
	if t, err := time.ParseInLocation("2006-01-02 15:04:05", s, time.Local); err == nil {
		return t, nil
	}
	if t, err := time.ParseInLocation("2006-01-02T15:04:05", s, time.Local); err == nil {
		return t, nil
	}
	if t, err := time.ParseInLocation("2006-01-02", s, time.Local); err == nil {
		if until {
			return t.AddDate(0, 0, 1), nil
		}
		return t, nil
	}
	return time.Time{}, fmt.Errorf("invalid time %q (want RFC3339, YYYY-MM-DD, or a duration like 24h)", s)
}

func newID(t time.Time) string {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return t.Format("20060102T150405.000000000") + "-" + hex.EncodeToString(b[:])
}

func marshalLine(rec Record) ([]byte, error) {
	var buf strings.Builder
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(rec); err != nil {
		return nil, err
	}
	return []byte(strings.TrimRight(buf.String(), "\n")), nil
}

func canonicalizeSource(source, actor string) string {
	switch strings.ToLower(strings.TrimSpace(source)) {
	case SourceCLI:
		return SourceCLI
	case SourceUI:
		return SourceUI
	}
	if strings.TrimSpace(actor) == SourceUI {
		return SourceUI
	}
	return SourceCLI
}

func scrubRecord(rec *Record) {
	rec.Command = clip(scrub(rec.Command), FieldLimit)
	rec.Src = clip(scrub(rec.Src), FieldLimit)
	rec.Dst = clip(scrub(rec.Dst), FieldLimit)
	rec.Reason = clip(scrub(rec.Reason), FieldLimit)
	rec.ResultSummary = clip(scrub(rec.ResultSummary), SummaryLimit)
	rec.Actor = clip(scrub(rec.Actor), 128)
	rec.Host = clip(rec.Host, 128)
	rec.Group = clip(rec.Group, 128)
	rec.Env = clip(rec.Env, 128)
}

var (
	pemRE  = regexp.MustCompile(`(?i)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----`)
	kvRE   = regexp.MustCompile(`(?i)\b(password|passwd|secret|token|api[_-]?key|authorization|ssh_cli_master_key)\b(\s*[=:]\s*)(?:"[^"]*"|'[^']*'|(?:bearer|basic)\s+\S+|\S+)`)
	flagRE = regexp.MustCompile(`(?i)(--(?:password|pass|master-key|token|secret|api-key|access-token|auth-token|bearer))(\s+|=)(?:"[^"]*"|'[^']*'|\S+)`)
	urlRE  = regexp.MustCompile(`(?i)([a-z][a-z0-9+.-]*://[^/\s:@]+:)[^@\s/]+@`)
)

func scrub(s string) string {
	if s == "" {
		return ""
	}
	s = pemRE.ReplaceAllString(s, "[redacted-key]")
	s = kvRE.ReplaceAllString(s, "${1}${2}[redacted]")
	s = flagRE.ReplaceAllString(s, "${1}${2}[redacted]")
	s = urlRE.ReplaceAllString(s, "${1}[redacted]@")
	return s
}

func clip(s string, n int) string {
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
	return s[:cut] + "\n[truncated]"
}
