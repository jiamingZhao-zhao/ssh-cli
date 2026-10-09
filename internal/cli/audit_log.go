package cli

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/audit"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/config"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/exitcode"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/guard"
)

// auditMeta describes one remote attempt. started is the beginning of the
// attempt; per-host execution replaces it with the dial time.
type auditMeta struct {
	op      string
	command string
	src     string
	dst     string
	started time.Time
}

func (a *App) auditMeta(op, command, src, dst string) auditMeta {
	return auditMeta{op: op, command: command, src: src, dst: dst, started: time.Now()}
}

func (a *App) auditSelectionError(meta auditMeta, hosts []config.ResolvedHost, err error) {
	if err == nil || len(hosts) == 0 || exitcode.From(err) != exitcode.Denied {
		return
	}
	cfg, loadErr := config.Load(a.Dir)
	for _, h := range hosts {
		var dec *guard.Decision
		if loadErr == nil {
			if eff, eerr := guard.Resolve(cfg, h, false); eerr == nil {
				switch meta.op {
				case audit.OpUpload, audit.OpDownload:
					remotePath := meta.dst
					if meta.op == audit.OpDownload {
						remotePath = meta.src
					}
					d := guard.DecideCapability(eff, meta.op, remotePath)
					dec = &d
				default:
					if meta.command != "" {
						d := guard.Decide(eff, meta.command)
						dec = &d
					}
				}
			}
		}
		a.logDenial(meta, h, dec, err.Error())
	}
}

func (a *App) logDenial(meta auditMeta, h config.ResolvedHost, dec *guard.Decision, reason string) {
	high := false
	if dec != nil {
		high = highRisk(*dec)
		if reason == "" {
			reason = decisionReason(*dec)
		}
	}
	if reason == "" {
		reason = "denied by policy"
	}
	code := exitcode.Denied
	_ = a.commitAudit(audit.Record{
		Op:             audit.OpPolicyCheck,
		Host:           h.Alias,
		Group:          h.Group,
		Env:            h.EnvName,
		Command:        meta.command,
		Src:            meta.src,
		Dst:            meta.dst,
		DurationMS:     msSince(meta.started),
		ExitCode:       &code,
		ResultSummary:  reason,
		Status:         audit.StatusDenied,
		HighRisk:       high,
		DeniedByPolicy: true,
		Reason:         reason,
	}, true)
}

func (a *App) logRemote(meta auditMeta, h config.ResolvedHost, dec guard.Decision, status string, code int, summary, reason string) error {
	c := code
	denied := status == audit.StatusDenied
	op := meta.op
	if denied {
		op = audit.OpPolicyCheck
	}
	if reason == "" && (denied || dec.NeedsConfirm) {
		reason = decisionReason(dec)
	}
	return a.commitAudit(audit.Record{
		Op:             op,
		Host:           h.Alias,
		Group:          h.Group,
		Env:            h.EnvName,
		Command:        meta.command,
		Src:            meta.src,
		Dst:            meta.dst,
		DurationMS:     msSince(meta.started),
		ExitCode:       &c,
		ResultSummary:  summary,
		Status:         status,
		HighRisk:       highRisk(dec),
		DeniedByPolicy: denied,
		Reason:         reason,
	}, status != audit.StatusOK)
}

// commitAudit appends a record. keepGoing preserves a remote or policy failure
// when the log itself cannot be written; a successful remote op fails closed.
func (a *App) commitAudit(rec audit.Record, keepGoing bool) error {
	if rec.Source == "" {
		rec.Source = audit.SourceCLI
	}
	if _, err := audit.Append(a.Dir, rec); err != nil {
		fmt.Fprintf(a.Err, "error: audit log: %s\n", err.Error())
		if !keepGoing {
			return exitcode.New(exitcode.Usage, "audit log: %s", err.Error())
		}
	}
	return nil
}

func highRisk(dec guard.Decision) bool {
	if dec.NeedsConfirm {
		return true
	}
	for _, f := range dec.Findings {
		if f.Layer == "builtin" || f.Kind == "confirm" || f.Kind == "obfuscated" {
			return true
		}
	}
	return false
}

func decisionReason(dec guard.Decision) string {
	if len(dec.Findings) == 0 {
		if !dec.Allowed {
			return "denied by policy"
		}
		if dec.NeedsConfirm {
			return "confirmation required"
		}
		return ""
	}
	parts := make([]string, 0, len(dec.Findings))
	for _, f := range dec.Findings {
		parts = append(parts, f.Layer+": "+f.Detail)
		if len(parts) == 3 {
			break
		}
	}
	s := strings.Join(parts, "; ")
	if len(s) > 300 {
		s = s[:300]
	}
	return s
}

func statusOf(code int, err error) (string, int) {
	if err == nil {
		if code == 0 {
			return audit.StatusOK, 0
		}
		return audit.StatusError, code
	}
	msg := strings.ToLower(err.Error())
	c := exitcode.From(err)
	switch {
	case strings.Contains(msg, "timed out"),
		strings.Contains(msg, "deadline exceeded"),
		strings.Contains(msg, "i/o timeout"):
		return audit.StatusTimeout, c
	case c == exitcode.Auth:
		return audit.StatusAuth, c
	case c == exitcode.HostKey, c == exitcode.Connect:
		return audit.StatusConnect, c
	case c == exitcode.Denied:
		return audit.StatusDenied, c
	default:
		return audit.StatusError, c
	}
}

func msSince(t time.Time) int64 {
	d := time.Since(t).Milliseconds()
	if d < 0 {
		return 0
	}
	return d
}

// capWriter keeps a prefix of what was written and reports a short write as success
// so the remote command is not failed by the audit excerpt.
type capWriter struct {
	max int
	buf bytes.Buffer
	cut bool
}

func (w *capWriter) Write(p []byte) (int, error) {
	if w.max <= 0 {
		w.max = 4 << 10
	}
	if w.buf.Len() >= w.max {
		w.cut = true
		return len(p), nil
	}
	remain := w.max - w.buf.Len()
	if len(p) > remain {
		_, _ = w.buf.Write(p[:remain])
		w.cut = true
		return len(p), nil
	}
	_, err := w.buf.Write(p)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func summarizeOutputs(stdout, stderr string, cut bool, extra string) string {
	var b strings.Builder
	if stdout != "" {
		b.WriteString(stdout)
	}
	if stderr != "" {
		if b.Len() > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(stderr)
	}
	if extra != "" {
		if b.Len() > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(extra)
	}
	if cut {
		b.WriteString("\n[truncated]")
	}
	return b.String()
}

func oneLine(s string) string {
	s = strings.ReplaceAll(s, "\r\n", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	return strings.TrimSpace(s)
}

// discardWriter satisfies places that need an io.Writer reference in this file's helpers.
var _ io.Writer = (*capWriter)(nil)
