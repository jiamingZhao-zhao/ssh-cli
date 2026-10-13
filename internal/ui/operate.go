package ui

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/audit"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/bundle"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/config"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/confirmgate"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/exitcode"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/guard"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/transfer"
)

const execCaptureLimit = 1 << 20

func (s *service) hostPlan(alias string) (*config.Config, config.ResolvedHost, guard.Effective, error) {
	cfg, err := config.Load(s.dir)
	if err != nil {
		return nil, config.ResolvedHost{}, guard.Effective{}, err
	}
	h, ok := cfg.Find(strings.TrimSpace(alias))
	if !ok {
		return nil, config.ResolvedHost{}, guard.Effective{}, fmt.Errorf("unknown host %s", alias)
	}
	eff, err := guard.Resolve(cfg, h, false)
	if err != nil {
		return nil, config.ResolvedHost{}, guard.Effective{}, err
	}
	return cfg, h, eff, nil
}

type execIn struct {
	previewRequest *execIn
	OperationID    string            `json:"operationId,omitempty"`
	PlanDigest     string            `json:"planDigest,omitempty"`
	Alias          string            `json:"alias"`
	Command        string            `json:"command"`
	Timeout        string            `json:"timeout"`
	Confirm        string            `json:"confirm"`
	Confirms       map[string]string `json:"confirms"`
	AllowOutflow   bool              `json:"allowOutflow"`
	OutflowConfirm string            `json:"outflowConfirm"`
	Aliases        []string          `json:"aliases"`
	Parallel       int               `json:"parallel"`
	SkipDenied     bool              `json:"skipDenied"`
	AllowCrossEnv  bool              `json:"allowCrossEnv"`
}

type execHit struct {
	status  int
	payload map[string]any
}

func (s *service) execAPI(w http.ResponseWriter, r *http.Request) {
	var body execIn
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
		writeFail(w, err)
		return
	}
	s.runOperation(w, r, body, func(w http.ResponseWriter) {
		if !s.checkPlan(w, body) {
			return
		}
		out := s.execOne(r.Context(), body, false)
		writeJSON(w, out.status, out.payload)
	})
}

func (s *service) execOne(ctx context.Context, body execIn, forceReadonly bool) execHit {
	// Keep audit failures on this result, including concurrent batch rows.
	auditResult := &operationWriter{header: make(http.Header)}
	cfg, h, eff, err := s.hostPlan(body.Alias)
	if err != nil {
		return execHit{status: http.StatusBadRequest, payload: map[string]any{"ok": false, "error": err.Error(), "alias": body.Alias, "outcome": "not_started", "retrySafe": false}}
	}
	preview := body.previewRequest
	if preview == nil {
		preview = &body
	}
	if preview.PlanDigest != "" && planDigest(cfg, *preview) != preview.PlanDigest {
		return execHit{status: http.StatusConflict, payload: map[string]any{"ok": false, "alias": body.Alias, "planChanged": true, "error": "主机、策略或执行内容已变化，请重新预检。", "outcome": "not_started", "retrySafe": false}}
	}
	if forceReadonly {
		eff, err = guard.Resolve(cfg, h, true)
		if err != nil {
			return execHit{status: http.StatusBadRequest, payload: map[string]any{"ok": false, "error": err.Error(), "alias": h.Alias, "outcome": "not_started", "retrySafe": false}}
		}
	}
	started := time.Now()
	phrase := strings.TrimSpace(body.Confirm)
	if body.Confirms != nil {
		if v := strings.TrimSpace(body.Confirms[h.Alias]); v != "" {
			phrase = v
		}
	}
	dec := guard.Decide(eff, body.Command)
	if !dec.Allowed {
		text := decisionText(dec)
		s.writeAudit(auditResult, h, audit.OpPolicyCheck, body.Command, "", "", audit.StatusDenied, exitcode.Denied, text, text, true, started)
		return execHit{status: http.StatusForbidden, payload: map[string]any{
			"ok": false, "alias": h.Alias, "error": text, "status": audit.StatusDenied,
			"outcome": "not_started", "retrySafe": false, "auditWarning": auditResult.Header().Get(auditWarningHeader),
		}}
	}
	if dec.NeedsConfirm && phrase != h.Alias {
		return execHit{status: http.StatusConflict, payload: map[string]any{
			"ok": false, "needsConfirm": true, "confirm": h.Alias, "alias": h.Alias,
			"status": "confirmation_required", "outcome": "not_started", "retrySafe": false,
			"error": "type the host alias to confirm",
		}}
	}
	suppress, needsOut := guard.ExecOutflow(eff.NoDataOut, body.AllowOutflow)
	if needsOut && body.OutflowConfirm != guard.OutflowPhrase {
		return execHit{status: http.StatusConflict, payload: map[string]any{
			"ok": false, "needsConfirm": true, "confirm": guard.OutflowPhrase, "confirmField": "outflowConfirm",
			"status": "confirmation_required", "outcome": "not_started", "retrySafe": false,
			"alias": h.Alias, "error": "type outflow to return command output",
		}}
	}
	timeout := 30 * time.Second
	if strings.TrimSpace(body.Timeout) != "" {
		d, err := time.ParseDuration(body.Timeout)
		if err != nil || d <= 0 || d > 5*time.Minute {
			return execHit{status: http.StatusBadRequest, payload: map[string]any{"ok": false, "error": "invalid timeout", "alias": h.Alias, "outcome": "not_started", "retrySafe": false}}
		}
		timeout = d
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var stdout, stderr limitBuf
	var outW, errW io.Writer = &stdout, &stderr
	stdout.n, stderr.n = execCaptureLimit, execCaptureLimit
	if body.OperationID != "" {
		stdout.n, stderr.n = 64<<10, 64<<10
	}
	if suppress {
		outW, errW = io.Discard, io.Discard
	}
	s.reconcile()
	code, err := s.pool.Exec(runCtx, h.Alias, cfg.SessionFingerprint(h), body.Command, outW, errW)
	summary := strings.TrimSpace(stdout.String() + "\n" + stderr.String())
	if stdout.cut || stderr.cut {
		summary += "\n[truncated]"
	}
	if suppress {
		summary = guard.OutflowDiscarded
	}
	if err != nil {
		status := execFailureStatus(runCtx, err)
		s.writeAudit(auditResult, h, audit.OpExec, body.Command, "", "", status, code, err.Error(), err.Error(), false, started)
		return execHit{status: http.StatusBadRequest, payload: map[string]any{
			"ok": false, "alias": h.Alias, "error": err.Error(), "exitCode": code, "status": status,
			"outcome": "unknown", "retrySafe": false, "auditWarning": auditResult.Header().Get(auditWarningHeader),
		}}
	}
	status := audit.StatusOK
	if code != 0 {
		status = audit.StatusError
	}
	s.writeAudit(auditResult, h, audit.OpExec, body.Command, "", "", status, code, summary, "", false, started)
	resp := map[string]any{
		"ok": true, "alias": h.Alias, "exitCode": code, "stdout": stdout.String(), "stderr": stderr.String(),
		"truncated": stdout.cut || stderr.cut, "status": status,
		"outcome": "completed", "retrySafe": false, "auditWarning": auditResult.Header().Get(auditWarningHeader),
	}
	if suppress {
		resp["stdout"] = ""
		resp["stderr"] = ""
		resp["stdoutSuppressed"] = true
		resp["notice"] = guard.OutflowDiscarded
		resp["truncated"] = false
	}
	return execHit{status: http.StatusOK, payload: resp}
}

func execFailureStatus(ctx context.Context, err error) string {
	var networkError net.Error
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) || (errors.As(err, &networkError) && networkError.Timeout()) {
		return audit.StatusTimeout
	}
	switch exitcode.From(err) {
	case exitcode.Auth:
		return audit.StatusAuth
	case exitcode.Connect, exitcode.HostKey:
		return audit.StatusConnect
	case exitcode.Denied:
		return audit.StatusDenied
	default:
		return audit.StatusError
	}
}

func (s *service) uploadAPI(w http.ResponseWriter, r *http.Request) {
	// No byte cap: the browser can only hand over the file bytes, then this
	// process writes them with transfer.UploadWithOptions, the same SFTP path
	// the CLI uses. Multipart spills past 32MiB onto disk instead of a blob.
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		writeFail(w, err)
		return
	}
	defer r.MultipartForm.RemoveAll()
	alias := r.FormValue("alias")
	remote := r.FormValue("remote")
	confirm := r.FormValue("confirm")
	file, hdr, err := r.FormFile("file")
	if err != nil {
		writeFail(w, fmt.Errorf("file is required"))
		return
	}
	defer file.Close()
	started := time.Now()
	_, h, eff, err := s.hostPlan(alias)
	if err != nil {
		writeFail(w, err)
		return
	}
	if !s.requireCapability(w, h, eff, "upload", remote, confirm, audit.OpUpload, started) {
		return
	}
	name, err := cleanUploadName(hdr.Filename)
	if err != nil {
		writeFail(w, err)
		return
	}
	dir, err := os.MkdirTemp("", "ssh-cli-upload-*")
	if err != nil {
		writeFail(w, err)
		return
	}
	defer os.RemoveAll(dir)
	tmpName := filepath.Join(dir, name)
	tmp, err := os.OpenFile(tmpName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		writeFail(w, err)
		return
	}
	if _, err := io.Copy(tmp, file); err != nil {
		_ = tmp.Close()
		writeFail(w, err)
		return
	}
	_ = tmp.Close()
	s.reconcile()
	client, err := s.dialResolved(r.Context(), h)
	if err != nil {
		s.writeAudit(w, h, audit.OpUpload, audit.OpUpload, "", remote, audit.StatusError, 1, err.Error(), err.Error(), false, started)
		writeFail(w, err)
		return
	}
	defer client.Close()
	sink := newProgressSink(w, wantsProgress(r))
	err = transfer.UploadWithOptions(client.Raw(), tmpName, remote, nil, transfer.UploadOptions{Context: r.Context(), Protected: eff.Protected, RejectOverwrite: r.FormValue("overwrite") != "true", Progress: sink.report, Check: func(dest string, protected []string) error {
		resolved := eff
		resolved.Protected = protected
		d := guard.DecideCapability(resolved, "upload", dest)
		if !d.Allowed {
			return capabilityError(decisionText(d))
		}
		if d.NeedsConfirm && strings.TrimSpace(confirm) != h.Alias {
			return errNeedConfirm{}
		}
		return nil
	}})
	if err != nil {
		var overwrite *transfer.OverwriteError
		if errors.As(err, &overwrite) {
			payload := map[string]any{"ok": false, "needsOverwrite": true, "path": overwrite.Path, "error": overwrite.Error()}
			if sink.on {
				sink.event(payload)
				return
			}
			writeJSON(w, http.StatusConflict, payload)
			return
		}
		var need errNeedConfirm
		if errors.As(err, &need) {
			payload := map[string]any{"ok": false, "needsConfirm": true, "confirm": h.Alias, "error": need.Error()}
			if sink.on {
				sink.event(payload)
				return
			}
			writeJSON(w, http.StatusConflict, payload)
			return
		}
		var denied capabilityError
		if errors.As(err, &denied) {
			s.writeAudit(w, h, audit.OpPolicyCheck, audit.OpUpload, "", remote, audit.StatusDenied, exitcode.Denied, denied.Error(), denied.Error(), true, started)
			payload := map[string]any{"ok": false, "error": denied.Error(), "status": "denied"}
			if sink.on {
				sink.event(payload)
				return
			}
			writeJSON(w, http.StatusForbidden, payload)
			return
		}
		s.writeAudit(w, h, audit.OpUpload, audit.OpUpload, "", remote, audit.StatusError, 1, err.Error(), err.Error(), false, started)
		if sink.fail(err) {
			return
		}
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error(), "outcome": "unknown", "retrySafe": false})
		return
	}
	s.writeAudit(w, h, audit.OpUpload, audit.OpUpload, name, remote, audit.StatusOK, 0, "upload "+remote, "", false, started)
	if sink.ok(map[string]any{"ok": true}) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *service) downloadAPI(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Alias   string `json:"alias"`
		Path    string `json:"path"`
		Local   string `json:"local"`
		Confirm string `json:"confirm"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
		writeFail(w, err)
		return
	}
	started := time.Now()
	_, h, eff, err := s.hostPlan(body.Alias)
	if err != nil {
		writeFail(w, err)
		return
	}
	if !s.requireCapability(w, h, eff, "download", body.Path, body.Confirm, audit.OpDownload, started) {
		return
	}
	remote := transfer.RestoreRemotePath(body.Path)
	dest, err := localDownloadDest(body.Local, remote)
	if err != nil {
		writeFail(w, err)
		return
	}
	s.reconcile()
	ctx := r.Context()
	client, err := s.dialResolved(ctx, h)
	if err != nil {
		s.writeAudit(w, h, audit.OpDownload, audit.OpDownload, remote, dest, audit.StatusError, 1, err.Error(), err.Error(), false, started)
		writeFail(w, err)
		return
	}
	defer client.Close()
	// Same writer as `ssh-cli download`: SFTP straight onto this machine.
	// The page only shows status. It does not buffer the file.
	sink := newProgressSink(w, wantsProgress(r))
	if err := transfer.DownloadWithOptions(client.Raw(), remote, dest, nil, transfer.DownloadOptions{Context: ctx, Progress: sink.report}); err != nil {
		s.writeAudit(w, h, audit.OpDownload, audit.OpDownload, remote, dest, audit.StatusError, 1, err.Error(), err.Error(), false, started)
		if sink.fail(err) {
			return
		}
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error(), "outcome": "unknown", "retrySafe": false})
		return
	}
	s.writeAudit(w, h, audit.OpDownload, audit.OpDownload, remote, dest, audit.StatusOK, 0, "download "+remote+" -> "+dest, "", false, started)
	if sink.ok(map[string]any{"ok": true, "remote": remote, "local": dest}) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "remote": remote, "local": dest})
}

// localDownloadDest is the CLI local argument. An empty request uses
// ~/Downloads when that directory exists, otherwise ~/ssh-cli-downloads.
func localDownloadDest(requested, remote string) (string, error) {
	base := path.Base(path.Clean(strings.ReplaceAll(remote, "\\", "/")))
	if base == "." || base == "/" || base == "" {
		base = "download"
	}
	dir := strings.TrimSpace(requested)
	var err error
	if dir == "" {
		dir, err = defaultDownloadDir()
		if err != nil {
			return "", err
		}
	} else {
		dir = filepath.Clean(dir)
		if !filepath.IsAbs(dir) {
			return "", fmt.Errorf("本机保存目录需要绝对路径")
		}
		if err = os.MkdirAll(dir, 0o755); err != nil {
			return "", err
		}
	}
	st, err := os.Stat(dir)
	if err != nil {
		return "", err
	}
	if !st.IsDir() {
		return "", fmt.Errorf("本机保存位置不是目录")
	}
	return filepath.Join(dir, base), nil
}

func wantsProgress(r *http.Request) bool {
	return strings.Contains(strings.ToLower(r.Header.Get("Accept")), "application/x-ndjson")
}

// progressSink writes newline-delimited progress once the caller asked for it.
// Until the first event, the response is still a normal JSON status.
type progressSink struct {
	w    http.ResponseWriter
	fl   http.Flusher
	want bool
	on   bool
}

func newProgressSink(w http.ResponseWriter, want bool) *progressSink {
	fl, _ := w.(http.Flusher)
	return &progressSink{w: w, fl: fl, want: want}
}

func (p *progressSink) report(done, total int64) {
	if p == nil || !p.want {
		return
	}
	p.event(map[string]any{"loaded": done, "total": total})
}

func (p *progressSink) event(v any) {
	if p == nil || !p.want {
		return
	}
	if fields, ok := v.(map[string]any); ok && p.w.Header().Get(auditWarningHeader) != "" {
		fields["auditWarning"] = "failed"
	}
	if !p.on {
		p.on = true
		p.w.Header().Set("Content-Type", "application/x-ndjson; charset=utf-8")
		p.w.Header().Set("Cache-Control", "no-store")
		p.w.Header().Set("X-Content-Type-Options", "nosniff")
		p.w.WriteHeader(http.StatusOK)
	}
	enc := json.NewEncoder(p.w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
	if p.fl != nil {
		p.fl.Flush()
	}
}

func (p *progressSink) fail(err error) bool {
	if p == nil || !p.on {
		return false
	}
	msg := "传输失败"
	if err != nil && strings.TrimSpace(err.Error()) != "" {
		msg = err.Error()
	}
	p.event(map[string]any{"ok": false, "error": msg, "outcome": "unknown", "retrySafe": false})
	return true
}

func (p *progressSink) ok(v map[string]any) bool {
	if p == nil || !p.on {
		return false
	}
	if v == nil {
		v = map[string]any{"ok": true}
	}
	p.event(v)
	return true
}

func defaultDownloadDir() (string, error) {
	home, err := os.UserHomeDir()
	if err == nil && home != "" {
		downloads := filepath.Join(home, "Downloads")
		if st, statErr := os.Stat(downloads); statErr == nil && st.IsDir() {
			return downloads, nil
		}
		dir := filepath.Join(home, "ssh-cli-downloads")
		if mkErr := os.MkdirAll(dir, 0o755); mkErr != nil {
			return "", mkErr
		}
		return dir, nil
	}
	return os.MkdirTemp("", "ssh-cli-downloads-")
}

// requireCapability applies upload and download checks for every caller,
// including a request that looks like the localhost page. false means the
// response was already written.
func (s *service) requireCapability(w http.ResponseWriter, h config.ResolvedHost, eff guard.Effective, capability, remote, confirm, command string, started time.Time) bool {
	dec := guard.DecideCapability(eff, capability, remote)
	if !dec.Allowed {
		text := decisionText(dec)
		s.writeAudit(w, h, audit.OpPolicyCheck, command, "", remote, audit.StatusDenied, exitcode.Denied, text, text, true, started)
		writeJSON(w, http.StatusForbidden, map[string]any{"ok": false, "error": text, "status": "denied"})
		return false
	}
	if dec.NeedsConfirm && strings.TrimSpace(confirm) != h.Alias {
		writeJSON(w, http.StatusConflict, map[string]any{
			"ok": false, "needsConfirm": true, "confirm": h.Alias, "error": "type the host alias to confirm",
		})
		return false
	}
	return true
}

type capabilityError string

func (e capabilityError) Error() string { return string(e) }

func (s *service) relayAPI(w http.ResponseWriter, r *http.Request) {
	var body struct {
		From     string `json:"from"`
		FromPath string `json:"fromPath"`
		To       string `json:"to"`
		ToPath   string `json:"toPath"`
		Confirm  string `json:"confirm"`
		CrossEnv bool   `json:"allowCrossEnv"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
		writeFail(w, err)
		return
	}
	_, src, srcEff, err := s.hostPlan(body.From)
	if err != nil {
		writeFail(w, err)
		return
	}
	_, dst, dstEff, err := s.hostPlan(body.To)
	if err != nil {
		writeFail(w, err)
		return
	}
	dec := guard.DecideRelay(srcEff, dstEff, src.EnvName, dst.EnvName, body.ToPath, body.CrossEnv)
	started := time.Now()
	if !dec.Allowed {
		s.writeAudit(w, dst, audit.OpPolicyCheck, "", body.From+":"+body.FromPath, body.To+":"+body.ToPath, audit.StatusDenied, 0, decisionText(dec), decisionText(dec), true, started)
		writeJSON(w, http.StatusForbidden, map[string]any{"ok": false, "error": decisionText(dec)})
		return
	}
	if dec.NeedsConfirm && body.Confirm != dst.Alias {
		writeJSON(w, http.StatusConflict, map[string]any{
			"ok": false, "needsConfirm": true, "confirm": dst.Alias, "error": "type the destination alias to confirm",
		})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	srcClient, err := s.dialResolved(ctx, src)
	if err != nil {
		s.writeAudit(w, src, audit.OpRelay, "", body.FromPath, body.ToPath, audit.StatusConnect, 0, err.Error(), err.Error(), false, started)
		writeFail(w, err)
		return
	}
	defer srcClient.Close()
	dstClient, err := s.dialResolved(ctx, dst)
	if err != nil {
		s.writeAudit(w, dst, audit.OpRelay, "", body.FromPath, body.ToPath, audit.StatusConnect, 0, err.Error(), err.Error(), false, started)
		writeFail(w, err)
		return
	}
	defer dstClient.Close()
	res, err := transfer.Relay(srcClient.Raw(), dstClient.Raw(), body.FromPath, body.ToPath)
	if err != nil {
		s.writeAudit(w, dst, audit.OpRelay, "", body.From+":"+body.FromPath, body.To+":"+body.ToPath, audit.StatusError, 0, err.Error(), err.Error(), false, started)
		writeFail(w, err)
		return
	}
	summary := fmt.Sprintf("relay %s %d bytes", res.Algo, res.Bytes)
	s.writeAudit(w, dst, audit.OpRelay, "", body.From+":"+body.FromPath, body.To+":"+body.ToPath, audit.StatusOK, 0, summary, "", false, started)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "bytes": res.Bytes, "algo": res.Algo, "sum": res.Sum})
}

func (s *service) sessionsAPI(w http.ResponseWriter, r *http.Request) {
	s.reconcile()
	writeJSON(w, http.StatusOK, map[string]any{"sessions": s.pool.List()})
}

func (s *service) sessionOpenAPI(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Alias string `json:"alias"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
		writeFail(w, err)
		return
	}
	_, h, _, err := s.hostPlan(body.Alias)
	if err != nil {
		writeFail(w, err)
		return
	}
	started := time.Now()
	s.reconcile()
	if err := s.pool.Open(r.Context(), h.Alias, s.fingerprint(h), false); err != nil {
		s.writeAudit(w, h, audit.OpSession, "", "", "", audit.StatusConnect, 0, err.Error(), err.Error(), false, started)
		writeFail(w, err)
		return
	}
	s.writeAudit(w, h, audit.OpSession, "", "", "", audit.StatusOK, 0, "open", "open", false, started)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *service) sessionCloseAPI(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Alias string `json:"alias"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
		writeFail(w, err)
		return
	}
	s.pool.Close(strings.TrimSpace(body.Alias))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *service) configExportAPI(w http.ResponseWriter, r *http.Request) {
	cfg, err := config.Load(s.dir)
	if err != nil {
		writeFail(w, err)
		return
	}
	data, err := bundle.Export(cfg)
	if err != nil {
		writeFail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "yaml": string(data)})
}

func (s *service) configImportAPI(w http.ResponseWriter, r *http.Request) {
	var body struct {
		YAML         string `json:"yaml"`
		HumanConfirm string `json:"humanConfirm"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4<<20)).Decode(&body); err != nil {
		writeFail(w, err)
		return
	}
	var needs []confirmgate.Need
	summary := ""
	err := config.Update(s.dir, func(cfg *config.Config) error {
		n, sum, err := bundle.ApplyConfirmed(s.dir, "ui", body.HumanConfirm, cfg, []byte(body.YAML))
		if err != nil {
			return err
		}
		needs = n
		summary = sum
		return nil
	})
	if err != nil {
		writeFail(w, err)
		return
	}
	confirmgate.RecordImport(s.dir, "ui", needs, summary)
	s.reconcile()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func cleanUploadName(raw string) (string, error) {
	raw = strings.ReplaceAll(strings.TrimSpace(raw), "\\", "/")
	name := path.Base(raw)
	if name == "." || name == ".." || name == "" || name == "/" || strings.ContainsRune(name, 0) {
		return "", fmt.Errorf("invalid upload filename")
	}
	return name, nil
}

func (s *service) auditOverviewAPI(w http.ResponseWriter, r *http.Request) {
	source := strings.TrimSpace(r.URL.Query().Get("source"))
	if source == "" {
		source = audit.SourceCLI
	}
	if source == "all" {
		source = ""
	}
	ov, err := audit.LoadOverviewSource(s.dir, 14, time.Now(), source)
	if err != nil {
		writeFail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, ov)
}

func (s *service) auditStatsAPI(w http.ResponseWriter, r *http.Request) {
	st, err := audit.Stat(s.dir)
	if err != nil {
		writeFail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *service) auditCleanupAPI(w http.ResponseWriter, r *http.Request) {
	res, err := audit.Cleanup(s.dir, audit.MinAge, time.Now())
	if err != nil {
		writeFail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "removed": res.Removed, "kept": res.Kept, "filesDeleted": res.FilesDeleted, "bytesFreed": res.BytesFreed,
	})
}

const auditWarningHeader = "X-SSH-CLI-Audit-Warning"
const auditWarningText = "本地审计写入失败，请检查配置目录的权限和磁盘空间；远端操作结果见本次返回，不要因此重复执行。"

func (s *service) writeAudit(w http.ResponseWriter, h config.ResolvedHost, op, command, src, dst, status string, code int, summary, reason string, denied bool, started time.Time) {
	c := code
	rec := audit.Record{
		Op: op, Host: h.Alias, Group: h.Group, Env: h.EnvName, Command: command, Src: src, Dst: dst,
		DurationMS: time.Since(started).Milliseconds(), ExitCode: &c, ResultSummary: summary, Status: status,
		DeniedByPolicy: denied, Reason: reason, Actor: "ui", Source: audit.SourceUI, HighRisk: denied,
	}
	if rec.DurationMS < 0 {
		rec.DurationMS = 0
	}
	if _, err := audit.Append(s.dir, rec); err != nil {
		// The header is ASCII-safe and also works for streaming/file responses.
		w.Header().Set(auditWarningHeader, "failed")
	}
}

func decisionText(dec guard.Decision) string {
	if len(dec.Findings) == 0 {
		if !dec.Allowed {
			return "denied by policy"
		}
		return "confirmation required"
	}
	parts := make([]string, 0, len(dec.Findings))
	for _, f := range dec.Findings {
		parts = append(parts, f.Layer+": "+f.Detail)
		if len(parts) == 3 {
			break
		}
	}
	return strings.Join(parts, "; ")
}

type limitBuf struct {
	buf bytes.Buffer
	n   int
	cut bool
}

func (b *limitBuf) Write(p []byte) (int, error) {
	if b.n <= 0 {
		b.n = execCaptureLimit
	}
	if b.buf.Len() >= b.n {
		b.cut = true
		return len(p), nil
	}
	remain := b.n - b.buf.Len()
	if len(p) > remain {
		_, _ = b.buf.Write(p[:remain])
		b.cut = true
		return len(p), nil
	}
	return b.buf.Write(p)
}

func (b *limitBuf) String() string { return b.buf.String() }
