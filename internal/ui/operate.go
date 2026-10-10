package ui

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/audit"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/bundle"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/config"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/confirmgate"
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
	out := s.execOne(r.Context(), body, false)
	writeJSON(w, out.status, out.payload)
}

func (s *service) execOne(ctx context.Context, body execIn, forceReadonly bool) execHit {
	cfg, h, eff, err := s.hostPlan(body.Alias)
	if err != nil {
		return execHit{status: http.StatusBadRequest, payload: map[string]any{"ok": false, "error": err.Error(), "alias": body.Alias}}
	}
	if forceReadonly {
		eff, err = guard.Resolve(cfg, h, true)
		if err != nil {
			return execHit{status: http.StatusBadRequest, payload: map[string]any{"ok": false, "error": err.Error(), "alias": h.Alias}}
		}
	}
	phrase := strings.TrimSpace(body.Confirm)
	if body.Confirms != nil {
		if v := strings.TrimSpace(body.Confirms[h.Alias]); v != "" {
			phrase = v
		}
	}
	dec := guard.Decide(eff, body.Command)
	if !dec.Allowed {
		return execHit{status: http.StatusForbidden, payload: map[string]any{
			"ok": false, "alias": h.Alias, "error": decisionText(dec), "status": audit.StatusDenied,
		}}
	}
	if dec.NeedsConfirm && phrase != h.Alias {
		return execHit{status: http.StatusConflict, payload: map[string]any{
			"ok": false, "needsConfirm": true, "confirm": h.Alias, "alias": h.Alias,
			"error": "type the host alias to confirm",
		}}
	}
	suppress, needsOut := guard.ExecOutflow(eff.NoDataOut, body.AllowOutflow)
	if needsOut && body.OutflowConfirm != guard.OutflowPhrase {
		return execHit{status: http.StatusConflict, payload: map[string]any{
			"ok": false, "needsConfirm": true, "confirm": guard.OutflowPhrase, "confirmField": "outflowConfirm",
			"alias": h.Alias, "error": "type outflow to return command output",
		}}
	}
	timeout := 30 * time.Second
	if strings.TrimSpace(body.Timeout) != "" {
		d, err := time.ParseDuration(body.Timeout)
		if err != nil || d <= 0 || d > 5*time.Minute {
			return execHit{status: http.StatusBadRequest, payload: map[string]any{"ok": false, "error": "invalid timeout", "alias": h.Alias}}
		}
		timeout = d
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var stdout, stderr limitBuf
	var outW, errW io.Writer = &stdout, &stderr
	stdout.n, stderr.n = execCaptureLimit, execCaptureLimit
	if suppress {
		outW, errW = io.Discard, io.Discard
	}
	s.reconcile()
	code, err := s.pool.Exec(runCtx, h.Alias, h.Host.ConnFingerprint(), body.Command, outW, errW)
	summary := strings.TrimSpace(stdout.String() + "\n" + stderr.String())
	if stdout.cut || stderr.cut {
		summary += "\n[truncated]"
	}
	if suppress {
		summary = guard.OutflowDiscarded
	}
	if err != nil {
		return execHit{status: http.StatusBadRequest, payload: map[string]any{
			"ok": false, "alias": h.Alias, "error": err.Error(), "exitCode": code, "status": audit.StatusError,
		}}
	}
	status := audit.StatusOK
	if code != 0 {
		status = audit.StatusError
	}
	resp := map[string]any{
		"ok": true, "alias": h.Alias, "exitCode": code, "stdout": stdout.String(), "stderr": stderr.String(),
		"truncated": stdout.cut || stderr.cut, "status": status,
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

func (s *service) uploadAPI(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<20)
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		writeFail(w, err)
		return
	}
	alias := r.FormValue("alias")
	remote := r.FormValue("remote")
	confirm := r.FormValue("confirm")
	file, hdr, err := r.FormFile("file")
	if err != nil {
		writeFail(w, fmt.Errorf("file is required"))
		return
	}
	defer file.Close()
	_, h, eff, err := s.hostPlan(alias)
	if err != nil {
		writeFail(w, err)
		return
	}
	human := s.workspaceHuman(r)
	if !human {
		dec := guard.DecideCapability(eff, "upload", remote)
		if !dec.Allowed {
			writeJSON(w, http.StatusForbidden, map[string]any{"ok": false, "error": decisionText(dec)})
			return
		}
		if dec.NeedsConfirm && confirm != h.Alias {
			writeJSON(w, http.StatusConflict, map[string]any{
				"ok": false, "needsConfirm": true, "confirm": h.Alias, "error": "type the host alias to confirm",
			})
			return
		}
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
	fp := h.Host.ConnFingerprint()
	if err := s.pool.Open(r.Context(), h.Alias, fp, false); err != nil {
		writeFail(w, err)
		return
	}
	err = s.pool.Use(h.Alias, fp, func() error {
		client, ok := s.pool.Client(h.Alias, fp)
		if !ok {
			return fmt.Errorf("session %s is not open", h.Alias)
		}
		return transfer.UploadChecked(client, tmpName, remote, nil, func(dest string) error {
			if human {
				return nil
			}
			d := guard.DecideCapability(eff, "upload", dest)
			if !d.Allowed {
				return fmt.Errorf("%s", decisionText(d))
			}
			if d.NeedsConfirm && confirm != h.Alias {
				return fmt.Errorf("type the host alias to confirm")
			}
			return nil
		})
	})
	if err != nil {
		writeFail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *service) downloadAPI(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Alias   string `json:"alias"`
		Path    string `json:"path"`
		Confirm string `json:"confirm"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
		writeFail(w, err)
		return
	}
	_, h, eff, err := s.hostPlan(body.Alias)
	if err != nil {
		writeFail(w, err)
		return
	}
	if !s.workspaceHuman(r) {
		dec := guard.DecideCapability(eff, "download", body.Path)
		if !dec.Allowed {
			writeJSON(w, http.StatusForbidden, map[string]any{"ok": false, "error": decisionText(dec)})
			return
		}
	}
	s.reconcile()
	fp := h.Host.ConnFingerprint()
	if err := s.pool.Open(r.Context(), h.Alias, fp, false); err != nil {
		writeFail(w, err)
		return
	}
	tmp, err := os.MkdirTemp("", "ssh-cli-download-*")
	if err != nil {
		writeFail(w, err)
		return
	}
	defer os.RemoveAll(tmp)
	dest := filepath.Join(tmp, "payload")
	err = s.pool.Use(h.Alias, fp, func() error {
		client, ok := s.pool.Client(h.Alias, fp)
		if !ok {
			return fmt.Errorf("session %s is not open", h.Alias)
		}
		return transfer.Download(client, body.Path, dest, nil)
	})
	if err != nil {
		writeFail(w, err)
		return
	}
	info, err := os.Stat(dest)
	if err != nil {
		writeFail(w, err)
		return
	}
	if info.IsDir() {
		w.Header().Set("Content-Type", "application/gzip")
		w.Header().Set("Content-Disposition", "attachment; filename=\"download.tar.gz\"")
		if err := tarGz(w, dest); err != nil {
			return
		}
		return
	}
	f, err := os.Open(dest)
	if err != nil {
		writeFail(w, err)
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", "attachment; filename="+filepath.Base(body.Path))
	w.Header().Set("Content-Length", strconv.FormatInt(info.Size(), 10))
	_, _ = io.Copy(w, f)
}

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
		s.writeAudit(dst, audit.OpPolicyCheck, "", body.From+":"+body.FromPath, body.To+":"+body.ToPath, audit.StatusDenied, 0, decisionText(dec), decisionText(dec), true, started)
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
		s.writeAudit(src, audit.OpRelay, "", body.FromPath, body.ToPath, audit.StatusConnect, 0, err.Error(), err.Error(), false, started)
		writeFail(w, err)
		return
	}
	defer srcClient.Close()
	dstClient, err := s.dialResolved(ctx, dst)
	if err != nil {
		s.writeAudit(dst, audit.OpRelay, "", body.FromPath, body.ToPath, audit.StatusConnect, 0, err.Error(), err.Error(), false, started)
		writeFail(w, err)
		return
	}
	defer dstClient.Close()
	res, err := transfer.Relay(srcClient.Raw(), dstClient.Raw(), body.FromPath, body.ToPath)
	if err != nil {
		s.writeAudit(dst, audit.OpRelay, "", body.From+":"+body.FromPath, body.To+":"+body.ToPath, audit.StatusError, 0, err.Error(), err.Error(), false, started)
		writeFail(w, err)
		return
	}
	summary := fmt.Sprintf("relay %s %d bytes", res.Algo, res.Bytes)
	s.writeAudit(dst, audit.OpRelay, "", body.From+":"+body.FromPath, body.To+":"+body.ToPath, audit.StatusOK, 0, summary, "", false, started)
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
	if err := s.pool.Open(r.Context(), h.Alias, h.Host.ConnFingerprint(), false); err != nil {
		s.writeAudit(h, audit.OpSession, "", "", "", audit.StatusConnect, 0, err.Error(), err.Error(), false, started)
		writeFail(w, err)
		return
	}
	s.writeAudit(h, audit.OpSession, "", "", "", audit.StatusOK, 0, "open", "open", false, started)
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

func (s *service) writeAudit(h config.ResolvedHost, op, command, src, dst, status string, code int, summary, reason string, denied bool, started time.Time) {
	c := code
	rec := audit.Record{
		Op: op, Host: h.Alias, Group: h.Group, Env: h.EnvName, Command: command, Src: src, Dst: dst,
		DurationMS: time.Since(started).Milliseconds(), ExitCode: &c, ResultSummary: summary, Status: status,
		DeniedByPolicy: denied, Reason: reason, Actor: "ui", Source: audit.SourceUI, HighRisk: denied,
	}
	if rec.DurationMS < 0 {
		rec.DurationMS = 0
	}
	_, _ = audit.Append(s.dir, rec)
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

func tarGz(w io.Writer, root string) error {
	gz := gzip.NewWriter(w)
	tw := tar.NewWriter(gz)
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		hdr, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		hdr.Name = filepath.ToSlash(rel)
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		_, err = io.Copy(tw, f)
		_ = f.Close()
		return err
	})
	if err != nil {
		_ = tw.Close()
		_ = gz.Close()
		return err
	}
	if err := tw.Close(); err != nil {
		_ = gz.Close()
		return err
	}
	return gz.Close()
}
