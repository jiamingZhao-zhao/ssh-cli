package ui

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/audit"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/exitcode"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/guard"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/transfer"
)

func (s *service) fileTextAPI(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	if !s.beginTransfer(w) {
		return
	}
	defer s.endTransfer()
	saving := r.URL.Path == "/api/files/text/save"
	var body struct {
		Alias, Path, Confirm, Version, Fingerprint string
		Content                                    *string
	}
	var limit int64 = 1 << 16
	if saving {
		limit += 6 * transfer.MaxTextBytes
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, limit))
	if err := decoder.Decode(&body); err != nil || decoder.Decode(new(any)) != io.EOF {
		writeFileChangeError(w, errors.New("请求格式无效或超过文本大小上限"), "not_started")
		return
	}
	if saving {
		if body.Content == nil || len(body.Version) != 64 {
			writeFileChangeError(w, errors.New("请先打开文件，再保存"), "not_started")
			return
		}
		if err := transfer.ValidateText(*body.Content); err != nil {
			writeFileChangeError(w, err, "not_started")
			return
		}
	}
	remote, err := transfer.TextPath(body.Path)
	if err != nil {
		writeFileChangeError(w, err, "not_started")
		return
	}
	cfg, host, effective, err := s.hostPlan(body.Alias)
	if err != nil {
		writeFileChangeError(w, err, "not_started")
		return
	}
	fingerprint := cfg.SessionFingerprint(host)
	op, command := audit.OpDownload, "open text"
	if saving {
		op, command = audit.OpFileChange, "save text"
		if fingerprint != body.Fingerprint {
			writeFileChangeError(w, errors.New("主机连接配置已变化，请重新打开文件"), "not_started")
			return
		}
	}
	decide := func(target string, protected []string) guard.Decision {
		eff := effective
		eff.Protected = protected
		read := guard.DecideCapability(eff, "download", target)
		if !saving {
			return read
		}
		return guard.Merge(read, guard.DecideCapability(eff, "upload", target))
	}
	check := func(target string, protected []string) error {
		decision := decide(target, protected)
		if !decision.Allowed {
			return capabilityError(decisionText(decision))
		}
		if decision.NeedsConfirm && strings.TrimSpace(body.Confirm) != host.Alias {
			return errNeedConfirm{}
		}
		return nil
	}
	fail := func(err error, outcome string) {
		var denied capabilityError
		var confirm errNeedConfirm
		switch {
		case errors.As(err, &denied):
			s.writeAudit(w, host, audit.OpPolicyCheck, command, remote, "", audit.StatusDenied, exitcode.Denied, denied.Error(), denied.Error(), true, started)
			writeJSON(w, http.StatusForbidden, map[string]any{"ok": false, "error": denied.Error(), "outcome": "not_started"})
		case errors.As(err, &confirm):
			writeJSON(w, http.StatusConflict, map[string]any{"ok": false, "needsConfirm": true, "confirm": host.Alias, "error": confirm.Error(), "outcome": "not_started"})
		case errors.Is(err, transfer.ErrTextChanged):
			s.writeAudit(w, host, op, command, remote, "", audit.StatusError, 1, err.Error(), err.Error(), false, started)
			writeJSON(w, http.StatusConflict, map[string]any{"ok": false, "error": err.Error(), "outcome": "not_started"})
		default:
			s.writeAudit(w, host, op, command, remote, "", audit.StatusError, 1, err.Error(), err.Error(), false, started)
			writeFileChangeError(w, err, outcome)
		}
	}
	if err := check(remote, effective.Protected); err != nil {
		fail(err, "not_started")
		return
	}
	if saving {
		key := fingerprint + "\x00" + remote
		s.mu.Lock()
		if s.textSaves[key] {
			s.mu.Unlock()
			writeFileChangeError(w, errors.New("这个文件正在保存，请先核对保存结果"), "not_started")
			return
		}
		if s.textSaves == nil {
			s.textSaves = make(map[string]bool)
		}
		s.textSaves[key] = true
		s.mu.Unlock()
		defer func() { s.mu.Lock(); delete(s.textSaves, key); s.mu.Unlock() }()
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	client, err := s.dialResolved(ctx, host)
	if err != nil {
		fail(err, "not_started")
		return
	}
	defer client.Close()
	stop := context.AfterFunc(ctx, func() { _ = client.Close() })
	defer stop()
	sftpClient, err := transfer.Client(client.Raw())
	if err != nil {
		fail(err, "not_started")
		return
	}
	defer sftpClient.Close()
	var resolvedProtected []string
	checkResolved := func() error {
		return transfer.CheckTextPath(sftpClient, remote, effective.Protected, func(target string, protected []string) error {
			resolvedProtected = protected
			return check(target, protected)
		})
	}
	if err := checkResolved(); err != nil {
		fail(err, "not_started")
		return
	}
	if saving {
		if err := transfer.SaveText(sftpClient, remote, body.Version, *body.Content, checkResolved); err != nil {
			fail(err, "unknown")
			return
		}
		s.writeAudit(w, host, op, command, remote, "", audit.StatusOK, 0, command, "", false, started)
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "outcome": "completed"})
		return
	}
	snapshot, err := transfer.ReadText(sftpClient, remote)
	if err != nil {
		fail(err, "not_started")
		return
	}
	effective.Protected = resolvedProtected
	_, atomicReplace := sftpClient.HasExtension("posix-rename@openssh.com")
	writable := atomicReplace && guard.DecideCapability(effective, "upload", remote).Allowed
	s.writeAudit(w, host, op, command, remote, "", audit.StatusOK, 0, command, "", false, started)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "snapshot": snapshot, "fingerprint": fingerprint, "writable": writable})
}
