package ui

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"regexp"
	"time"
)

// This bounded, session-scoped cache prevents re-running an accepted request.
// It is deliberately not a durable job queue: restart/expiry means unknown,
// never permission to replay a write. Confirmation-only replies are not cached.
const operationTTL = 30 * time.Minute
const maxOperations = 32

var operationIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{16,80}$`)

type operation struct {
	digest  string
	created time.Time
	state   string
	status  int
	result  json.RawMessage
}

type operationWriter struct {
	header http.Header
	status int
	bytes.Buffer
}

func (w *operationWriter) Header() http.Header { return w.header }
func (w *operationWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
}
func (w *operationWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.Buffer.Write(b)
}

func (s *service) runOperation(w http.ResponseWriter, r *http.Request, body execIn, run func(http.ResponseWriter)) {
	if body.OperationID == "" {
		run(w)
		return
	}
	if !operationIDPattern.MatchString(body.OperationID) {
		writeErr(w, 400, "invalid operationId")
		return
	}
	if _, ok := s.sessionCSRF(r); !ok {
		writeErr(w, 403, "ui session required")
		return
	}
	key := sessionID(r) + ":" + body.OperationID
	canonical := body
	canonical.Confirm, canonical.Confirms, canonical.OutflowConfirm = "", nil, ""
	b, _ := json.Marshal(canonical)
	sum := sha256.Sum256(append([]byte(r.URL.Path+"\x00"), b...))
	digest := hex.EncodeToString(sum[:])
	s.opMu.Lock()
	if s.operations == nil {
		s.operations = map[string]*operation{}
	}
	for k, op := range s.operations {
		if op.state != "running" && time.Since(op.created) > operationTTL {
			delete(s.operations, k)
		}
	}
	if op := s.operations[key]; op != nil {
		if op.digest != digest {
			s.opMu.Unlock()
			writeErr(w, 409, "operationId is already bound to a different request")
			return
		}
		state, status, result := op.state, op.status, append(json.RawMessage(nil), op.result...)
		s.opMu.Unlock()
		if state == "running" {
			writeJSON(w, 202, map[string]any{"ok": true, "pending": true, "state": state, "operationId": body.OperationID})
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(status)
		_, _ = w.Write(result)
		return
	}
	if len(s.operations) >= maxOperations {
		s.opMu.Unlock()
		writeErr(w, 429, "操作记录暂满，请等待记录过期后再执行。不要更换 ID 重试已有操作。")
		return
	}
	op := &operation{digest: digest, created: time.Now(), state: "running"}
	s.operations[key] = op
	s.opMu.Unlock()
	defer func() {
		if p := recover(); p != nil {
			s.opMu.Lock()
			op.state, op.status = "unknown", http.StatusInternalServerError
			op.result = json.RawMessage(`{"ok":false,"error":"操作中断，执行结果未知；请核验远端状态，不要重放。"}`)
			s.opMu.Unlock()
			panic(p)
		}
	}()
	rec := &operationWriter{header: make(http.Header)}
	run(rec)
	if rec.status == 0 {
		rec.status = http.StatusOK
	}
	s.opMu.Lock()
	if rec.status == http.StatusConflict {
		delete(s.operations, key)
	} else {
		op.state = "complete"
		if r.Context().Err() != nil {
			op.state = "unknown"
		}
		op.status = rec.status
		op.result = append(json.RawMessage(nil), rec.Bytes()...)
	}
	s.opMu.Unlock()
	for k, v := range rec.header {
		w.Header()[k] = v
	}
	w.WriteHeader(rec.status)
	_, _ = w.Write(rec.Bytes())
}

func (s *service) operationAPI(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.sessionCSRF(r); !ok {
		writeErr(w, 403, "ui session required")
		return
	}
	s.opMu.Lock()
	op := s.operations[sessionID(r)+":"+r.PathValue("id")]
	if op == nil || (op.state != "running" && time.Since(op.created) > operationTTL) {
		s.opMu.Unlock()
		writeErr(w, 404, "找不到操作记录，执行结果未知。请核验远端状态，不要自动重放。")
		return
	}
	state, status, result := op.state, op.status, append(json.RawMessage(nil), op.result...)
	s.opMu.Unlock()
	writeJSON(w, 200, map[string]any{"ok": true, "operationId": r.PathValue("id"), "state": state, "httpStatus": status, "result": result})
}
