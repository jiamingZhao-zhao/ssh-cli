package ui

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestOperationDedupAndIsolation(t *testing.T) {
	s := &service{sessions: map[string]string{"first": "csrf", "second": "csrf"}}
	body := execIn{OperationID: "0123456789abcdef", Alias: "box", Command: "echo once"}
	request := func(sid string) *http.Request {
		r := httptest.NewRequest("POST", "/api/exec", nil)
		r.AddCookie(&http.Cookie{Name: sessionCookie, Value: sid})
		return r
	}
	started, finish, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	run := func(w http.ResponseWriter) {
		calls.Add(1)
		close(started)
		<-finish
		writeJSON(w, 200, map[string]any{"ok": true, "stdout": "once"})
	}
	first := httptest.NewRecorder()
	go func() { defer close(done); s.runOperation(first, request("first"), body, run) }()
	<-started
	rr := httptest.NewRecorder()
	s.runOperation(rr, request("first"), body, run)
	if rr.Code != 202 || calls.Load() != 1 {
		t.Fatalf("duplicate %d calls %d", rr.Code, calls.Load())
	}
	changed := body
	changed.Command = "echo twice"
	rr = httptest.NewRecorder()
	s.runOperation(rr, request("first"), changed, run)
	if rr.Code != 409 {
		t.Fatalf("rebound operation %d", rr.Code)
	}
	close(finish)
	<-done
	rr = httptest.NewRecorder()
	s.runOperation(rr, request("first"), body, run)
	if rr.Code != 200 || rr.Body.String() != first.Body.String() || calls.Load() != 1 {
		t.Fatal("completed operation was replayed")
	}
	query := request("second")
	query.SetPathValue("id", body.OperationID)
	rr = httptest.NewRecorder()
	s.operationAPI(rr, query)
	if rr.Code != 404 {
		t.Fatal("another session read operation output")
	}
	query = request("first")
	query.SetPathValue("id", body.OperationID)
	rr = httptest.NewRecorder()
	s.operationAPI(rr, query)
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), "complete") {
		t.Fatal("missing completed result")
	}
	s.operations["first:"+body.OperationID].created = time.Now().Add(-operationTTL - time.Second)
	rr = httptest.NewRecorder()
	s.operationAPI(rr, query)
	if rr.Code != 404 {
		t.Fatal("expired operation still available")
	}
}

func TestOperationResultBudgetRetainsReplayProtection(t *testing.T) {
	s := &service{sessions: map[string]string{"first": "csrf"}}
	r := httptest.NewRequest("POST", "/api/exec", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: "first"})
	var calls int
	base := time.Now().Add(-time.Minute)
	first := execIn{OperationID: "operation_00000000", Command: "echo once"}
	for i := 0; i < maxOperationResults+2; i++ {
		body := first
		body.OperationID = fmt.Sprintf("operation_%08d", i)
		rr := httptest.NewRecorder()
		s.runOperation(rr, r, body, func(w http.ResponseWriter) {
			calls++
			writeJSON(w, 200, map[string]any{"ok": true, "outcome": "completed", "exitCode": 0})
		})
		if rr.Code != 200 {
			t.Fatalf("operation %d blocked: %d", i, rr.Code)
		}
		s.operations["first:"+body.OperationID].created = base.Add(time.Duration(i) * time.Second)
	}
	results := 0
	for _, op := range s.operations {
		if len(op.result) > 0 {
			results++
		}
	}
	if results != maxOperationResults {
		t.Fatalf("retained %d results", results)
	}
	before := calls
	rr := httptest.NewRecorder()
	s.runOperation(rr, r, first, func(http.ResponseWriter) { calls++ })
	if calls != before || !strings.Contains(rr.Body.String(), `"outcome":"unknown"`) {
		t.Fatal("evicted operation replayed")
	}
	r.SetPathValue("id", first.OperationID)
	rr = httptest.NewRecorder()
	s.operationAPI(rr, r)
	if !strings.Contains(rr.Body.String(), `"state":"unknown"`) {
		t.Fatal("eviction looks complete")
	}
	// Count alone is insufficient: encoded output is bounded by bytes as well.
	s.operations = map[string]*operation{}
	for i := 0; i < 3; i++ {
		s.operations[fmt.Sprint(i)] = &operation{state: "complete", created: time.Now().Add(time.Duration(i) * time.Second), result: make(json.RawMessage, maxOperationBytes/2)}
	}
	s.trimOperationResults()
	if s.operations["0"].result != nil || s.operations["0"].state != "unknown" {
		t.Fatal("byte budget did not evict oldest output")
	}
}

func TestCanceledOperationCannotReplayCompletedLookingPayload(t *testing.T) {
	s := &service{sessions: map[string]string{"first": "csrf"}}
	ctx, cancel := context.WithCancel(context.Background())
	r := httptest.NewRequest("POST", "/api/exec", nil).WithContext(ctx)
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: "first"})
	body := execIn{OperationID: "0123456789abcdef", Command: "write"}
	s.runOperation(httptest.NewRecorder(), r, body, func(w http.ResponseWriter) {
		cancel()
		writeJSON(w, 200, map[string]any{"ok": true, "outcome": "completed", "exitCode": 0})
	})
	rr := httptest.NewRecorder()
	s.runOperation(rr, r, body, func(http.ResponseWriter) { t.Fatal("canceled write replayed") })
	if rr.Code != 500 || strings.Contains(rr.Body.String(), `"outcome":"completed"`) {
		t.Fatal("unknown operation looked safe to repeat")
	}
}

func TestPreviewDoesNotDialAndInvalidatesChangedPlan(t *testing.T) {
	dir := t.TempDir()
	raw := "groups:\n  demo:\n    env: dev\n    hosts:\n      box:\n        host: 127.0.0.1\n        port: 1\n        user: demo\n        auth: key\n        identity: /missing-synthetic-key\n"
	if err := os.WriteFile(filepath.Join(dir, "hosts.yaml"), []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	s := newService(dir, false, "")
	body := execIn{Aliases: []string{"box"}, Command: "echo preview"}
	b, _ := json.Marshal(body)
	rr := httptest.NewRecorder()
	s.execPreviewAPI(rr, httptest.NewRequest("POST", "/api/exec/preview", strings.NewReader(string(b))))
	var preview struct {
		PlanDigest string `json:"planDigest"`
		CanExecute bool   `json:"canExecute"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &preview); err != nil || rr.Code != 200 || !preview.CanExecute || preview.PlanDigest == "" {
		t.Fatalf("preview %d %s", rr.Code, rr.Body.String())
	}
	body.PlanDigest = preview.PlanDigest
	if !s.checkPlan(httptest.NewRecorder(), body) {
		t.Fatal("unchanged plan refused")
	}
	body.Command = "echo changed"
	rr = httptest.NewRecorder()
	if s.checkPlan(rr, body) || rr.Code != 409 {
		t.Fatal("changed command accepted")
	}
	body.Command = "echo preview"
	if err := os.WriteFile(filepath.Join(dir, "hosts.yaml"), []byte(strings.Replace(raw, "port: 1", "port: 2", 1)), 0600); err != nil {
		t.Fatal(err)
	}
	rr = httptest.NewRecorder()
	if s.checkPlan(rr, body) || rr.Code != 409 {
		t.Fatal("changed destination accepted")
	}
	hit := s.execOne(context.Background(), execIn{Alias: "box", previewRequest: &body}, false)
	if hit.status != 409 {
		t.Fatalf("execution bypassed changed preview: %d", hit.status)
	}
}

func TestInterruptedOperationIsUnknownAndNotReplayed(t *testing.T) {
	s := &service{sessions: map[string]string{"first": "csrf"}}
	r := httptest.NewRequest("POST", "/api/exec", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: "first"})
	body := execIn{OperationID: "0123456789abcdef", Command: "write"}
	func() {
		defer func() { _ = recover() }()
		s.runOperation(httptest.NewRecorder(), r, body, func(http.ResponseWriter) { panic("interrupted") })
	}()
	rr := httptest.NewRecorder()
	s.runOperation(rr, r, body, func(http.ResponseWriter) { t.Fatal("interrupted write replayed") })
	if rr.Code != 500 {
		t.Fatalf("lost interruption state: %d", rr.Code)
	}
	r.SetPathValue("id", body.OperationID)
	rr = httptest.NewRecorder()
	s.operationAPI(rr, r)
	if !strings.Contains(rr.Body.String(), `"state":"unknown"`) {
		t.Fatal("interruption reported complete")
	}
}
