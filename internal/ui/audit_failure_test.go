package ui

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/audit"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/config"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/sshtest"
)

func TestAuditFailureDoesNotChangeRemoteResult(t *testing.T) {
	srv, err := sshtest.Start("tester", "audit-test-secret", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	host, port, err := net.SplitHostPort(srv.Addr)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	s := newService(dir, false, "")
	t.Cleanup(s.pool.Shutdown)
	post := func(handler http.HandlerFunc, body any) *httptest.ResponseRecorder {
		t.Helper()
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest("POST", "/api/exec", strings.NewReader(string(raw)))
		rr := httptest.NewRecorder()
		handler(rr, r)
		return rr
	}
	if rr := post(s.addGroup, map[string]string{"name": "sandbox", "env": "dev"}); rr.Code != 200 {
		t.Fatal(rr.Body.String())
	}
	if rr := post(s.addHost, map[string]any{"alias": "box", "group": "sandbox", "host": host, "port": json.Number(port), "user": "tester", "password": "audit-test-secret"}); rr.Code != 200 {
		t.Fatal(rr.Body.String())
	}
	// A file where the audit directory should be fails on Windows and Unix,
	// including privileged test users; permission-bit tricks do not.
	if err := os.WriteFile(filepath.Join(dir, audit.DirName), []byte("blocker"), 0600); err != nil {
		t.Fatal(err)
	}
	s.sessions["first"] = "csrf"
	body := execIn{Alias: "box", Command: "echo audit-result", OperationID: "0123456789abcdef"}
	raw, _ := json.Marshal(body)
	r := httptest.NewRequest("POST", "/api/exec", strings.NewReader(string(raw)))
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: "first"})
	rr := httptest.NewRecorder()
	s.execAPI(rr, r)
	var result map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if rr.Code != 200 || result["outcome"] != "completed" || result["exitCode"] != float64(0) || result["auditWarning"] != "failed" || !strings.Contains(result["stdout"].(string), "audit-result") {
		t.Fatalf("remote success lost: %d %s", rr.Code, rr.Body.String())
	}
	r.SetPathValue("id", body.OperationID)
	rr = httptest.NewRecorder()
	s.operationAPI(rr, r)
	if !strings.Contains(rr.Body.String(), `"auditWarning":"failed"`) {
		t.Fatal("query lost audit warning")
	}
	if rr := post(s.updateGroup, map[string]any{"name": "sandbox", "deny": []string{"echo blocked"}}); rr.Code != 200 {
		t.Fatal(rr.Body.String())
	}
	rr = post(s.execAPI, execIn{Alias: "box", Command: "echo blocked"})
	if rr.Code != 403 || !strings.Contains(rr.Body.String(), `"outcome":"not_started"`) || !strings.Contains(rr.Body.String(), `"auditWarning":"failed"`) {
		t.Fatalf("audit failure bypassed denial: %d %s", rr.Code, rr.Body.String())
	}
	// Invalid names are rejected before touching the remote filesystem.
	rr = post(s.fileChangeAPI, map[string]string{"alias": "box", "op": "touch", "path": "/tmp", "name": "bad/name"})
	if rr.Code != 400 || !strings.Contains(rr.Body.String(), `"outcome":"not_started"`) {
		t.Fatalf("validation %d %s", rr.Code, rr.Body.String())
	}
	// The fixture uses the OS filesystem as its SFTP root. Unix paths let this
	// test exercise a real mutation without simulating Windows remote paths.
	if runtime.GOOS != "windows" {
		parent := t.TempDir()
		rr = post(s.fileChangeAPI, map[string]string{"alias": "box", "op": "touch", "path": parent, "name": "created.txt"})
		want := filepath.Join(parent, "created.txt")
		if err := json.Unmarshal(rr.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if rr.Code != 200 || result["outcome"] != "completed" || result["path"] != want || result["auditWarning"] != "failed" {
			t.Fatalf("file success lost: %d %s", rr.Code, rr.Body.String())
		}
		if _, err := os.Stat(want); err != nil {
			t.Fatal(err)
		}
	}
}

func TestAuditFailureSurvivesStreamingAndPoolClose(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, audit.DirName), []byte("blocker"), 0600); err != nil {
		t.Fatal(err)
	}
	s := &service{dir: dir, sessions: map[string]string{}}
	rr := httptest.NewRecorder()
	sink := newProgressSink(rr, true)
	sink.report(1, 1) // Response headers have already been sent.
	s.writeAudit(rr, config.ResolvedHost{Alias: "box"}, audit.OpUpload, "upload", "", "/tmp/a", audit.StatusOK, 0, "done", "", false, time.Now())
	sink.ok(map[string]any{"ok": true})
	if !strings.Contains(rr.Body.String(), `"auditWarning":"failed"`) || !strings.Contains(rr.Body.String(), `"ok":true`) {
		t.Fatalf("stream warning missing: %s", rr.Body.String())
	}
	s.onSessionClose("box", "idle")
	r := httptest.NewRequest("GET", "/api/session", nil)
	r.Host = "127.0.0.1"
	r.RemoteAddr = "127.0.0.1:1"
	rr = httptest.NewRecorder()
	s.guard(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, 200, map[string]any{"ok": true})
	})).ServeHTTP(rr, r)
	if rr.Result().Header.Get(auditWarningHeader) != "failed" {
		t.Fatalf("pool close failure disappeared: %d %s", rr.Code, rr.Body.String())
	}
}
