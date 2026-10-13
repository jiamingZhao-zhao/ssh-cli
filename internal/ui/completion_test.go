package ui

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/config"
)

func mutationRequest() *http.Request {
	r := httptest.NewRequest("POST", "http://localhost/api/exec", strings.NewReader(`{}`))
	r.RemoteAddr = "127.0.0.1:1234"
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set(csrfHeader, "csrf")
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: "sid"})
	return r
}

func TestSessionExpiredRejectedBeforeDispatch(t *testing.T) {
	s := &service{dir: t.TempDir(), sessions: map[string]string{}}
	called := false
	rr := httptest.NewRecorder()
	s.guard(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true })).ServeHTTP(rr, mutationRequest())
	if called || rr.Code != 403 || rr.Header().Get("X-SSH-CLI-Session-Expired") != "1" {
		t.Fatalf("dispatched expired session: %d", rr.Code)
	}
}

func TestAuditPreflightStopsDispatch(t *testing.T) {
	dir := t.TempDir()
	if err := config.Save(dir, &config.Config{Version: 1, Audit: &config.AuditSettings{RequireWritable: true}}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "audit"), []byte("synthetic blockage"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := &service{dir: dir, sessions: map[string]string{"sid": "csrf"}}
	called := false
	rr := httptest.NewRecorder()
	s.guard(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true })).ServeHTTP(rr, mutationRequest())
	if called || rr.Code != 503 || !strings.Contains(rr.Body.String(), "not_started") {
		t.Fatalf("dispatched without audit: %d %s", rr.Code, rr.Body.String())
	}
}

func TestTransferAdmissionAndMalformedControls(t *testing.T) {
	s := &service{}
	for i := 0; i < 2; i++ {
		if !s.beginTransfer(httptest.NewRecorder()) {
			t.Fatal("early rejection")
		}
	}
	rr := httptest.NewRecorder()
	if s.beginTransfer(rr) || rr.Code != 429 {
		t.Fatal("unbounded transfer admission")
	}
	s.endTransfer()
	if !s.beginTransfer(httptest.NewRecorder()) {
		t.Fatal("slot was not released")
	}
	s.endTransfer()
	s.endTransfer()
	for _, frame := range []string{`{"type":"resize","cols":"bad"}`, `{"type":"resize","rows":-1}`} {
		cols, rows, control := parseResize([]byte(frame))
		if !control || cols != 0 || rows != 0 {
			t.Fatal("malformed resize reached shell")
		}
	}
}
