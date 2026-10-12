package ui

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAuditExportKeepsNewestPast2000(t *testing.T) {
	dir := t.TempDir()
	day := time.Date(2026, 10, 12, 0, 0, 1, 0, time.UTC)
	auditDir := filepath.Join(dir, "audit")
	if err := os.MkdirAll(auditDir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(auditDir, day.Format("2006-01-02")+".jsonl")
	var b strings.Builder
	const n = 2001
	for i := 0; i < n; i++ {
		stamp := day.Add(time.Duration(i) * time.Second).Format(time.RFC3339Nano)
		fmt.Fprintf(&b, `{"id":"%s","time":"%s","op":"exec","host":"box","status":"ok","command":"cmd-%04d","source":"cli"}`+"\n", stamp, stamp, i)
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	h := Handler(dir, false)
	req := httptest.NewRequest(http.MethodGet, "/api/audit/export", nil)
	req.RemoteAddr = "127.0.0.1:9"
	req.Host = "127.0.0.1"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("export %d %s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	if !strings.Contains(body, "cmd-0000") || !strings.Contains(body, "cmd-2000") {
		t.Fatalf("export dropped an endpoint row, len=%d", len(body))
	}
	lines := strings.Split(strings.TrimRight(body, "\n"), "\n")
	if len(lines) != n+1 {
		t.Fatalf("csv lines %d, want %d", len(lines), n+1)
	}
}
