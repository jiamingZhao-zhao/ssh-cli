package ui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCleanPickedDir(t *testing.T) {
	dir := t.TempDir()
	got, err := cleanPickedDir(dir + string(filepath.Separator))
	if err != nil || got != dir {
		t.Fatalf("clean %q err=%v", got, err)
	}
	if _, err := cleanPickedDir("relative/path"); err == nil {
		t.Fatal("relative path accepted")
	}
	file := filepath.Join(dir, "note.txt")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := cleanPickedDir(file); err == nil {
		t.Fatal("file accepted as directory")
	}
	if _, err := cleanPickedDir("  "); err != errPickCancelled {
		t.Fatalf("blank: %v", err)
	}
}

func TestPickDownloadDirAPI(t *testing.T) {
	old := chooseDownloadDir
	t.Cleanup(func() { chooseDownloadDir = old })
	h := Handler(t.TempDir(), false)
	post := func() *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/api/download-dir", strings.NewReader("{}"))
		req.RemoteAddr = "127.0.0.1:9"
		req.Host = "127.0.0.1"
		req.Header.Set("Content-Type", "application/json")
		attachCSRF(t, h, req)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr
	}
	dir := t.TempDir()
	chooseDownloadDir = func(context.Context) (string, error) { return dir, nil }
	rr := post()
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), dir) || strings.Contains(rr.Body.String(), `"cancelled":true`) {
		t.Fatalf("pick %d %s", rr.Code, rr.Body.String())
	}
	chooseDownloadDir = func(context.Context) (string, error) { return "", errPickCancelled }
	rr = post()
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), `"cancelled":true`) {
		t.Fatalf("cancel %d %s", rr.Code, rr.Body.String())
	}
	chooseDownloadDir = func(context.Context) (string, error) { return "not-absolute", nil }
	rr = post()
	if rr.Code == 200 {
		t.Fatalf("relative accepted %s", rr.Body.String())
	}
	bare := httptest.NewRequest(http.MethodPost, "/api/download-dir", strings.NewReader("dir"))
	bare.RemoteAddr = "127.0.0.1:9"
	bare.Host = "127.0.0.1"
	bare.Header.Set("Content-Type", "text/plain")
	attachCSRF(t, h, bare)
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, bare)
	if rr.Code != http.StatusUnsupportedMediaType || !strings.Contains(rr.Body.String(), "mutating requests must use JSON") {
		t.Fatalf("non-json %d %s", rr.Code, rr.Body.String())
	}
}
