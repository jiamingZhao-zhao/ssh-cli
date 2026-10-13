package ui

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
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

func TestRevealTarget(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "note.txt")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	spec, err := revealTarget(file)
	if err != nil || !spec.file || spec.path != file || spec.dir != dir {
		t.Fatalf("file %#v %v", spec, err)
	}
	spec, err = revealTarget(dir + string(filepath.Separator))
	if err != nil || spec.file || spec.dir != dir || spec.path != dir {
		t.Fatalf("dir %#v %v", spec, err)
	}
	if _, err := revealTarget("relative/path"); err == nil {
		t.Fatal("relative path accepted")
	}
	if _, err := revealTarget(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("missing path accepted")
	}
}

func TestRevealDownloadAPI(t *testing.T) {
	old := openLocal
	t.Cleanup(func() { openLocal = old })
	h := Handler(t.TempDir(), false)
	dir := t.TempDir()
	file := filepath.Join(dir, "saved.bin")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	var got revealSpec
	openLocal = func(_ context.Context, spec revealSpec) error {
		got = spec
		return nil
	}
	post := func(body, contentType string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/api/download-dir/reveal", strings.NewReader(body))
		req.RemoteAddr = "127.0.0.1:9"
		req.Host = "127.0.0.1"
		req.Header.Set("Content-Type", contentType)
		attachCSRF(t, h, req)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr
	}
	body, err := json.Marshal(map[string]string{"path": file})
	if err != nil {
		t.Fatal(err)
	}
	rr := post(string(body), "application/json")
	var reply struct {
		Path string `json:"path"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &reply); err != nil {
		t.Fatal(err)
	}
	if rr.Code != 200 || !got.file || got.path != file || reply.Path != dir {
		t.Fatalf("reveal %d %s %#v", rr.Code, rr.Body.String(), got)
	}
	rr = post(`{"path":"relative"}`, "application/json")
	if rr.Code == 200 {
		t.Fatalf("relative accepted %s", rr.Body.String())
	}
	rr = post("dir", "text/plain")
	if rr.Code != http.StatusUnsupportedMediaType || !strings.Contains(rr.Body.String(), "mutating requests must use JSON") {
		t.Fatalf("non-json %d %s", rr.Code, rr.Body.String())
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
	dir := filepath.Join(t.TempDir(), "中文 保存目录")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	chooseDownloadDir = func(context.Context) (string, error) { return dir, nil }
	rr := post()
	var reply struct {
		Path string `json:"path"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &reply); err != nil {
		t.Fatal(err)
	}
	if rr.Code != 200 || reply.Path != dir || strings.Contains(rr.Body.String(), `"cancelled":true`) {
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

func TestWindowsPickerUTF8(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("native Windows PowerShell encoding")
	}
	dir := filepath.Join(t.TempDir(), "中文 保存目录")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	script := windowsPickerEncoding + "Write-Output '" + strings.ReplaceAll(dir, "'", "''") + "'"
	got, err := runDirPicker(context.Background(), "powershell", "-NoProfile", "-Command", script)
	if err != nil || got != dir {
		t.Fatalf("unicode path %q, want %q: %v", got, dir, err)
	}
}
