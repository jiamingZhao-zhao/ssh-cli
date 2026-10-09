package ui

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/audit"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/sshtest"
)

func TestUIExecUploadDownload(t *testing.T) {
	srv, err := sshtest.Start("tester", "ui-secret", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		done := make(chan struct{})
		go func() {
			srv.Close()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
	})
	host, port, err := net.SplitHostPort(srv.Addr)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	h := Handler(dir, false)
	post := func(path, body string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		req.RemoteAddr = "127.0.0.1:9"
		req.Host = "127.0.0.1"
		req.Header.Set("Content-Type", "application/json")
		attachCSRF(t, h, req)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr
	}
	if rr := post("/api/groups", `{"name":"sandbox","env":"dev","label":"显示名"}`); rr.Code != 200 {
		t.Fatalf("group %d %s", rr.Code, rr.Body.String())
	}
	add := `{"alias":"box","group":"sandbox","host":"` + host + `","port":` + port + `,"user":"tester","password":"ui-secret"}`
	if rr := post("/api/hosts", add); rr.Code != 200 {
		t.Fatalf("host %d %s", rr.Code, rr.Body.String())
	}
	rr := post("/api/exec", `{"alias":"box","command":"echo hi"}`)
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), "hi") {
		t.Fatalf("exec %d %s", rr.Code, rr.Body.String())
	}
	text := auditText(t, dir)
	if !strings.Contains(text, `"actor":"ui"`) || !strings.Contains(text, `"op":"exec"`) || strings.Contains(text, "ui-secret") {
		t.Fatalf("audit\n%s", text)
	}

	remote := filepath.Join(t.TempDir(), "up.txt")
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	_ = w.WriteField("alias", "box")
	_ = w.WriteField("remote", remote)
	part, err := w.CreateFormFile("file", "up.txt")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = part.Write([]byte("uploaded"))
	_ = w.Close()
	req := httptest.NewRequest(http.MethodPost, "/api/upload", &buf)
	req.RemoteAddr = "127.0.0.1:9"
	req.Host = "127.0.0.1"
	req.Header.Set("Content-Type", w.FormDataContentType())
	attachCSRF(t, h, req)
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("upload %d %s", rr.Code, rr.Body.String())
	}
	got, err := os.ReadFile(remote)
	if err != nil || string(got) != "uploaded" {
		t.Fatalf("uploaded %q %v", got, err)
	}
	destDir := t.TempDir()
	var dirBuf bytes.Buffer
	dw := multipart.NewWriter(&dirBuf)
	_ = dw.WriteField("alias", "box")
	_ = dw.WriteField("remote", destDir)
	part, err = dw.CreateFormFile("file", "original.txt")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = part.Write([]byte("named"))
	_ = dw.Close()
	req = httptest.NewRequest(http.MethodPost, "/api/upload", &dirBuf)
	req.RemoteAddr = "127.0.0.1:9"
	req.Host = "127.0.0.1"
	req.Header.Set("Content-Type", dw.FormDataContentType())
	attachCSRF(t, h, req)
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("dir upload %d %s", rr.Code, rr.Body.String())
	}
	named, err := os.ReadFile(filepath.Join(destDir, "original.txt"))
	if err != nil || string(named) != "named" {
		entries, _ := os.ReadDir(destDir)
		t.Fatalf("kept name %q %v entries %v", named, err, entries)
	}

	body, err := json.Marshal(map[string]string{"alias": "box", "path": remote})
	if err != nil {
		t.Fatal(err)
	}
	rr = post("/api/download", string(body))
	if rr.Code != 200 || !bytes.Contains(rr.Body.Bytes(), []byte("uploaded")) {
		t.Fatalf("download %d %q", rr.Code, rr.Body.String())
	}

	rr = post("/api/exec", `{"alias":"box","command":"rm -rf /"}`)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("deny %d %s", rr.Code, rr.Body.String())
	}

	exp := httptest.NewRequest(http.MethodGet, "/api/config/export", nil)
	exp.RemoteAddr = "127.0.0.1:9"
	exp.Host = "127.0.0.1"
	useLoopback(exp)
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, exp)
	if rr.Code != 200 || strings.Contains(rr.Body.String(), "ui-secret") || !strings.Contains(rr.Body.String(), "passwordRef") {
		t.Fatalf("export %d %s", rr.Code, rr.Body.String())
	}
	var doc struct {
		YAML string `json:"yaml"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	imp := post("/api/config/import", `{"yaml":`+mustJSON(t, doc.YAML)+`}`)
	if imp.Code != 200 {
		t.Fatalf("import %d %s", imp.Code, imp.Body.String())
	}
}

func mustJSON(t *testing.T, s string) string {
	t.Helper()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func auditText(t *testing.T, dir string) string {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(dir, "audit", "*.jsonl"))
	if err != nil || len(matches) == 0 {
		t.Fatalf("audit %v %v", matches, err)
	}
	b, err := os.ReadFile(matches[len(matches)-1])
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestUIImportAndSessionIdentity(t *testing.T) {
	a, err := sshtest.Start("tester", "ui-secret", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	b, err := sshtest.Start("tester", "ui-secret", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Close)
	ah, ap, err := net.SplitHostPort(a.Addr)
	if err != nil {
		t.Fatal(err)
	}
	_, bp, err := net.SplitHostPort(b.Addr)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	h := Handler(dir, false)
	t.Cleanup(func() {
		req := httptest.NewRequest(http.MethodPost, "/api/session/close", strings.NewReader(`{"alias":"box"}`))
		req.RemoteAddr = "127.0.0.1:9"
		req.Host = "127.0.0.1"
		req.Header.Set("Content-Type", "application/json")
		attachCSRF(t, h, req)
		h.ServeHTTP(httptest.NewRecorder(), req)
	})
	post := func(path, body string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		req.RemoteAddr = "127.0.0.1:9"
		req.Host = "127.0.0.1"
		req.Header.Set("Content-Type", "application/json")
		attachCSRF(t, h, req)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr
	}
	if rr := post("/api/groups", `{"name":"app","env":"prod"}`); rr.Code != 200 {
		t.Fatalf("group %d %s", rr.Code, rr.Body.String())
	}
	exp := httptest.NewRequest(http.MethodGet, "/api/config/export", nil)
	exp.RemoteAddr = "127.0.0.1:9"
	exp.Host = "127.0.0.1"
	useLoopback(exp)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, exp)
	var doc struct {
		YAML string `json:"yaml"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	weaker := strings.Replace(doc.YAML, "env: prod", "env: dev", 1)
	denied := post("/api/config/import", `{"yaml":`+mustJSON(t, weaker)+`}`)
	if denied.Code != http.StatusConflict || !strings.Contains(denied.Body.String(), `"confirm":"prod"`) {
		t.Fatalf("import confirm %d %s", denied.Code, denied.Body.String())
	}
	raw, err := os.ReadFile(filepath.Join(dir, "hosts.yaml"))
	if err != nil || !strings.Contains(string(raw), "env: prod") {
		t.Fatalf("committed without confirm\n%s", raw)
	}
	ok := post("/api/config/import", `{"humanConfirm":"prod","yaml":`+mustJSON(t, weaker)+`}`)
	if ok.Code != 200 {
		t.Fatalf("confirmed import %d %s", ok.Code, ok.Body.String())
	}

	if rr := post("/api/groups", `{"name":"sandbox","env":"dev"}`); rr.Code != 200 {
		t.Fatalf("sandbox %d %s", rr.Code, rr.Body.String())
	}
	add := `{"alias":"box","group":"sandbox","host":"` + ah + `","port":` + ap + `,"user":"tester","password":"ui-secret"}`
	if rr := post("/api/hosts", add); rr.Code != 200 {
		t.Fatalf("host %d %s", rr.Code, rr.Body.String())
	}
	if rr := post("/api/exec", `{"alias":"box","command":"X=from-a"}`); rr.Code != 200 {
		t.Fatalf("set %d %s", rr.Code, rr.Body.String())
	}
	if rr := post("/api/hosts/update", `{"alias":"box","port":`+bp+`}`); rr.Code != 200 {
		t.Fatalf("port %d %s", rr.Code, rr.Body.String())
	}
	rr = post("/api/exec", `{"alias":"box","command":"printf %s \"$X\""}`)
	if rr.Code != 200 {
		t.Fatalf("echo %d %s", rr.Code, rr.Body.String())
	}
	var body struct {
		Stdout string `json:"stdout"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(body.Stdout, "from-a") {
		t.Fatalf("reused old ssh session %q", body.Stdout)
	}
}

func TestUIPageStillMentionsDanger(t *testing.T) {
	h := Handler(t.TempDir(), false)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:9"
	req.Host = "127.0.0.1"
	useLoopback(req)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	body := rr.Body.String()
	for _, s := range []string{"标签只写在主机上", "危险命令", "已知主机密钥", "显示名"} {
		if !strings.Contains(body, s) {
			t.Fatalf("missing %s", s)
		}
	}
	if _, err := audit.Stat(t.TempDir()); err != nil {
		t.Fatal(err)
	}
}
