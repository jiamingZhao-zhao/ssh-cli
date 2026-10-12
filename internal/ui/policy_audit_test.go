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

	"github.com/jiamingZhao-zhao/ssh-cli/internal/sshtest"
)

func TestForgedBrowserCannotSkipWritePolicy(t *testing.T) {
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
	if rr := post("/api/envs", `{"name":"locked","label":"锁定","maxMode":"readonly","defaultPolicy":"readonly","noDataOutflow":true}`); rr.Code != 200 {
		t.Fatalf("env %d %s", rr.Code, rr.Body.String())
	}
	if rr := post("/api/groups", `{"name":"vault","env":"locked"}`); rr.Code != 200 {
		t.Fatalf("vault group %d %s", rr.Code, rr.Body.String())
	}
	if rr := post("/api/groups", `{"name":"sandbox","env":"dev"}`); rr.Code != 200 {
		t.Fatalf("dev group %d %s", rr.Code, rr.Body.String())
	}
	add := func(alias, group string) {
		t.Helper()
		body := `{"alias":"` + alias + `","group":"` + group + `","host":"` + host + `","port":` + port + `,"user":"tester","password":"ui-secret"}`
		if rr := post("/api/hosts", body); rr.Code != 200 {
			t.Fatalf("host %s %d %s", alias, rr.Code, rr.Body.String())
		}
	}
	add("locked", "vault")
	add("box", "sandbox")

	forge := func(path, body, contentType string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		req.RemoteAddr = "127.0.0.1:9"
		req.Host = "127.0.0.1"
		req.Header.Set("Origin", "http://127.0.0.1")
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		req.Header.Set("Sec-Fetch-Dest", "empty")
		req.Header.Set("Sec-Fetch-Mode", "cors")
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		attachCSRF(t, h, req)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr
	}

	keep := filepath.Join(t.TempDir(), "keep.txt")
	if err := os.WriteFile(keep, []byte("keep-me"), 0o644); err != nil {
		t.Fatal(err)
	}
	removed := forge("/api/files/change", `{"alias":"locked","op":"remove","path":"`+keep+`","source":"ui"}`, "application/json")
	if removed.Code != http.StatusForbidden {
		t.Fatalf("forged remove %d %s", removed.Code, removed.Body.String())
	}
	if _, err := os.Stat(keep); err != nil {
		t.Fatalf("forged remove deleted the file: %v", err)
	}

	var up bytes.Buffer
	mw := multipart.NewWriter(&up)
	_ = mw.WriteField("alias", "locked")
	_ = mw.WriteField("remote", t.TempDir())
	part, err := mw.CreateFormFile("file", "evil.txt")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = part.Write([]byte("forged"))
	_ = mw.Close()
	upload := forge("/api/upload", up.String(), mw.FormDataContentType())
	if upload.Code != http.StatusForbidden {
		t.Fatalf("forged upload %d %s", upload.Code, upload.Body.String())
	}

	payload := filepath.Join(t.TempDir(), "payload.txt")
	if err := os.WriteFile(payload, []byte("payload-marker"), 0o644); err != nil {
		t.Fatal(err)
	}
	downBody, err := json.Marshal(map[string]string{"alias": "locked", "path": payload, "source": "ui"})
	if err != nil {
		t.Fatal(err)
	}
	down := forge("/api/download", string(downBody), "application/json")
	if down.Code != http.StatusForbidden || strings.Contains(down.Body.String(), "payload-marker") {
		t.Fatalf("forged download %d %s", down.Code, down.Body.String())
	}
	listed := forge("/api/files/list", `{"alias":"locked","path":".","source":"ui"}`, "application/json")
	if listed.Code != http.StatusForbidden {
		t.Fatalf("forged list %d %s", listed.Code, listed.Body.String())
	}

	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := os.WriteFile(filepath.Join(home, ".bash_history"), []byte("marker-line\necho password=ui-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	hist := forge("/api/history", `{"alias":"locked","lines":20,"source":"ui"}`, "application/json")
	if hist.Code != 200 || strings.Contains(hist.Body.String(), "marker-line") || strings.Contains(hist.Body.String(), "ui-secret") || !strings.Contains(hist.Body.String(), `"suppressed":true`) {
		t.Fatalf("history noDataOut %d %s", hist.Code, hist.Body.String())
	}
	need := forge("/api/history", `{"alias":"locked","allowOutflow":true,"source":"ui"}`, "application/json")
	if need.Code != http.StatusConflict || strings.Contains(need.Body.String(), "marker-line") || strings.Contains(need.Body.String(), "ui-secret") {
		t.Fatalf("history confirm %d %s", need.Code, need.Body.String())
	}
	shown := forge("/api/history", `{"alias":"locked","allowOutflow":true,"outflowConfirm":"outflow","source":"ui"}`, "application/json")
	if shown.Code != 200 || !strings.Contains(shown.Body.String(), "marker-line") || strings.Contains(shown.Body.String(), "ui-secret") || strings.Contains(shown.Body.String(), `"suppressed":true`) {
		t.Fatalf("history outflow %d %s", shown.Code, shown.Body.String())
	}

	parent := t.TempDir()
	made := forge("/api/files/change", `{"alias":"box","op":"mkdir","path":"`+parent+`","name":"made"}`, "application/json")
	if made.Code != 200 {
		t.Fatalf("dev mkdir %d %s", made.Code, made.Body.String())
	}
	if st, err := os.Stat(filepath.Join(parent, "made")); err != nil || !st.IsDir() {
		t.Fatalf("mkdir result %v", err)
	}
	var okUp bytes.Buffer
	ow := multipart.NewWriter(&okUp)
	_ = ow.WriteField("alias", "box")
	remote := filepath.Join(t.TempDir(), "up.txt")
	_ = ow.WriteField("remote", remote)
	part, err = ow.CreateFormFile("file", "up.txt")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = part.Write([]byte("uploaded-marker"))
	_ = ow.Close()
	okUpload := forge("/api/upload", okUp.String(), ow.FormDataContentType())
	if okUpload.Code != 200 {
		t.Fatalf("dev upload %d %s", okUpload.Code, okUpload.Body.String())
	}
	saveDir := t.TempDir()
	okDownBody, err := json.Marshal(map[string]string{"alias": "box", "path": remote, "local": saveDir})
	if err != nil {
		t.Fatal(err)
	}
	okDown := forge("/api/download", string(okDownBody), "application/json")
	if okDown.Code != 200 || bytes.Contains(okDown.Body.Bytes(), []byte("uploaded-marker")) {
		t.Fatalf("dev download %d %q", okDown.Code, okDown.Body.String())
	}
	savedBytes, err := os.ReadFile(filepath.Join(saveDir, "up.txt"))
	if err != nil || string(savedBytes) != "uploaded-marker" {
		t.Fatalf("dev download file %q %v", savedBytes, err)
	}

	logged := auditText(t, dir)
	for _, op := range []string{"policy_check", "history", "file_change", "upload", "download"} {
		if !strings.Contains(logged, `"op":"`+op+`"`) {
			t.Fatalf("missing op %s\n%s", op, logged)
		}
	}
	if !strings.Contains(logged, `"source":"ui"`) || strings.Contains(logged, "ui-secret") || strings.Contains(logged, "marker-line") {
		t.Fatalf("ui audit\n%s", logged)
	}
}

func TestAllowRemoteDisablesProbeExemption(t *testing.T) {
	dir := t.TempDir()
	local := Handler(dir, false)
	post := func(path, body string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		req.RemoteAddr = "127.0.0.1:9"
		req.Host = "127.0.0.1"
		req.Header.Set("Content-Type", "application/json")
		attachCSRF(t, local, req)
		rr := httptest.NewRecorder()
		local.ServeHTTP(rr, req)
		return rr
	}
	if rr := post("/api/groups", `{"name":"sandbox","env":"dev"}`); rr.Code != 200 {
		t.Fatalf("group %d %s", rr.Code, rr.Body.String())
	}
	if rr := post("/api/hosts", `{"alias":"box","group":"sandbox","host":"127.0.0.1","port":1,"user":"tester","password":"x"}`); rr.Code != 200 {
		t.Fatalf("host %d %s", rr.Code, rr.Body.String())
	}
	if rr := post("/api/policies", `{"name":"tight","mode":"readonly","allow":["uptime"]}`); rr.Code != 200 {
		t.Fatalf("policy %d %s", rr.Code, rr.Body.String())
	}
	if rr := post("/api/groups/update", `{"name":"sandbox","policy":"tight"}`); rr.Code != 200 {
		t.Fatalf("group policy %d %s", rr.Code, rr.Body.String())
	}

	exposed := HandlerBearer(dir, true, "test-token")
	req := httptest.NewRequest(http.MethodPost, "/api/history", strings.NewReader(`{"alias":"box","source":"ui"}`))
	req.RemoteAddr = "127.0.0.1:9"
	req.Host = "127.0.0.1"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "http://127.0.0.1")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Authorization", "Bearer test-token")
	attachCSRFBearer(t, exposed, req, "test-token")
	rr := httptest.NewRecorder()
	exposed.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("exposed history %d %s", rr.Code, rr.Body.String())
	}
	list := httptest.NewRequest(http.MethodPost, "/api/files/list", strings.NewReader(`{"alias":"box","path":".","source":"ui"}`))
	list.RemoteAddr = "127.0.0.1:9"
	list.Host = "127.0.0.1"
	list.Header.Set("Content-Type", "application/json")
	list.Header.Set("Origin", "http://127.0.0.1")
	list.Header.Set("Sec-Fetch-Site", "same-origin")
	list.Header.Set("Sec-Fetch-Dest", "empty")
	list.Header.Set("Sec-Fetch-Mode", "cors")
	list.Header.Set("Authorization", "Bearer test-token")
	attachCSRFBearer(t, exposed, list, "test-token")
	lr := httptest.NewRecorder()
	exposed.ServeHTTP(lr, list)
	if lr.Code != http.StatusForbidden {
		t.Fatalf("exposed list %d %s", lr.Code, lr.Body.String())
	}
	logged := auditText(t, dir)
	if !strings.Contains(logged, `"source":"ui"`) || !strings.Contains(logged, `"op":"policy_check"`) {
		t.Fatalf("exposed audit\n%s", logged)
	}
}

func attachCSRFBearer(t *testing.T, h http.Handler, req *http.Request, token string) {
	t.Helper()
	useLoopback(req)
	sess := httptest.NewRequest(http.MethodGet, "/api/session", nil)
	sess.Host = req.Host
	sess.RemoteAddr = "127.0.0.1:9"
	sess.Header.Set("Authorization", "Bearer "+token)
	sr := httptest.NewRecorder()
	h.ServeHTTP(sr, sess)
	if sr.Code != http.StatusOK {
		t.Fatalf("session %d %s", sr.Code, sr.Body.String())
	}
	var body struct {
		CSRF string `json:"csrf"`
	}
	if err := json.Unmarshal(sr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	for _, c := range sr.Result().Cookies() {
		if c.Name == sessionCookie {
			req.AddCookie(c)
		}
	}
	req.Header.Set(csrfHeader, body.CSRF)
}
