package ui

import (
	"encoding/json"
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

func TestWorkspaceChrome(t *testing.T) {
	dir := t.TempDir()
	h := Handler(dir, false)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:9"
	req.Host = "127.0.0.1"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("page %d", rr.Code)
	}
	body := rr.Body.String()
	start := strings.Index(body, `class="ws"`)
	if start < 0 {
		t.Fatal("terminal view missing")
	}
	rest := body[start:]
	end := strings.Index(rest, `data-view="hosts"`)
	if end < 0 {
		t.Fatal("hosts view missing")
	}
	chunk := rest[:end]
	for _, s := range []string{
		`data-pane="overview"`,
		`data-pane="terminal"`,
		`data-pane="files"`,
		`data-pane="history"`,
		"文件",
		"历史",
		"beginSplit",
		"ws-overview",
		"CPU",
		"内存",
		"ws-download-lane",
		"拖到这里下载到本机",
		"复制路径",
		"ws-via",
	} {
		if !strings.Contains(chunk, s) {
			t.Fatalf("workspace missing %s", s)
		}
	}
	if strings.Contains(chunk, ">命令<") || strings.Contains(chunk, `data-pane="commands"`) {
		t.Fatal("command tab is out of scope")
	}
	jsReq := httptest.NewRequest(http.MethodGet, "/app.js", nil)
	jsReq.RemoteAddr = "127.0.0.1:9"
	jsReq.Host = "127.0.0.1"
	jsRR := httptest.NewRecorder()
	h.ServeHTTP(jsRR, jsReq)
	script := jsRR.Body.String()
	for _, s := range []string{"refreshFiles", "loadHistory", "refreshMetrics", "beginSplit", "wsDownload", "wsUpload", "wsSide", "enqueueUploads", "cancelTransfer", "abortRead", "postRead", "互相绕回去", "先添加那台跳板并保存"} {
		if !strings.Contains(script, s) {
			t.Fatalf("app.js missing %s", s)
		}
	}
}

func TestWorkspaceListHistoryMetrics(t *testing.T) {
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
	if rr := post("/api/groups", `{"name":"sandbox","env":"dev"}`); rr.Code != 200 {
		t.Fatalf("group %d %s", rr.Code, rr.Body.String())
	}
	add := `{"alias":"box","group":"sandbox","host":"` + host + `","port":` + port + `,"user":"tester","password":"ui-secret"}`
	if rr := post("/api/hosts", add); rr.Code != 200 {
		t.Fatalf("host %d %s", rr.Code, rr.Body.String())
	}

	listDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(listDir, "note.txt"), []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}
	rr := post("/api/files/list", `{"alias":"box","path":"`+listDir+`","source":"cli"}`)
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), "note.txt") {
		t.Fatalf("list %d %s", rr.Code, rr.Body.String())
	}
	miss := post("/api/files/list", `{"alias":"box","path":"`+filepath.Join(listDir, "nope")+`"}`)
	if miss.Code == 200 {
		t.Fatalf("missing list %s", miss.Body.String())
	}

	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := os.WriteFile(filepath.Join(home, ".bash_history"), []byte("echo password=ui-secret\nuptime\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rr = post("/api/history", `{"alias":"box","lines":20,"source":"cli"}`)
	if rr.Code != 200 {
		t.Fatalf("history %d %s", rr.Code, rr.Body.String())
	}
	var hist struct {
		Found  bool     `json:"found"`
		Lines  []string `json:"lines"`
		Source string   `json:"source"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &hist); err != nil {
		t.Fatal(err)
	}
	if !hist.Found || hist.Source != "" || strings.Contains(strings.Join(hist.Lines, "\n"), "ui-secret") {
		t.Fatalf("history body %#v", hist)
	}
	text := readAuditMaybe(t, dir)
	if strings.Contains(text, `"op":"history"`) || strings.Contains(text, `"op":"list"`) || strings.Contains(text, `"op":"metrics"`) || strings.Contains(text, "ui-secret") {
		t.Fatalf("workspace must not write file/history/metrics audit\n%s", text)
	}

	if closed := post("/api/sessions/close", `{"alias":"box"}`); closed.Code != 200 {
		t.Fatalf("close %d %s", closed.Code, closed.Body.String())
	}
	empty := t.TempDir()
	t.Setenv("HOME", empty)
	rr = post("/api/history", `{"alias":"box","source":"ui"}`)
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), `"found":false`) || !strings.Contains(rr.Body.String(), `"status":"empty"`) {
		t.Fatalf("empty history %d %s", rr.Code, rr.Body.String())
	}

	metrics := post("/api/metrics", `{"alias":"box","source":"cli"}`)
	if metrics.Code != 200 || !strings.Contains(metrics.Body.String(), `"connected":true`) {
		t.Fatalf("metrics %d %s", metrics.Code, metrics.Body.String())
	}
	text = readAuditMaybe(t, dir)
	if strings.Contains(text, `"op":"metrics"`) {
		t.Fatalf("metrics audit\n%s", text)
	}

	if rr := post("/api/policies", `{"name":"tight","mode":"readonly","allow":["uptime"]}`); rr.Code != 200 {
		t.Fatalf("policy %d %s", rr.Code, rr.Body.String())
	}
	if rr := post("/api/groups/update", `{"name":"sandbox","policy":"tight"}`); rr.Code != 200 {
		t.Fatalf("group %d %s", rr.Code, rr.Body.String())
	}
	denied := post("/api/history", `{"alias":"box","source":"ui"}`)
	if denied.Code != http.StatusForbidden {
		t.Fatalf("forged source did not keep policy %d %s", denied.Code, denied.Body.String())
	}
	deniedList := post("/api/files/list", `{"alias":"box","path":".","source":"ui"}`)
	if deniedList.Code != http.StatusForbidden {
		t.Fatalf("list policy %d %s", deniedList.Code, deniedList.Body.String())
	}
	browser := func(path, body string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		req.RemoteAddr = "127.0.0.1:9"
		req.Host = "127.0.0.1"
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", "http://127.0.0.1")
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		req.Header.Set("Sec-Fetch-Dest", "empty")
		req.Header.Set("Sec-Fetch-Mode", "cors")
		attachCSRF(t, h, req)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr
	}
	allowed := browser("/api/history", `{"alias":"box","source":"cli"}`)
	if allowed.Code != 200 {
		t.Fatalf("browser history should skip policy %d %s", allowed.Code, allowed.Body.String())
	}
	text = readAuditMaybe(t, dir)
	if strings.Contains(text, `"op":"history"`) {
		t.Fatalf("browser history audited\n%s", text)
	}
}
