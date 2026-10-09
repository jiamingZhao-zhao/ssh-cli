package ui

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/audit"
)

func TestV050PagesAndAPIs(t *testing.T) {
	dir := t.TempDir()
	h := Handler(dir, false)
	get := func(path string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.RemoteAddr = "127.0.0.1:9"
		req.Host = "127.0.0.1"
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr
	}
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

	page := get("/")
	body := page.Body.String()
	for _, s := range []string{"概览", "主机详情", "设置", "批量执行", "导出 CSV", "tabler.min.css", "alpine-csp.min.js"} {
		if !strings.Contains(body, s) {
			t.Fatalf("index missing %s", s)
		}
	}
	script := get("/app.js").Body.String()
	if !strings.Contains(script, "DEFAULT_PAGE_SIZE = 10") || !strings.Contains(script, "/api/exec/batch") || !strings.Contains(script, "host-search") || !strings.Contains(script, "data-bs-theme") || !strings.Contains(script, "table-sm") {
		t.Fatal("app.js missing v0.5 hooks")
	}
	style := get("/app.css").Body.String()
	if strings.Contains(style, ".tabbar") || !strings.Contains(style, "margin: auto") || !strings.Contains(style, "justify-content: flex-end") {
		t.Fatal("app.css missing modal or pager hook")
	}
	if get("/tabler.min.css").Code != 200 || get("/alpine-csp.min.js").Code != 200 {
		t.Fatal("vendored tabler or alpine missing")
	}

	dash := get("/api/dashboard")
	if dash.Code != 200 || !strings.Contains(dash.Body.String(), `"hosts":0`) || !strings.Contains(dash.Body.String(), `"status":"unsigned"`) {
		t.Fatalf("dashboard %d %s", dash.Code, dash.Body.String())
	}
	ops := get("/api/ops")
	if ops.Code != 200 || !strings.Contains(ops.Body.String(), "only entries older than 30 days") {
		t.Fatalf("ops %d %s", ops.Code, ops.Body.String())
	}
	if miss := get("/api/hosts/detail"); miss.Code != http.StatusBadRequest {
		t.Fatalf("detail %d %s", miss.Code, miss.Body.String())
	}

	seedEnvGroup(t, dir)
	password := "s3cret-ui"
	if w := post("/api/hosts", `{"alias":"main","group":"app-prod","host":"192.0.2.10","user":"viewer","password":"`+password+`"}`); w.Code != 200 {
		t.Fatalf("add %d %s", w.Code, w.Body.String())
	}
	detail := get("/api/hosts/detail?alias=main")
	text := detail.Body.String()
	if detail.Code != 200 || !strings.Contains(text, `"alias":"main"`) || !strings.Contains(text, `"mode":"readonly"`) || strings.Contains(text, password) {
		t.Fatalf("detail %d %s", detail.Code, text)
	}
	if _, err := audit.Append(dir, audit.Record{
		Op: audit.OpPolicyCheck, Host: "main", Group: "app-prod", Env: "prod",
		Command: "rm -rf /", Status: audit.StatusDenied, HighRisk: true, DeniedByPolicy: true,
		Reason: "builtin: rm of filesystem root",
	}); err != nil {
		t.Fatal(err)
	}
	csv := get("/api/audit/export?host=main&status=denied")
	if csv.Code != 200 || !strings.Contains(csv.Header().Get("Content-Type"), "text/csv") || !strings.Contains(csv.Body.String(), "rm -rf /") || strings.Contains(csv.Body.String(), password) {
		t.Fatalf("csv %d %s %s", csv.Code, csv.Header().Get("Content-Type"), csv.Body.String())
	}
	home := get("/api/dashboard")
	if !strings.Contains(home.Body.String(), `"hosts":1`) || !strings.Contains(home.Body.String(), "rm -rf /") || strings.Contains(home.Body.String(), password) {
		t.Fatalf("home %s", home.Body.String())
	}
	batch := post("/api/exec/batch", `{"aliases":["main","main"],"command":"rm -rf /","parallel":8}`)
	if batch.Code != http.StatusForbidden || strings.Contains(batch.Body.String(), password) || !strings.Contains(batch.Body.String(), "denied") {
		t.Fatalf("batch %d %s", batch.Code, batch.Body.String())
	}
	unknown := post("/api/exec/batch", `{"aliases":["missing"],"command":"ls"}`)
	if unknown.Code != http.StatusBadRequest {
		t.Fatalf("unknown %d %s", unknown.Code, unknown.Body.String())
	}
	if w := post("/api/settings", `{"idle":"6m","maxLife":"45m"}`); w.Code != 200 {
		t.Fatalf("settings %d %s", w.Code, w.Body.String())
	}
	got := get("/api/settings")
	if !strings.Contains(got.Body.String(), `"idle":"6m0s"`) || !strings.Contains(got.Body.String(), `"maxLife":"45m0s"`) {
		t.Fatalf("settings get %s", got.Body.String())
	}
	yamlBytes, err := os.ReadFile(filepath.Join(dir, "hosts.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(yamlBytes), "idle: 6m") || strings.Contains(string(yamlBytes), password) {
		t.Fatalf("yaml\n%s", yamlBytes)
	}
	if w := post("/api/settings", `{"idle":"-1s"}`); w.Code != http.StatusBadRequest {
		t.Fatalf("bad idle %d %s", w.Code, w.Body.String())
	}
}
