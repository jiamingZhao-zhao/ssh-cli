package ui

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/audit"
)

func TestCheckBind(t *testing.T) {
	if err := CheckBind("127.0.0.1:7788", false); err != nil {
		t.Fatal(err)
	}
	if err := CheckBind("localhost:7788", false); err != nil {
		t.Fatal(err)
	}
	if err := CheckBind("[::1]:7788", false); err != nil {
		t.Fatal(err)
	}
	err := CheckBind("0.0.0.0:7788", false)
	if err == nil || !strings.Contains(err.Error(), "refusing to bind") || !strings.Contains(err.Error(), "--allow-non-loopback") {
		t.Fatalf("err %v", err)
	}
	if err := CheckBind("0.0.0.0:7788", true); err != nil {
		t.Fatal(err)
	}
	if !WarnNonLoopback("192.0.2.10:7788") {
		t.Fatal("expected non-loopback warning")
	}
	if WarnNonLoopback("127.0.0.1:7788") {
		t.Fatal("loopback should not warn")
	}
}

func TestUISmoke(t *testing.T) {
	dir := t.TempDir()
	h := Handler(dir, false)
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	res, err := srv.Client().Get(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	body := mustBody(t, res)
	if res.StatusCode != 200 || !strings.Contains(body, "ssh-cli") || !strings.Contains(body, "审计") {
		t.Fatalf("index %d %s", res.StatusCode, body)
	}
	for _, path := range []string{"/app.js", "/app.css"} {
		res, err := srv.Client().Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		b := mustBody(t, res)
		if res.StatusCode != 200 || len(b) < 20 {
			t.Fatalf("%s %d %s", path, res.StatusCode, b)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/api/catalog", nil)
	req.RemoteAddr = "192.0.2.10:1234"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("remote %d %s", rr.Code, rr.Body.String())
	}

	seedEnvGroup(t, dir)
	password := "s3cret-ui"
	add := httptest.NewRequest(http.MethodPost, "/api/hosts", strings.NewReader(
		`{"alias":"main","group":"app-prod","host":"192.0.2.10","user":"viewer","password":"`+password+`","tags":["app"],"setDefault":true}`))
	add.RemoteAddr = "127.0.0.1:9"
	add.Header.Set("Content-Type", "application/json")
	attachCSRF(t, h, add)
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, add)
	if rr.Code != 200 || strings.Contains(rr.Body.String(), password) {
		t.Fatalf("add %d %s", rr.Code, rr.Body.String())
	}

	q := httptest.NewRequest(http.MethodPost, "/api/hosts?password="+password, strings.NewReader(`{"alias":"x"}`))
	q.RemoteAddr = "127.0.0.1:9"
	q.Header.Set("Content-Type", "application/json")
	attachCSRF(t, h, q)
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, q)
	if rr.Code != http.StatusBadRequest || strings.Contains(rr.Body.String(), password) {
		t.Fatalf("query password %d %s", rr.Code, rr.Body.String())
	}

	res, err = srv.Client().Get(srv.URL + "/api/catalog")
	if err != nil {
		t.Fatal(err)
	}
	catalog := mustBody(t, res)
	if strings.Contains(catalog, password) || !strings.Contains(catalog, `"alias":"main"`) || !strings.Contains(catalog, `"auth":"password"`) {
		t.Fatalf("catalog %s", catalog)
	}
	yamlBytes, err := os.ReadFile(filepath.Join(dir, "hosts.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	secBytes, err := os.ReadFile(filepath.Join(dir, "secrets.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(yamlBytes), password) || strings.Contains(string(secBytes), password) {
		t.Fatal("password stored in plaintext")
	}

	edit := httptest.NewRequest(http.MethodPost, "/api/hosts/update", strings.NewReader(`{"alias":"main","port":2222}`))
	edit.RemoteAddr = "127.0.0.1:9"
	edit.Header.Set("Content-Type", "application/json")
	attachCSRF(t, h, edit)
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, edit)
	if rr.Code != 200 {
		t.Fatalf("edit %d %s", rr.Code, rr.Body.String())
	}
	res, err = srv.Client().Get(srv.URL + "/api/catalog")
	if err != nil {
		t.Fatal(err)
	}
	edited := mustBody(t, res)
	if !strings.Contains(edited, `"port":2222`) {
		t.Fatal(edited)
	}

	if _, err := audit.Append(dir, audit.Record{
		Op: audit.OpPolicyCheck, Host: "main", Group: "app-prod", Env: "prod",
		Command: "rm -rf /", Status: audit.StatusDenied, HighRisk: true, DeniedByPolicy: true,
		Reason: "builtin: rm of filesystem root",
	}); err != nil {
		t.Fatal(err)
	}
	res, err = srv.Client().Get(srv.URL + "/api/audit?host=main&status=denied")
	if err != nil {
		t.Fatal(err)
	}
	auditBody := mustBody(t, res)
	if !strings.Contains(auditBody, "rm -rf /") || !strings.Contains(auditBody, `"high_risk":true`) || strings.Contains(auditBody, password) {
		t.Fatalf("audit %s", auditBody)
	}

	rm := httptest.NewRequest(http.MethodPost, "/api/hosts/remove", strings.NewReader(`{"alias":"main"}`))
	rm.RemoteAddr = "127.0.0.1:9"
	rm.Header.Set("Content-Type", "application/json")
	attachCSRF(t, h, rm)
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, rm)
	if rr.Code != 200 {
		t.Fatalf("remove %d %s", rr.Code, rr.Body.String())
	}
	res, err = srv.Client().Get(srv.URL + "/api/catalog")
	if err != nil {
		t.Fatal(err)
	}
	left := mustBody(t, res)
	if strings.Contains(left, `"alias":"main"`) {
		t.Fatalf("host still listed: %s", left)
	}
}

func TestUIConfigParity(t *testing.T) {
	dir := t.TempDir()
	h := Handler(dir, false)
	index := httptest.NewRequest(http.MethodGet, "/", nil)
	index.Host = "127.0.0.1"
	index.RemoteAddr = "127.0.0.1:9"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, index)
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), "危险命令") || !strings.Contains(rr.Body.String(), "已知主机密钥") || !strings.Contains(rr.Body.String(), "标签只写在主机上") {
		t.Fatalf("index %d %s", rr.Code, rr.Body.String())
	}
	post := func(path, body string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		req.RemoteAddr = "127.0.0.1:9"
		req.Header.Set("Content-Type", "application/json")
		attachCSRF(t, h, req)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w
	}
	if w := post("/api/envs", `{"name":"lab","label":"实验","maxMode":"admin","noDataOutflow":true}`); w.Code != 200 {
		t.Fatalf("env %d %s", w.Code, w.Body.String())
	}
	if w := post("/api/groups", `{"name":"sandbox","env":"lab","protectedPaths":["/root/app"]}`); w.Code != 200 {
		t.Fatalf("group %d %s", w.Code, w.Body.String())
	}
	if w := post("/api/policies", `{"name":"tight","mode":"readonly","deny":["shutdown"],"confirm":["systemctl restart"]}`); w.Code != 200 {
		t.Fatalf("policy %d %s", w.Code, w.Body.String())
	}
	if w := post("/api/policies/update", `{"name":"tight","mode":"standard","deny":["shutdown","poweroff"],"confirm":["systemctl restart"],"humanConfirm":"tight"}`); w.Code != 200 {
		t.Fatalf("policy update %d %s", w.Code, w.Body.String())
	}
	if w := post("/api/envs/update", `{"name":"lab","label":"实验","maxMode":"standard","defaultPolicy":"tight","humanConfirm":"lab"}`); w.Code != 200 {
		t.Fatalf("env update %d %s", w.Code, w.Body.String())
	}
	if w := post("/api/groups/set-env", `{"name":"sandbox","env":"lab"}`); w.Code != 200 {
		t.Fatalf("set-env %d %s", w.Code, w.Body.String())
	}
	req := httptest.NewRequest(http.MethodGet, "/api/catalog", nil)
	req.Host = "127.0.0.1"
	req.RemoteAddr = "127.0.0.1:9"
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	body := rr.Body.String()
	for _, fragment := range []string{`"name":"lab"`, `"name":"sandbox"`, `"name":"tight"`, "poweroff", `"maxMode":"standard"`} {
		if !strings.Contains(body, fragment) {
			t.Fatalf("catalog missing %s\n%s", fragment, body)
		}
	}
	if w := post("/api/known-hosts/remove", `{"marker":"192.0.2.10"}`); w.Code == 200 {
		t.Fatalf("missing known host removed: %s", w.Body.String())
	}
	yamlBytes, err := os.ReadFile(filepath.Join(dir, "hosts.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(yamlBytes), "noDataOutflow: true") || !strings.Contains(string(yamlBytes), "shutdown") {
		t.Fatalf("yaml\n%s", yamlBytes)
	}
}

func TestUILayout(t *testing.T) {
	h := Handler(t.TempDir(), false)
	get := func(path string) string {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Host = "127.0.0.1"
		req.RemoteAddr = "127.0.0.1:9"
		useLoopback(req)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != 200 {
			t.Fatalf("%s %d %s", path, rr.Code, rr.Body.String())
		}
		return rr.Body.String()
	}
	body := get("/")
	if strings.Contains(body, "tabbar") {
		t.Fatal("top tab bar still present")
	}
	if strings.Count(body, `data-view="known"`) != 2 {
		t.Fatalf("known nav count %d", strings.Count(body, `data-view="known"`))
	}
	for _, id := range []string{"#hosts", "#group-rows", "#tag-rows", "#env-rows", "#policy-rows", "#known", "#session-rows"} {
		if !strings.Contains(body, `data-pager="`+id+`"`) {
			t.Fatalf("missing pager for %s", id)
		}
	}
	if !strings.Contains(body, `id="audit-pager"`) {
		t.Fatal("missing audit pager")
	}
	script := get("/app.js")
	if !strings.Contains(script, "DEFAULT_PAGE_SIZE = 10") || strings.Contains(script, `params.set("pageSize", "50")`) || strings.Contains(script, "const size = 25") {
		t.Fatal("page size default is not 10")
	}
	style := get("/app.css")
	if strings.Contains(style, ".tabbar") || !strings.Contains(style, "margin: auto") || !strings.Contains(style, "justify-content: flex-end") {
		t.Fatal("css missing centered dialog or bottom-right pager")
	}
}

func TestAllowRemoteRequiresBearer(t *testing.T) {
	dir := t.TempDir()
	h := HandlerBearer(dir, true, "test-token")
	spoof := httptest.NewRequest(http.MethodGet, "/api/catalog", nil)
	spoof.Host = "localhost"
	spoof.RemoteAddr = "192.0.2.10:9"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, spoof)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("spoofed host %d %s", rr.Code, rr.Body.String())
	}
	page := httptest.NewRequest(http.MethodGet, "/", nil)
	page.Host = "192.0.2.10:7788"
	page.RemoteAddr = "192.0.2.10:9"
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, page)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "ssh-cli") {
		t.Fatalf("page %d %s", rr.Code, rr.Body.String())
	}
	ok := httptest.NewRequest(http.MethodGet, "/api/catalog", nil)
	ok.Host = "192.0.2.10:7788"
	ok.RemoteAddr = "192.0.2.10:9"
	ok.Header.Set("Authorization", "Bearer test-token")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, ok)
	if rr.Code != http.StatusOK {
		t.Fatalf("bearer %d %s", rr.Code, rr.Body.String())
	}
	cross := httptest.NewRequest(http.MethodGet, "/api/catalog", nil)
	cross.Host = "192.0.2.10:7788"
	cross.RemoteAddr = "192.0.2.10:9"
	cross.Header.Set("Authorization", "Bearer test-token")
	cross.Header.Set("Origin", "http://evil.example")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, cross)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("origin %d %s", rr.Code, rr.Body.String())
	}
}

func seedEnvGroup(t *testing.T, dir string) {
	t.Helper()
	err := os.WriteFile(filepath.Join(dir, "hosts.yaml"), []byte(`
version: 1
envs:
  prod:
    label: 生产
    maxMode: readonly
    defaultPolicy: readonly
groups:
  app-prod:
    env: prod
    hosts: {}
`), 0o600)
	if err != nil {
		t.Fatal(err)
	}
}

func mustBody(t *testing.T, res *http.Response) string {
	t.Helper()
	defer res.Body.Close()
	b, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
