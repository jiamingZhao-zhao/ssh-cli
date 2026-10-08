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
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, add)
	if rr.Code != 200 || strings.Contains(rr.Body.String(), password) {
		t.Fatalf("add %d %s", rr.Code, rr.Body.String())
	}

	q := httptest.NewRequest(http.MethodPost, "/api/hosts?password="+password, strings.NewReader(`{"alias":"x"}`))
	q.RemoteAddr = "127.0.0.1:9"
	q.Header.Set("Content-Type", "application/json")
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
