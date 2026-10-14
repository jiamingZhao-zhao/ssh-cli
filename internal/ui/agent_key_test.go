package ui

import (
	"github.com/jiamingZhao-zhao/ssh-cli/internal/config"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAgentKeyBrowserLifecycle(t *testing.T) {
	dir := t.TempDir()
	seedEnvGroup(t, dir)
	h := Handler(dir, false)
	pin := "SHA256:" + strings.Repeat("A", 43)
	res := postJSON(t, h, "/api/hosts", `{"alias":"a","group":"app-prod","host":"example","user":"u","agent":true,"agentKey":"`+pin+`"}`)
	if res.Code != http.StatusOK {
		t.Fatal(res.Body.String())
	}
	req := httptest.NewRequest(http.MethodGet, "/api/catalog", nil)
	req.RemoteAddr = "127.0.0.1:9"
	attachCSRF(t, h, req)
	out := httptest.NewRecorder()
	h.ServeHTTP(out, req)
	if out.Code != http.StatusOK || !strings.Contains(out.Body.String(), pin) {
		t.Fatalf("catalog %d %s", out.Code, out.Body.String())
	}
	for _, body := range []string{`{"alias":"a","agentKey":42}`, `{"alias":"a","agentKey":"bad"}`, `{"alias":"a","agentKey":"` + pin + `","identity":"key"}`} {
		res = postJSON(t, h, "/api/hosts/update", body)
		if res.Code == http.StatusOK {
			t.Fatalf("accepted %s", body)
		}
	}
	cfg, err := config.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	host, _ := cfg.Find("a")
	if host.Host.AgentKey != pin {
		t.Fatal("failed browser edit changed pin")
	}
	res = postJSON(t, h, "/api/hosts/update", `{"alias":"a","agentKey":""}`)
	if res.Code != http.StatusOK {
		t.Fatal(res.Body.String())
	}
	cfg, err = config.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	host, _ = cfg.Find("a")
	if host.Host.AgentKey != "" || host.Host.Auth != "agent" {
		t.Fatal("clear selector changed auth")
	}
}
