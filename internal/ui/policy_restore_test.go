package ui

import (
	"encoding/json"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/config"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/guard"
	"net/http"
	"testing"
)

func TestBuiltinUIInheritanceAndRestoreGate(t *testing.T) {
	dir := t.TempDir()
	if err := config.Save(dir, &config.Config{Version: 1}); err != nil {
		t.Fatal(err)
	}
	h := Handler(dir, false)
	p, _ := guard.BuiltinPolicy("readonly")
	body, _ := json.Marshal(map[string]any{"name": "readonly", "mode": "readonly", "allow": *p.Allow})
	if rr := postJSON(t, h, "/api/policies", string(body)); rr.Code != 200 {
		t.Fatal(rr.Code, rr.Body.String())
	}
	cfg, _ := config.Load(dir)
	if cfg.Policies["readonly"] != nil {
		t.Fatal("UI snapshot stored unchanged builtin")
	}
	if rr := postJSON(t, h, "/api/policies", `{"name":"readonly","allow":["ls"],"deny":["docker logs"]}`); rr.Code != 200 {
		t.Fatal(rr.Code, rr.Body.String())
	}
	for _, body := range []string{`{"name":"readonly"}`, `{"name":"readonly","humanConfirm":"wrong"}`} {
		rr := postJSON(t, h, "/api/policies/remove", body)
		if rr.Code != http.StatusConflict {
			t.Fatalf("unguarded restore: %d %s", rr.Code, rr.Body.String())
		}
		var response map[string]any
		json.Unmarshal(rr.Body.Bytes(), &response)
		if response["confirm"] != "readonly" || response["needsConfirm"] != true {
			t.Fatal(response)
		}
	}
	cfg, _ = config.Load(dir)
	if cfg.Policies["readonly"] == nil {
		t.Fatal("override lost before confirmation")
	}
	if rr := postJSON(t, h, "/api/policies/remove", `{"name":"readonly","humanConfirm":"readonly"}`); rr.Code != 200 {
		t.Fatal(rr.Code, rr.Body.String())
	}
	cfg, _ = config.Load(dir)
	if cfg.Policies["readonly"] != nil {
		t.Fatal("restore did not finish")
	}
	// Widening on the create/override endpoint must also be checked.
	rr := postJSON(t, h, "/api/policies", `{"name":"readonly","mode":"admin"}`)
	if rr.Code != http.StatusConflict {
		t.Fatalf("override widening accepted: %d %s", rr.Code, rr.Body.String())
	}
}
