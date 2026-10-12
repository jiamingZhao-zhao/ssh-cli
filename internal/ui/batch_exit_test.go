package ui

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/sshtest"
)

func TestBatchNonZeroExitIsFailure(t *testing.T) {
	srv, err := sshtest.Start("tester", "ui-secret", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeSoon(srv) })
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
	rr := post("/api/exec/batch", `{"aliases":["box"],"command":"false"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("batch %d %s", rr.Code, rr.Body.String())
	}
	var body struct {
		OK      bool `json:"ok"`
		Failed  int  `json:"failed"`
		Count   int  `json:"count"`
		Results []struct {
			OK       bool   `json:"ok"`
			ExitCode int    `json:"exitCode"`
			Status   string `json:"status"`
			Alias    string `json:"alias"`
		} `json:"results"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body.OK || body.Failed != 1 || body.Count != 1 || len(body.Results) != 1 {
		t.Fatalf("body %+v", body)
	}
	row := body.Results[0]
	if row.Alias != "box" || row.ExitCode != 1 || row.Status != "error" || !row.OK {
		t.Fatalf("row %+v", row)
	}
	if !resultFailed(map[string]any{"ok": true, "exitCode": row.ExitCode, "status": row.Status}) {
		t.Fatal("resultFailed ignored exitCode and status")
	}
}
