package ui

import (
	"context"
	"fmt"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/sshtest"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNoDataOutflowRejectsWorkspaceProbes(t *testing.T) {
	dir := t.TempDir()
	raw := "envs:\n  dev:\n    noDataOutflow: true\ngroups:\n  demo:\n    env: dev\n    hosts:\n      box:\n        host: 127.0.0.1\n        port: 1\n        user: demo\n        auth: key\n        identity: /missing-synthetic-key\n"
	if err := os.WriteFile(filepath.Join(dir, "hosts.yaml"), []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	s := newService(dir, false, "")
	for _, route := range []string{"metrics", "proc"} {
		req := httptest.NewRequest("POST", "/api/metrics", strings.NewReader(`{"alias":"box","pid":"1"}`))
		browserFetch(req, "http://127.0.0.1")
		rr := httptest.NewRecorder()
		if route == "metrics" {
			s.metricsAPI(rr, req)
		} else {
			s.procDetailAPI(rr, req)
		}
		if rr.Code != 403 {
			t.Fatalf("%s %d %s", route, rr.Code, rr.Body.String())
		}
	}
}

func TestCanceledProbePreservesPooledShell(t *testing.T) {
	srv, err := sshtest.Start("tester", "synthetic-pass", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	host, port, _ := net.SplitHostPort(srv.Addr)
	dir := t.TempDir()
	h := Handler(dir, false)
	for _, item := range []struct{ route, body string }{
		{"/api/groups", `{"name":"demo","env":"dev"}`},
		{"/api/hosts", fmt.Sprintf(`{"alias":"box","group":"demo","host":%q,"port":%s,"user":"tester","password":"synthetic-pass"}`, host, port)},
	} {
		req := httptest.NewRequest("POST", item.route, strings.NewReader(item.body))
		req.RemoteAddr = "127.0.0.1:9"
		attachCSRF(t, h, req)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != 200 {
			t.Fatalf("setup %d %s", rr.Code, rr.Body.String())
		}
	}
	s := newService(dir, false, "")
	defer s.pool.Close("box")
	_, resolved, _, err := s.hostPlan("box")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err = s.pool.Open(ctx, "box", s.fingerprint(resolved), false); err != nil {
		t.Fatal(err)
	}
	probeCtx, stop := context.WithTimeout(ctx, 50*time.Millisecond)
	defer stop()
	if _, _, _, err = s.probeRun(probeCtx, resolved, "sleep 0.2"); err == nil {
		t.Fatal("probe did not time out")
	}
	if len(s.pool.List()) != 1 {
		t.Fatal("probe cancellation removed pooled connection")
	}
	stdout, _, code, err := s.poolRun(ctx, resolved, "echo still-alive", time.Second)
	if err != nil || code != 0 || !strings.Contains(stdout, "still-alive") {
		t.Fatalf("shell lost: %q %d %v", stdout, code, err)
	}
}
