package ui

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/sshtest"
)

func TestJumpHostUIAndDirectDial(t *testing.T) {
	jump, err := sshtest.Start("jumper", "jump-secret", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeSoon(jump) })
	dest, err := sshtest.Start("destuser", "dest-secret", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeSoon(dest) })
	jHost, jPort, err := net.SplitHostPort(jump.Addr)
	if err != nil {
		t.Fatal(err)
	}
	dHost, dPort, err := net.SplitHostPort(dest.Addr)
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
	get := func(path string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.RemoteAddr = "127.0.0.1:9"
		req.Host = "127.0.0.1"
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr
	}

	page := get("/")
	body := page.Body.String()
	for _, s := range []string{"经跳板", "跨机拷贝", "经由 ", "term-tab-via", `x-text="tab.alias"`} {
		if !strings.Contains(body, s) {
			t.Fatalf("page missing %s", s)
		}
	}
	if strings.Contains(body, ">中继<") {
		t.Fatal("file relay page still uses 中继")
	}

	if rr := post("/api/groups", `{"name":"sandbox","env":"dev"}`); rr.Code != 200 {
		t.Fatalf("group %d %s", rr.Code, rr.Body.String())
	}
	addJump := `{"alias":"jump","group":"sandbox","host":"` + jHost + `","port":` + jPort + `,"user":"jumper","password":"jump-secret"}`
	if rr := post("/api/hosts", addJump); rr.Code != 200 {
		t.Fatalf("jump %d %s", rr.Code, rr.Body.String())
	}
	addBox := `{"alias":"box","group":"sandbox","host":"` + dHost + `","port":` + dPort + `,"user":"destuser","password":"dest-secret","via":"jump"}`
	if rr := post("/api/hosts", addBox); rr.Code != 200 {
		t.Fatalf("box %d %s", rr.Code, rr.Body.String())
	}
	cat := get("/api/catalog")
	if cat.Code != 200 || !strings.Contains(cat.Body.String(), `"via":"jump"`) {
		t.Fatalf("catalog %d %s", cat.Code, cat.Body.String())
	}
	detail := get("/api/hosts/detail?alias=box")
	if detail.Code != 200 || !strings.Contains(detail.Body.String(), `"via":"jump"`) || !strings.Contains(detail.Body.String(), `"host":"`+dHost+`"`) {
		t.Fatalf("detail %d %s", detail.Code, detail.Body.String())
	}

	direct := post("/api/exec", `{"alias":"jump","command":"echo direct-ok"}`)
	if direct.Code != 200 || !strings.Contains(direct.Body.String(), "direct-ok") {
		t.Fatalf("direct %d %s", direct.Code, direct.Body.String())
	}
	if jump.Sessions() < 1 {
		t.Fatalf("direct sessions %d", jump.Sessions())
	}
	before := jump.Sessions()
	via := post("/api/exec", `{"alias":"box","command":"echo dest-ok"}`)
	if via.Code != 200 || !strings.Contains(via.Body.String(), "dest-ok") {
		t.Fatalf("via %d %s", via.Code, via.Body.String())
	}
	if jump.Sessions() != before || dest.Sessions() < 1 {
		t.Fatalf("jump sessions %d->%d dest %d", before, jump.Sessions(), dest.Sessions())
	}

	cycle := post("/api/hosts/update", `{"alias":"jump","via":"box"}`)
	if cycle.Code == 200 || !strings.Contains(cycle.Body.String(), "cycle") {
		t.Fatalf("cycle %d %s", cycle.Code, cycle.Body.String())
	}
	missing := post("/api/hosts", `{"alias":"ghost","group":"sandbox","host":"192.0.2.9","user":"ops","password":"x","via":"missing"}`)
	if missing.Code == 200 || !strings.Contains(missing.Body.String(), "does not exist") {
		t.Fatalf("missing %d %s", missing.Code, missing.Body.String())
	}
}

func closeSoon(s *sshtest.Server) {
	done := make(chan struct{})
	go func() {
		s.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
	}
}
