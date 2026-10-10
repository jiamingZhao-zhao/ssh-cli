package ui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func useLoopback(req *http.Request) {
	if req.Host == "" || req.Host == "example.com" {
		req.Host = "127.0.0.1"
	}
	if req.RemoteAddr == "" {
		req.RemoteAddr = "127.0.0.1:9"
	}
}

func attachCSRF(t *testing.T, h http.Handler, req *http.Request) {
	t.Helper()
	useLoopback(req)
	sess := httptest.NewRequest(http.MethodGet, "/api/session", nil)
	sess.Host = req.Host
	sess.RemoteAddr = "127.0.0.1:9"
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
	if req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}
}

func TestSessionReusesCSRF(t *testing.T) {
	h := Handler(t.TempDir(), false)
	first := httptest.NewRequest(http.MethodGet, "/api/session", nil)
	first.Host = "127.0.0.1"
	first.RemoteAddr = "127.0.0.1:9"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, first)
	if rr.Code != http.StatusOK {
		t.Fatalf("session %d %s", rr.Code, rr.Body.String())
	}
	var body struct {
		CSRF string `json:"csrf"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil || body.CSRF == "" {
		t.Fatalf("csrf %v %s", err, rr.Body.String())
	}
	var cookie *http.Cookie
	for _, c := range rr.Result().Cookies() {
		if c.Name == sessionCookie {
			cookie = c
		}
	}
	if cookie == nil {
		t.Fatal("missing session cookie")
	}
	again := httptest.NewRequest(http.MethodGet, "/api/session", nil)
	again.Host = "127.0.0.1"
	again.RemoteAddr = "127.0.0.1:9"
	again.AddCookie(cookie)
	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, again)
	var body2 struct {
		CSRF string `json:"csrf"`
	}
	if err := json.Unmarshal(rr2.Body.Bytes(), &body2); err != nil {
		t.Fatal(err)
	}
	if body2.CSRF != body.CSRF {
		t.Fatalf("session rotated csrf %q -> %q", body.CSRF, body2.CSRF)
	}
	if len(rr2.Result().Cookies()) != 0 {
		t.Fatalf("reuse set a new cookie: %#v", rr2.Result().Cookies())
	}
}
