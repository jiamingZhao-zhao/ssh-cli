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
