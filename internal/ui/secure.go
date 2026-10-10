package ui

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"net/url"
	"strings"
)

const (
	sessionCookie = "ssh_cli_sid"
	csrfHeader    = "X-CSRF-Token"
)

func (s *service) ensureSessions() {
	if s.sessions == nil {
		s.sessions = map[string]string{}
	}
}

func (s *service) apiSession(w http.ResponseWriter, r *http.Request) {
	// A live cookie keeps its token. The terminal workspace fires metrics,
	// files, and history together; minting a new cookie on every call would
	// make the other in-flight POST send a token the browser no longer holds.
	if csrf, ok := s.sessionCSRF(r); ok {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "csrf": csrf})
		return
	}
	sid, csrf := newToken(), newToken()
	s.mu.Lock()
	s.ensureSessions()
	s.sessions[sid] = csrf
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    sid,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "csrf": csrf})
}

func (s *service) sessionCSRF(r *http.Request) (string, bool) {
	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" {
		return "", false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensureSessions()
	csrf := s.sessions[c.Value]
	if csrf == "" {
		return "", false
	}
	return csrf, true
}

func newToken() string {
	var b [32]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// MintToken is a startup secret for --allow-non-loopback. The CLI prints it once.
func MintToken() string { return newToken() }

func bearerOK(r *http.Request, want string) bool {
	h := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(h) < len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return false
	}
	got := strings.TrimSpace(h[len(prefix):])
	if want == "" || len(got) != len(want) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

func (s *service) authorize(w http.ResponseWriter, r *http.Request) bool {
	if s.allowRemote {
		// The WebSocket cannot send Authorization. The ticket was minted by a
		// bearer-authenticated POST, and the handler still requires loopback.
		if strings.HasPrefix(r.URL.Path, "/api/") && r.URL.Path != "/api/terminal/ws" && !bearerOK(r, s.bearer) {
			w.Header().Set("WWW-Authenticate", "Bearer")
			http.Error(w, "bearer token required", http.StatusUnauthorized)
			return false
		}
	} else if !hostAllowed(r.Host) {
		http.Error(w, "localhost only", http.StatusForbidden)
		return false
	}
	if !originAllowed(r, s.allowRemote) || !fetchSiteAllowed(r) {
		http.Error(w, "cross-origin request rejected", http.StatusForbidden)
		return false
	}
	if !mutating(r.Method) {
		return true
	}
	if !jsonMutation(r) {
		http.Error(w, "mutating requests must use JSON", http.StatusUnsupportedMediaType)
		return false
	}
	if !s.csrfOK(r) {
		http.Error(w, "csrf token required", http.StatusForbidden)
		return false
	}
	return true
}

func mutating(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

func hostAllowed(hostport string) bool {
	host := hostport
	if strings.HasPrefix(host, "[") {
		if i := strings.LastIndex(host, "]"); i >= 0 {
			host = host[1:i]
		}
	} else if i := strings.LastIndex(host, ":"); i >= 0 {
		host = host[:i]
	}
	switch strings.ToLower(host) {
	case "localhost", "127.0.0.1", "::1":
		return true
	default:
		return false
	}
}

func originAllowed(r *http.Request, allowRemote bool) bool {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	if !allowRemote && !hostAllowed(u.Host) {
		return false
	}
	return strings.EqualFold(u.Host, r.Host)
}

func fetchSiteAllowed(r *http.Request) bool {
	v := strings.ToLower(strings.TrimSpace(r.Header.Get("Sec-Fetch-Site")))
	if v == "" {
		return true
	}
	return v == "same-origin" || v == "none"
}

func jsonMutation(r *http.Request) bool {
	ct := strings.ToLower(r.Header.Get("Content-Type"))
	if strings.Contains(ct, "application/x-www-form-urlencoded") {
		return false
	}
	if strings.Contains(ct, "application/json") {
		return true
	}
	// Directory and file uploads use multipart. Every other mutating call is JSON.
	if r.URL.Path == "/api/upload" && strings.Contains(ct, "multipart/form-data") {
		return true
	}
	return false
}

func (s *service) csrfOK(r *http.Request) bool {
	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" {
		return false
	}
	s.mu.Lock()
	want := ""
	if s.sessions != nil {
		want = s.sessions[c.Value]
	}
	s.mu.Unlock()
	got := r.Header.Get(csrfHeader)
	if want == "" || len(got) != len(want) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(want), []byte(got)) == 1
}
