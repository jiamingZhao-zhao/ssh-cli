package guard

import (
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"sync"
	"testing"
)

// Exercise the exact allow-listed argv on GNU Wget; BusyBox and environments
// without Wget skip rather than asserting compatibility with its flags.
func TestReadonlyWgetDoesNotFollowRedirect(t *testing.T) {
	wget, err := exec.LookPath("wget")
	if err != nil {
		t.Skip("GNU wget not installed")
	}
	version, err := exec.Command(wget, "--version").Output()
	if err != nil || !strings.Contains(string(version), "GNU Wget") {
		t.Skip("not GNU Wget")
	}
	var mu sync.Mutex
	var requests []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requests = append(requests, r.Method+" "+r.URL.Path)
		mu.Unlock()
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/must-not-request", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	args := []string{"--no-config", "--no-proxy", "--no-netrc", "--no-hsts", "--no-cookies", "--method=HEAD", "--max-redirect=0", "--tries=1", "--timeout=5", "--output-document=/dev/null", srv.URL + "/ok"}
	if !loopbackWgetHEAD(append([]string{"wget"}, args...)) {
		t.Fatal("valid Wget argv rejected")
	}
	if output, err := exec.Command(wget, args...).CombinedOutput(); err != nil {
		t.Fatalf("HEAD failed: %v: %s", err, output)
	}
	args[len(args)-1] = srv.URL + "/redirect"
	_ = exec.Command(wget, args...).Run() // A redirect with limit zero is expected to fail.
	mu.Lock()
	defer mu.Unlock()
	if len(requests) != 2 || requests[0] != "HEAD /ok" || requests[1] != "HEAD /redirect" {
		t.Fatalf("unexpected HTTP requests: %#v", requests)
	}
}
