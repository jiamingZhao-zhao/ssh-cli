package ui

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/sshtest"
)

func TestProtectedRenameAndParentDelete(t *testing.T) {
	srv, err := sshtest.Start("tester", "ui-secret", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		done := make(chan struct{})
		go func() {
			srv.Close()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
	})
	host, port, err := net.SplitHostPort(srv.Addr)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	h := Handler(dir, false)
	post := func(path, body, contentType string, browser bool) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		req.RemoteAddr = "127.0.0.1:9"
		req.Host = "127.0.0.1"
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		if browser {
			req.Header.Set("Origin", "http://127.0.0.1")
			req.Header.Set("Sec-Fetch-Site", "same-origin")
			req.Header.Set("Sec-Fetch-Dest", "empty")
			req.Header.Set("Sec-Fetch-Mode", "cors")
		}
		attachCSRF(t, h, req)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr
	}
	if rr := post("/api/groups", `{"name":"sandbox","env":"dev"}`, "application/json", false); rr.Code != 200 {
		t.Fatalf("group %d %s", rr.Code, rr.Body.String())
	}
	addHost := `{"alias":"box","group":"sandbox","host":"` + host + `","port":` + port + `,"user":"tester","password":"ui-secret"}`
	if rr := post("/api/hosts", addHost, "application/json", false); rr.Code != 200 {
		t.Fatalf("host %d %s", rr.Code, rr.Body.String())
	}

	root := t.TempDir()
	protected := filepath.Join(root, "protected.txt")
	if err := os.WriteFile(protected, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	parent := filepath.Join(root, "parent")
	if err := os.Mkdir(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	child := filepath.Join(parent, "protected-child.txt")
	if err := os.WriteFile(child, []byte("child"), 0o644); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(root, "outside.txt")
	if err := os.WriteFile(outside, []byte("out"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link.txt")
	linkOK := true
	if err := os.Symlink(protected, link); err != nil {
		linkOK = false
		t.Logf("skip symlink probe: %v", err)
	}
	home, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	rel, err := filepath.Rel(home, protected)
	if err != nil {
		t.Fatal(err)
	}

	paths := []string{filepath.ToSlash(protected), filepath.ToSlash(child)}
	raw, err := json.Marshal(map[string]any{"name": "sandbox", "protectedPaths": paths})
	if err != nil {
		t.Fatal(err)
	}
	if rr := post("/api/groups/update", string(raw), "application/json", false); rr.Code != 200 {
		t.Fatalf("protect %d %s", rr.Code, rr.Body.String())
	}

	change := func(op, path, name, confirm string, browser bool) *httptest.ResponseRecorder {
		t.Helper()
		body, err := json.Marshal(map[string]string{
			"alias": "box", "op": op, "path": path, "name": name, "confirm": confirm, "source": "ui",
		})
		if err != nil {
			t.Fatal(err)
		}
		return post("/api/files/change", string(body), "application/json", browser)
	}
	expectConfirm := func(op, path, name string) {
		t.Helper()
		rr := change(op, path, name, "", true)
		if rr.Code != http.StatusConflict || !strings.Contains(rr.Body.String(), `"needsConfirm":true`) {
			t.Fatalf("%s %s: %d %s", op, path, rr.Code, rr.Body.String())
		}
	}

	expectConfirm("rename", protected, "renamed.txt")
	if _, err := os.Stat(protected); err != nil {
		t.Fatalf("rename removed the protected file: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "renamed.txt")); !os.IsNotExist(err) {
		t.Fatalf("rename wrote the new name: %v", err)
	}
	expectConfirm("remove", protected, "")
	if _, err := os.Stat(protected); err != nil {
		t.Fatalf("direct remove deleted the protected file: %v", err)
	}
	expectConfirm("remove", parent, "")
	if _, err := os.Stat(child); err != nil {
		t.Fatalf("parent delete removed the protected child: %v", err)
	}
	expectConfirm("rename", filepath.ToSlash(rel), "renamed-rel.txt")
	if _, err := os.Stat(protected); err != nil {
		t.Fatalf("relative rename removed the protected file: %v", err)
	}
	if linkOK {
		expectConfirm("rename", link, "renamed-link.txt")
		if _, err := os.Stat(protected); err != nil {
			t.Fatalf("symlink rename removed the target: %v", err)
		}
		if _, err := os.Lstat(link); err != nil {
			t.Fatalf("symlink rename removed the link: %v", err)
		}
	}

	plain := change("rename", outside, "outside-renamed.txt", "", false)
	if plain.Code != 200 {
		t.Fatalf("unprotected rename %d %s", plain.Code, plain.Body.String())
	}
	if _, err := os.Stat(filepath.Join(root, "outside-renamed.txt")); err != nil {
		t.Fatal(err)
	}

	ok := change("rename", protected, "renamed.txt", "box", true)
	if ok.Code != 200 {
		t.Fatalf("confirmed rename %d %s", ok.Code, ok.Body.String())
	}
	if _, err := os.Stat(filepath.Join(root, "renamed.txt")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(protected); !os.IsNotExist(err) {
		t.Fatalf("confirmed rename left the source: %v", err)
	}
}
