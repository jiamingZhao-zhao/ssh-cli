package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/config"
)

func protectedAudit(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("SSH_CLI_MASTER_KEY", strings.Repeat("12", 32))
	if err := config.Save(dir, &config.Config{Version: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := Append(dir, Record{Op: OpExec, Command: "echo one", Status: StatusOK}); err != nil {
		t.Fatal(err)
	}
	if err := Protect(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := Append(dir, Record{Op: OpExec, Command: "echo two", Status: StatusOK}); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestIntegrityDetectsMutationAndMissingCheckpoint(t *testing.T) {
	for _, change := range []string{"edit", "truncate", "delete", "checkpoint", "extra"} {
		t.Run(change, func(t *testing.T) {
			dir := protectedAudit(t)
			if err := VerifyIntegrity(dir); err != nil {
				t.Fatal(err)
			}
			files, _ := dataFiles(dir)
			p := files[0]
			body, _ := os.ReadFile(p)
			switch change {
			case "edit":
				os.WriteFile(p, []byte(strings.Replace(string(body), "echo one", "echo bad", 1)), 0o600)
			case "truncate":
				os.WriteFile(p, body[:strings.IndexByte(string(body), '\n')+1], 0o600)
			case "delete":
				os.Remove(p)
			case "checkpoint":
				os.Remove(filepath.Join(dir, DirName, integrityName))
			case "extra":
				os.WriteFile(filepath.Join(dir, DirName, "2000-01-01.jsonl"), body, 0o600)
			}
			if err := VerifyIntegrity(dir); err == nil {
				t.Fatal("tampering accepted")
			}
			if err := Protect(dir); err == nil {
				t.Fatal("silently re-signed altered baseline")
			}
		})
	}
}

func TestIntegrityCleanupRetainsValidChains(t *testing.T) {
	dir := protectedAudit(t)
	when := time.Now().Add(-100 * 24 * time.Hour)
	if _, err := Append(dir, Record{Op: OpExec, Command: "old", Time: when.Format(time.RFC3339Nano)}); err != nil {
		t.Fatal(err)
	}
	if _, err := Cleanup(dir, MinAge, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := VerifyIntegrity(dir); err != nil {
		t.Fatal(err)
	}
}

func TestShortPasswordRedaction(t *testing.T) {
	for _, s := range []string{"mysql -psecret", "mysql -p'with space'", "x;mysql -psecret", "x | mysql -psecret"} {
		got := Scrub(s)
		if strings.Contains(got, "secret") || strings.Contains(got, "with space") {
			t.Fatalf("leaked: %s", got)
		}
	}
}
