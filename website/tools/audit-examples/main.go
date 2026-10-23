// audit-examples generates inert website fixtures using the real local audit code.
package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/audit"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/secrets"
)

type isolatedKeyring struct{}

func (isolatedKeyring) Get(string, string) (string, error) { return "", secrets.ErrNotFound }
func (isolatedKeyring) Set(string, string, string) error {
	return fmt.Errorf("fixture uses an ephemeral environment key")
}

type result struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

func main() {
	check := flag.Bool("check", false, "compare with the committed website fixture")
	flag.Parse()
	if err := generate(*check); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func generate(check bool) error {
	// Never consult the developer's OS credential store or saved passwords.
	restore := secrets.SetTestKeyring(isolatedKeyring{})
	defer restore()
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		return err
	}
	old, had := os.LookupEnv("SSH_CLI_MASTER_KEY")
	if err := os.Setenv("SSH_CLI_MASTER_KEY", base64.StdEncoding.EncodeToString(key[:])); err != nil {
		return err
	}
	defer func() {
		if had {
			os.Setenv("SSH_CLI_MASTER_KEY", old)
		} else {
			os.Unsetenv("SSH_CLI_MASTER_KEY")
		}
	}()
	base, err := filepath.Abs(os.TempDir())
	if err != nil {
		return err
	}
	dir, err := os.MkdirTemp(base, "ssh-cli-site-audit-")
	if err != nil {
		return err
	}
	if filepath.Dir(dir) != base {
		return fmt.Errorf("temporary fixture escaped its parent")
	}
	defer os.RemoveAll(dir)
	records := []audit.Record{}
	for i, alias := range []string{"hn-test-wms-01", "hn-test-wms-02"} {
		exit := 0
		r, err := audit.Append(dir, audit.Record{ID: fmt.Sprintf("example-%02d", i+1), Time: fmt.Sprintf("2026-10-22T09:41:0%d+08:00", i), Op: audit.OpExec, Host: alias, Group: "hunan-test", Env: "test", Command: "journalctl -u wms -n 40 --no-pager", ExitCode: &exit, Status: audit.StatusOK, Actor: "example-agent", Source: audit.SourceCLI, Reason: "Illustrative website fixture; no remote command was executed"})
		if err != nil {
			return err
		}
		records = append(records, r)
	}
	if err := audit.Protect(dir); err != nil {
		return err
	}
	verify := func() result {
		err := audit.VerifyIntegrity(dir)
		if err != nil {
			return result{Error: err.Error()}
		}
		return result{OK: true}
	}
	variants := map[string]result{"original": verify()}
	path := filepath.Join(dir, audit.DirName, "2026-10-22.jsonl")
	original, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	changed := bytes.Replace(original, []byte("journalctl -u wms -n 40 --no-pager"), []byte("rm -rf /opt/app"), 1)
	if bytes.Equal(original, changed) {
		return fmt.Errorf("fixture mutation did not change a record")
	}
	if err := os.WriteFile(path, changed, 0600); err != nil {
		return err
	}
	variants["tampered"] = verify()
	if err := os.Remove(path); err != nil {
		return err
	}
	variants["deleted"] = verify()
	data := map[string]any{"version": "0.7.37", "records": records, "variants": variants, "illustrative": true}
	body, err := json.Marshal(data)
	if err != nil {
		return err
	}
	payload := append([]byte("// Generated local audit fixtures. Records are illustrative; no remote command was run.\nwindow.SSH_CLI_AUDIT_EXAMPLES = "), body...)
	payload = append(payload, []byte(";\n")...)
	destination := filepath.Join("website", "audit-examples.js")
	if check {
		existing, err := os.ReadFile(destination)
		if err != nil {
			return err
		}
		if !bytes.Equal(existing, payload) {
			return fmt.Errorf("audit fixtures differ; regenerate and review")
		}
		fmt.Println("Checked real audit integrity results for original, edited and deleted fixture logs.")
		return nil
	}
	if err := os.WriteFile(destination, payload, 0644); err != nil {
		return err
	}
	fmt.Println("Generated inert audit integrity fixtures; no OS credentials or servers accessed.")
	return nil
}
