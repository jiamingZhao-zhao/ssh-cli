package remote

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestServiceCommand(t *testing.T) {
	got, err := ServiceCommand("status", "nginx")
	if err != nil || got != "systemctl status nginx" {
		t.Fatalf("%q %v", got, err)
	}
	if _, err := ServiceCommand("disable", "nginx"); err == nil {
		t.Fatal("disable should be rejected")
	}
	if _, err := ServiceCommand("restart", "nginx;rm"); err == nil {
		t.Fatal("metacharacters should be rejected")
	}
	if _, err := ServiceCommand("restart", "../nginx"); err == nil {
		t.Fatal("path should be rejected")
	}
}

func TestValidateRemotePath(t *testing.T) {
	if _, err := ValidateRemotePath(".ssh/authorized_keys"); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", "foo bar", "a;rm", "../.ssh/authorized_keys", "-rf", "foo|bar"} {
		if _, err := ValidateRemotePath(bad); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}

func TestParseAuthorizedKeys(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))) + " laptop"
	body := "# comment\n\n" + line + "\nnot-a-key\n"
	keys, warnings := ParseAuthorizedKeys([]byte(body))
	if len(keys) != 1 || keys[0].Comment != "laptop" || keys[0].Line != 3 {
		t.Fatalf("keys %+v", keys)
	}
	if keys[0].Fingerprint != ssh.FingerprintSHA256(signer.PublicKey()) {
		t.Fatalf("fingerprint %s", keys[0].Fingerprint)
	}
	if len(warnings) != 1 {
		t.Fatalf("warnings %v", warnings)
	}
}

func TestParseListMTime(t *testing.T) {
	in := "-rw------- 1 root root 100 2026-10-08 11:05 .ssh/authorized_keys"
	if got := ParseListMTime(in); got != "2026-10-08 11:05" {
		t.Fatal(got)
	}
}
