package secrets

import (
	"bytes"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

type fakeRing struct {
	data   map[string]string
	getErr error
	setErr error
}

func (f *fakeRing) key(service, user string) string { return service + "\x00" + user }

func (f *fakeRing) Get(service, user string) (string, error) {
	if f.getErr != nil {
		return "", f.getErr
	}
	v, ok := f.data[f.key(service, user)]
	if !ok {
		return "", ErrNotFound
	}
	return v, nil
}

func (f *fakeRing) Set(service, user, secret string) error {
	if f.setErr != nil {
		return f.setErr
	}
	if f.data == nil {
		f.data = map[string]string{}
	}
	f.data[f.key(service, user)] = secret
	return nil
}

func TestEncryptRoundTripHidesPlaintext(t *testing.T) {
	dir := t.TempDir()
	kr := &fakeRing{}
	var warn bytes.Buffer
	st, err := Open(dir, Options{Keyring: kr, Warn: &warn})
	if err != nil {
		t.Fatal(err)
	}
	const secret = "s3cret-value"
	if err := st.Put("app.main", secret); err != nil {
		t.Fatal(err)
	}
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, fileName))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), secret) {
		t.Fatal("plaintext leaked into secrets.json")
	}
	if warn.Len() != 0 {
		t.Fatalf("unexpected warning: %s", warn.String())
	}
	got, err := st.Get("app.main")
	if err != nil || got != secret {
		t.Fatalf("got %q err %v", got, err)
	}
	info, err := os.Stat(filepath.Join(dir, fileName))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o", info.Mode().Perm())
	}

	// A different key cannot decrypt, and the error must not echo the secret.
	other := make([]byte, chacha20poly1305.KeySize)
	for i := range other {
		other[i] = 7
	}
	env := base64.StdEncoding.EncodeToString(other)
	st2, err := Open(dir, Options{Keyring: &fakeRing{getErr: ErrNotFound}, Warn: &warn, EnvKey: &env})
	if err != nil {
		t.Fatal(err)
	}
	_, err = st2.Get("app.main")
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("err = %v", err)
	}
}

func TestKeyringPreferredOverEnv(t *testing.T) {
	dir := t.TempDir()
	kr := &fakeRing{}
	keyA := bytes.Repeat([]byte{3}, chacha20poly1305.KeySize)
	if err := kr.Set(serviceName, keyringUser, base64.StdEncoding.EncodeToString(keyA)); err != nil {
		t.Fatal(err)
	}
	envKey := bytes.Repeat([]byte{9}, chacha20poly1305.KeySize)
	env := base64.StdEncoding.EncodeToString(envKey)
	st, err := Open(dir, Options{Keyring: kr, EnvKey: &env, Warn: ioDiscard()})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Put("ref", "pw"); err != nil {
		t.Fatal(err)
	}
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}
	// Reopen with only the env key: decryption must fail because keyring won.
	stEnv, err := Open(dir, Options{Keyring: &fakeRing{getErr: ErrNotFound}, EnvKey: &env, Warn: ioDiscard()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stEnv.Get("ref"); err == nil {
		t.Fatal("env key decrypted a keyring-encrypted secret")
	}
	stKR, err := Open(dir, Options{Keyring: kr, EnvKey: &env, Warn: ioDiscard()})
	if err != nil {
		t.Fatal(err)
	}
	got, err := stKR.Get("ref")
	if err != nil || got != "pw" {
		t.Fatalf("keyring reopen: %q %v", got, err)
	}
}

func TestFileFallbackWarnsAndIsPrivate(t *testing.T) {
	dir := t.TempDir()
	var warn bytes.Buffer
	kr := &fakeRing{getErr: ErrNotFound, setErr: errors.New("no dbus")}
	st, err := Open(dir, Options{Keyring: kr, Warn: &warn})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Put("ref", "pw"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(warn.String(), "mode 0600") {
		t.Fatalf("warning = %q", warn.String())
	}
	info, err := os.Stat(filepath.Join(dir, keyFileName))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("key mode %o", info.Mode().Perm())
	}
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}
	warn.Reset()
	st2, err := Open(dir, Options{Keyring: kr, Warn: &warn})
	if err != nil {
		t.Fatal(err)
	}
	got, err := st2.Get("ref")
	if err != nil || got != "pw" {
		t.Fatalf("file key reopen: %q %v", got, err)
	}
	if !strings.Contains(warn.String(), keyFileName) {
		t.Fatalf("expected fallback warning, got %q", warn.String())
	}
}

func TestDecryptRejectsShortNonce(t *testing.T) {
	key := make([]byte, chacha20poly1305.KeySize)
	_, err := decrypt(key, "ref", entry{
		Nonce:      base64.StdEncoding.EncodeToString([]byte("short")),
		Ciphertext: base64.StdEncoding.EncodeToString([]byte("cipher")),
	})
	if err == nil || !strings.Contains(err.Error(), "nonce") {
		t.Fatal(err)
	}
}

func TestNoMasterKeySentinel(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir, Options{Keyring: &fakeRing{}, Warn: ioDiscard()})
	if err != nil {
		t.Fatal(err)
	}
	_, err = st.masterKey(false)
	if err == nil || !errors.Is(err, ErrNoMasterKey) || !strings.Contains(err.Error(), "no master key available to decrypt secrets") {
		t.Fatal(err)
	}
}

func ioDiscard() *bytes.Buffer { return &bytes.Buffer{} }
