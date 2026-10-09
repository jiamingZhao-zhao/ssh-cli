// Package secrets encrypts passwords at rest.
//
// hosts.yaml stores only a passwordRef. The secret itself lives in secrets.json
// as a ChaCha20-Poly1305 ciphertext. The master key comes from the OS keyring,
// then SSH_CLI_MASTER_KEY, then a 0600 key file.
package secrets

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/fsutil"
)

const (
	fileName    = "secrets.json"
	keyFileName = "master.key"
	serviceName = "ssh-cli"
	keyringUser = "master-key"
	version     = 1
)

// ErrNoMasterKey is returned when a ciphertext must be opened and no master key exists.
var ErrNoMasterKey = errors.New("no master key available to decrypt secrets")

// Keyring is the OS keyring. Tests substitute a fake.
type Keyring interface {
	Get(service, user string) (string, error)
	Set(service, user, secret string) error
}

// Options configures Open. Zero values use the real keyring and stderr.
type Options struct {
	Keyring Keyring
	Warn    io.Writer
	// EnvKey, when non-nil, is used instead of SSH_CLI_MASTER_KEY.
	// A pointer distinguishes "not provided" from "explicitly empty".
	EnvKey *string
}

type entry struct {
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

type document struct {
	Version int              `json:"version"`
	Entries map[string]entry `json:"entries"`
}

// Store is an encrypted secret map. It is safe for one locked update at a time.
type Store struct {
	dir  string
	path string
	key  []byte
	doc  document
	kr   Keyring
	warn io.Writer
	env  *string
}

// MasterMaterial returns the master key bytes. create mints one when none exists.
// The bytes authenticate policy HMAC; they are not a plaintext secret export.
func MasterMaterial(dir string, create bool) ([]byte, error) {
	st, err := Open(dir, Options{Warn: io.Discard})
	if err != nil {
		return nil, err
	}
	key, err := st.masterKey(create)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(key))
	copy(out, key)
	return out, nil
}

// Open reads secrets.json. It does not create a master key until Put.
func Open(dir string, opt Options) (*Store, error) {
	if err := fsutil.MkdirPrivate(dir); err != nil {
		return nil, err
	}
	kr := opt.Keyring
	if kr == nil {
		kr = realKeyring{}
	}
	warn := opt.Warn
	if warn == nil {
		warn = os.Stderr
	}
	s := &Store{
		dir:  dir,
		path: filepath.Join(dir, fileName),
		kr:   kr,
		warn: warn,
		env:  opt.EnvKey,
		doc:  document{Version: version, Entries: map[string]entry{}},
	}
	data, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return s, nil
	}
	if err := json.Unmarshal(data, &s.doc); err != nil {
		return nil, fmt.Errorf("parse secrets.json: %w", err)
	}
	if s.doc.Version == 0 {
		s.doc.Version = version
	}
	if s.doc.Version != version {
		return nil, fmt.Errorf("unsupported secrets.json version %d", s.doc.Version)
	}
	if s.doc.Entries == nil {
		s.doc.Entries = map[string]entry{}
	}
	return s, nil
}

// Get decrypts one secret. The plaintext is never included in errors.
func (s *Store) Get(ref string) (string, error) {
	e, ok := s.doc.Entries[ref]
	if !ok {
		return "", fmt.Errorf("secret %q not found", ref)
	}
	key, err := s.masterKey(false)
	if err != nil {
		return "", err
	}
	pt, err := decrypt(key, ref, e)
	if err != nil {
		return "", fmt.Errorf("decrypt secret %q failed", ref)
	}
	return string(pt), nil
}

// Put encrypts secret under ref. Call Save to persist.
func (s *Store) Put(ref, secret string) error {
	if ref == "" {
		return fmt.Errorf("empty secret ref")
	}
	if secret == "" {
		return fmt.Errorf("empty secret")
	}
	key, err := s.masterKey(true)
	if err != nil {
		return err
	}
	nonce, ct, err := encrypt(key, ref, []byte(secret))
	if err != nil {
		return err
	}
	s.doc.Entries[ref] = entry{
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ct),
	}
	return nil
}

// Delete removes ref if present.
func (s *Store) Delete(ref string) {
	delete(s.doc.Entries, ref)
}

// Save writes secrets.json atomically with mode 0600.
func (s *Store) Save() error {
	s.doc.Version = version
	if s.doc.Entries == nil {
		s.doc.Entries = map[string]entry{}
	}
	buf, err := json.MarshalIndent(s.doc, "", "  ")
	if err != nil {
		return err
	}
	buf = append(buf, '\n')
	return fsutil.WriteAtomic(s.path, buf, 0o600)
}

func (s *Store) masterKey(create bool) ([]byte, error) {
	if s.key != nil {
		return s.key, nil
	}
	if encoded, ok, err := s.fromKeyring(); err != nil {
		return nil, err
	} else if ok {
		key, err := decodeKey(encoded)
		if err != nil {
			return nil, fmt.Errorf("keyring master key: %w", err)
		}
		s.key = key
		return s.key, nil
	}
	if encoded, ok := s.fromEnv(); ok {
		key, err := decodeKey(encoded)
		if err != nil {
			return nil, fmt.Errorf("SSH_CLI_MASTER_KEY: %w", err)
		}
		s.key = key
		return s.key, nil
	}
	path := filepath.Join(s.dir, keyFileName)
	if data, err := os.ReadFile(path); err == nil {
		key, err := decodeKey(strings.TrimSpace(string(data)))
		if err != nil {
			return nil, fmt.Errorf("master key file: %w", err)
		}
		s.warnFile(path)
		s.key = key
		return s.key, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if !create {
		return nil, fmt.Errorf("%w", ErrNoMasterKey)
	}
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	encoded := base64.StdEncoding.EncodeToString(key)
	if err := s.kr.Set(serviceName, keyringUser, encoded); err == nil {
		s.key = key
		return s.key, nil
	}
	if err := fsutil.WriteAtomic(path, []byte(encoded+"\n"), 0o600); err != nil {
		return nil, err
	}
	s.warnFile(path)
	s.key = key
	return s.key, nil
}

func (s *Store) fromKeyring() (string, bool, error) {
	v, err := s.kr.Get(serviceName, keyringUser)
	if err == nil {
		return v, true, nil
	}
	if errors.Is(err, errNotFound) || errors.Is(err, errUnsupported) || errors.Is(err, ErrNotFound) {
		return "", false, nil
	}
	// A missing desktop bus or an unavailable keyring is a fallback, not fatal.
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "not found") || strings.Contains(msg, "unsupported") ||
		strings.Contains(msg, "dbus") || strings.Contains(msg, "secret service") ||
		strings.Contains(msg, "connect") {
		return "", false, nil
	}
	return "", false, nil
}

func (s *Store) fromEnv() (string, bool) {
	if s.env != nil {
		if *s.env == "" {
			return "", false
		}
		return *s.env, true
	}
	v, ok := os.LookupEnv("SSH_CLI_MASTER_KEY")
	if !ok || v == "" {
		return "", false
	}
	return v, true
}

func (s *Store) warnFile(path string) {
	fmt.Fprintf(s.warn, "warning: OS keyring unavailable; master key stored in %s (mode 0600)\n", path)
}

func decodeKey(encoded string) ([]byte, error) {
	encoded = strings.TrimSpace(encoded)
	if b, err := base64.StdEncoding.DecodeString(encoded); err == nil && len(b) == chacha20poly1305.KeySize {
		return b, nil
	}
	if b, err := base64.RawStdEncoding.DecodeString(encoded); err == nil && len(b) == chacha20poly1305.KeySize {
		return b, nil
	}
	if b, err := hex.DecodeString(encoded); err == nil && len(b) == chacha20poly1305.KeySize {
		return b, nil
	}
	return nil, fmt.Errorf("expected 32 bytes in base64 or hex")
}

func encrypt(key []byte, ref string, plaintext []byte) (nonce, ciphertext []byte, err error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	// The ref is additional data so a ciphertext cannot be moved between refs.
	ciphertext = aead.Seal(nil, nonce, plaintext, []byte(ref))
	return nonce, ciphertext, nil
}

func decrypt(key []byte, ref string, e entry) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	nonce, err := base64.StdEncoding.DecodeString(e.Nonce)
	if err != nil {
		return nil, err
	}
	if len(nonce) != aead.NonceSize() {
		return nil, fmt.Errorf("secret %s: nonce length %d, want %d", ref, len(nonce), aead.NonceSize())
	}
	ct, err := base64.StdEncoding.DecodeString(e.Ciphertext)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce, ct, []byte(ref))
}
