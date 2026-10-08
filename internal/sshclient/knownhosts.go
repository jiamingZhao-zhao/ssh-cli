// Package sshclient dials SSH servers and enforces TOFU host keys.
package sshclient

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/fsutil"
)

// HostKeyChangedError means the server key does not match known_hosts.
type HostKeyChangedError struct {
	Host        string
	Fingerprint string
}

func (e *HostKeyChangedError) Error() string {
	return fmt.Sprintf("host key for %s changed (server presented %s); refusing. If this is expected, remove the old line from known_hosts", e.Host, e.Fingerprint)
}

var khMu sync.Mutex

// HostKeyCallback returns a TOFU callback. The first key seen for a host is
// stored in path. A later different key is rejected. insecure accepts any key
// and writes nothing.
func HostKeyCallback(path string, insecure bool) ssh.HostKeyCallback {
	if insecure {
		return ssh.InsecureIgnoreHostKey()
	}
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		return fsutil.WithLock(filepath.Dir(path), func() error {
			khMu.Lock()
			defer khMu.Unlock()
			return trustHostKey(path, hostname, remote, key)
		})
	}
}

func trustHostKey(path, hostname string, remote net.Addr, key ssh.PublicKey) error {
	if err := ensureFile(path); err != nil {
		return err
	}
	cb, err := knownhosts.New(path)
	if err != nil {
		return fmt.Errorf("read known_hosts: %w", err)
	}
	err = cb(hostname, remote, key)
	if err == nil {
		return nil
	}
	var ke *knownhosts.KeyError
	if errors.As(err, &ke) && len(ke.Want) == 0 {
		return appendKnownHost(path, hostname, key)
	}
	if ke != nil && len(ke.Want) > 0 {
		return &HostKeyChangedError{Host: hostname, Fingerprint: ssh.FingerprintSHA256(key)}
	}
	var rev *knownhosts.RevokedError
	if errors.As(err, &rev) {
		return &HostKeyChangedError{Host: hostname, Fingerprint: ssh.FingerprintSHA256(key)}
	}
	return err
}

// KnownHost is one trusted key in a known_hosts file.
// Marker is the hostname field as stored (often [host]:port).
type KnownHost struct {
	Marker      string `json:"marker"`
	KeyType     string `json:"keyType"`
	Fingerprint string `json:"fingerprint"`
	Comment     string `json:"comment,omitempty"`
	Revoked     bool   `json:"revoked,omitempty"`
}

// ListKnownHosts reads path. A missing file is an empty list.
// Hashed entries are returned with their hashed marker; they are not reversed.
func ListKnownHosts(path string) ([]KnownHost, error) {
	var out []KnownHost
	err := fsutil.WithLock(filepath.Dir(path), func() error {
		f, err := os.Open(path)
		if errors.Is(err, os.ErrNotExist) {
			out = []KnownHost{}
			return nil
		}
		if err != nil {
			return err
		}
		defer f.Close()
		parsed, err := parseKnownHosts(f)
		if err != nil {
			return err
		}
		out = parsed
		return nil
	})
	if out == nil && err == nil {
		out = []KnownHost{}
	}
	return out, err
}

// RemoveKnownHost deletes lines whose hostname matches marker.
// Matching accepts host, host:port, and [host]:port. It does not trust a new
// key; the next connection records the first key it sees (TOFU). A key that
// still has a stored line is rejected when it changes.
func RemoveKnownHost(path, marker string) (int, error) {
	marker = strings.TrimSpace(marker)
	if marker == "" {
		return 0, fmt.Errorf("empty known_hosts marker")
	}
	removed := 0
	err := fsutil.WithLock(filepath.Dir(path), func() error {
		data, err := os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("known_hosts entry %q not found", marker)
		}
		if err != nil {
			return err
		}
		lines := bytes.Split(data, []byte("\n"))
		var kept [][]byte
		for _, line := range lines {
			trim := bytes.TrimSpace(line)
			if len(trim) == 0 || trim[0] == '#' {
				kept = append(kept, line)
				continue
			}
			hostField, _, _, _, revoked, ok := splitKnownHost(string(trim))
			if !ok {
				kept = append(kept, line)
				continue
			}
			if !revoked && hostMatches(hostField, marker) {
				removed++
				continue
			}
			if revoked && hostMatches(hostField, marker) {
				removed++
				continue
			}
			kept = append(kept, line)
		}
		if removed == 0 {
			return fmt.Errorf("known_hosts entry %q not found", marker)
		}
		body := bytes.Join(kept, []byte("\n"))
		if len(body) > 0 && !bytes.HasSuffix(body, []byte("\n")) {
			body = append(body, '\n')
		}
		return fsutil.WriteAtomic(path, body, 0o600)
	})
	return removed, err
}

func parseKnownHosts(r *os.File) ([]KnownHost, error) {
	var out []KnownHost
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		hostField, keyType, keyBody, comment, revoked, ok := splitKnownHost(line)
		if !ok {
			return nil, fmt.Errorf("malformed known_hosts line")
		}
		pub, parsedComment, _, _, err := ssh.ParseAuthorizedKey([]byte(keyType + " " + keyBody + " " + comment))
		if err != nil {
			return nil, fmt.Errorf("malformed known_hosts key: %w", err)
		}
		if parsedComment != "" {
			comment = parsedComment
		}
		out = append(out, KnownHost{
			Marker:      hostField,
			KeyType:     pub.Type(),
			Fingerprint: ssh.FingerprintSHA256(pub),
			Comment:     comment,
			Revoked:     revoked,
		})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if out == nil {
		out = []KnownHost{}
	}
	return out, nil
}

func splitKnownHost(line string) (hostField, keyType, keyBody, comment string, revoked, ok bool) {
	fields := strings.Fields(line)
	i := 0
	if len(fields) > 0 && strings.HasPrefix(fields[0], "@") {
		revoked = fields[0] == "@revoked"
		i = 1
	}
	if len(fields) < i+3 {
		return "", "", "", "", false, false
	}
	hostField = fields[i]
	keyType = fields[i+1]
	keyBody = fields[i+2]
	if i+3 < len(fields) {
		comment = strings.Join(fields[i+3:], " ")
	}
	return hostField, keyType, keyBody, comment, revoked, true
}

func hostMatches(stored, query string) bool {
	for _, token := range strings.Split(stored, ",") {
		token = strings.TrimSpace(token)
		if token == "" {
			continue
		}
		if token == query || normalizeMarker(token) == normalizeMarker(query) {
			return true
		}
	}
	return false
}

// normalizeMarker maps host, host:port, and [host]:port onto one form.
// Hashed |1| markers are compared as written.
func normalizeMarker(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || strings.HasPrefix(s, "|") {
		return s
	}
	if strings.HasPrefix(s, "[") {
		end := strings.Index(s, "]")
		if end > 1 && end+1 < len(s) && s[end+1] == ':' {
			host := s[1:end]
			port := s[end+2:]
			if port == "22" {
				return host
			}
			return "[" + host + "]:" + port
		}
	}
	if host, port, err := net.SplitHostPort(s); err == nil {
		if port == "22" {
			return host
		}
		return "[" + host + "]:" + port
	}
	return s
}

func ensureFile(path string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	return f.Close()
}

func appendKnownHost(path, hostname string, key ssh.PublicKey) error {
	line := knownhosts.Line([]string{hostname}, key)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := fmt.Fprintln(f, line); err != nil {
		return err
	}
	return nil
}
