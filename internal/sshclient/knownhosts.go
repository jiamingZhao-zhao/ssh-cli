// Package sshclient dials SSH servers and enforces TOFU host keys.
package sshclient

import (
	"errors"
	"fmt"
	"net"
	"os"
	"sync"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
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
		khMu.Lock()
		defer khMu.Unlock()
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
