package sshclient

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestKnownHostsListAndRemove(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "known_hosts")
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherSigner, err := ssh.NewSignerFromKey(other)
	if err != nil {
		t.Fatal(err)
	}
	cb := HostKeyCallback(path, false)
	addr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 2222}
	if err := cb("127.0.0.1:2222", addr, signer.PublicKey()); err != nil {
		t.Fatal(err)
	}
	entries, err := ListKnownHosts(path)
	if err != nil || len(entries) != 1 {
		t.Fatalf("%v %+v", err, entries)
	}
	if entries[0].Fingerprint != ssh.FingerprintSHA256(signer.PublicKey()) {
		t.Fatalf("fingerprint %s", entries[0].Fingerprint)
	}
	if err := cb("127.0.0.1:2222", addr, otherSigner.PublicKey()); err == nil {
		t.Fatal("changed key was accepted while the entry existed")
	}
	n, err := RemoveKnownHost(path, "127.0.0.1:2222")
	if err != nil || n != 1 {
		t.Fatalf("remove %d %v marker %q", n, err, entries[0].Marker)
	}
	left, err := ListKnownHosts(path)
	if err != nil || len(left) != 0 {
		t.Fatalf("left %+v %v", left, err)
	}
	if err := cb("127.0.0.1:2222", addr, otherSigner.PublicKey()); err != nil {
		t.Fatal(err)
	}
	if _, err := RemoveKnownHost(path, "192.0.2.10"); err == nil {
		t.Fatal("missing marker should fail")
	}
}
