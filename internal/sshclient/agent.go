package sshclient

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/config"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// AgentAuth uses an explicitly selected local SSH_AUTH_SOCK; it never forwards
// the agent to a server, exports a key, or falls back to another credential.
func AgentAuth(selected ...string) (ssh.AuthMethod, error) {
	fingerprint := ""
	if len(selected) > 1 {
		return nil, fmt.Errorf("select only one ssh-agent identity")
	}
	if len(selected) == 1 {
		fingerprint = selected[0]
	}
	if err := config.ValidateAgentKey("agent", fingerprint); err != nil {
		return nil, err
	}
	sock := strings.TrimSpace(os.Getenv("SSH_AUTH_SOCK"))
	if sock == "" {
		sock = defaultAgentSocket()
		if sock == "" {
			return nil, fmt.Errorf("agent auth requires SSH_AUTH_SOCK")
		}
	}
	return ssh.PublicKeysCallback(func() ([]ssh.Signer, error) {
		conn, err := connectAgent(sock)
		if err != nil {
			return nil, err
		}
		defer conn.Close()
		keys, err := agent.NewClient(conn).List()
		if err != nil {
			return nil, err
		}
		if len(keys) == 0 {
			return nil, fmt.Errorf("ssh-agent has no identities")
		}
		keys, err = selectAgentKeys(keys, fingerprint)
		if err != nil {
			return nil, err
		}
		if len(keys) > 16 {
			return nil, fmt.Errorf("ssh-agent has too many identities (limit 16); set agentKey to one fingerprint from ssh-add -l")
		}
		signers := make([]ssh.Signer, 0, len(keys))
		for _, key := range keys {
			signers = append(signers, &localAgentSigner{sock: sock, key: key})
		}
		return signers, nil
	}), nil
}

type agentConnection interface {
	io.ReadWriteCloser
	SetDeadline(time.Time) error
}

func connectAgent(sock string) (agentConnection, error) {
	conn, err := agentEndpoint(sock)
	if err != nil {
		return nil, fmt.Errorf("connect ssh-agent: %w", err)
	}
	if err := conn.SetDeadline(time.Now().Add(20 * time.Second)); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

type localAgentSigner struct {
	sock string
	key  ssh.PublicKey
}

func (s *localAgentSigner) PublicKey() ssh.PublicKey { return s.key }
func (s *localAgentSigner) Sign(r io.Reader, data []byte) (*ssh.Signature, error) {
	return s.SignWithAlgorithm(r, data, "")
}
func (s *localAgentSigner) SignWithAlgorithm(_ io.Reader, data []byte, algorithm string) (*ssh.Signature, error) {
	var flags agent.SignatureFlags
	switch algorithm {
	case "", s.key.Type():
	case ssh.KeyAlgoRSASHA256:
		flags = agent.SignatureFlagRsaSha256
	case ssh.KeyAlgoRSASHA512:
		flags = agent.SignatureFlagRsaSha512
	default:
		return nil, fmt.Errorf("unsupported agent signature algorithm %s", algorithm)
	}
	conn, err := connectAgent(s.sock)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	return agent.NewClient(conn).SignWithFlags(s.key, data, flags)
}

func selectAgentKeys(keys []*agent.Key, fingerprint string) ([]*agent.Key, error) {
	if fingerprint == "" {
		return keys, nil
	}
	for _, key := range keys {
		if ssh.FingerprintSHA256(key) == fingerprint {
			return []*agent.Key{key}, nil
		}
	}
	return nil, fmt.Errorf("selected ssh-agent identity is unavailable; check ssh-add -l")
}
