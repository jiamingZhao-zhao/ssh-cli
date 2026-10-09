// Package policyhmac signs and checks the policy-relevant part of hosts.yaml.
// The sidecar is <config>/policy.mac. A missing file is a legacy unsigned
// config and is allowed. HMAC does not replace the human confirmation gate.
package policyhmac

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/config"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/fsutil"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/secrets"
)

const (
	fileName = "policy.mac"
	domain   = "ssh-cli-policy-hmac-v1"
)

// Install attaches verify-on-load and sign-on-save. Config package tests stay
// unsigned until a caller installs the hooks.
func Install() {
	config.VerifyPolicy = Verify
	config.SignOnSave = Sign
}

// MacPath is the sidecar next to hosts.yaml.
func MacPath(dir string) string { return filepath.Join(dir, fileName) }

// Verify checks policy.mac when it exists. A missing sidecar is allowed.
func Verify(dir string, cfg *config.Config) error {
	raw, err := os.ReadFile(MacPath(dir))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	want, err := parseMac(raw)
	if err != nil {
		return err
	}
	key, err := secrets.MasterMaterial(dir, false)
	if err != nil {
		return fmt.Errorf("policy hmac: %w", err)
	}
	got := checksum(key, canonical(cfg))
	if !hmac.Equal(want, got) {
		return fmt.Errorf("policy hmac mismatch")
	}
	return nil
}

// Sign writes policy.mac when a master key already exists. With no key it
// leaves any existing sidecar untouched and returns nil.
func Sign(dir string, cfg *config.Config) error {
	key, err := secrets.MasterMaterial(dir, false)
	if err != nil {
		if errors.Is(err, secrets.ErrNoMasterKey) {
			return nil
		}
		return err
	}
	return writeMac(dir, key, cfg)
}

// SignNew creates a master key when needed and writes policy.mac.
func SignNew(dir string, cfg *config.Config) error {
	key, err := secrets.MasterMaterial(dir, true)
	if err != nil {
		return err
	}
	return writeMac(dir, key, cfg)
}

// Remove deletes policy.mac so the next load is unsigned.
func Remove(dir string) error {
	err := os.Remove(MacPath(dir))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func writeMac(dir string, key []byte, cfg *config.Config) error {
	sum := checksum(key, canonical(cfg))
	body := "v1\n" + hex.EncodeToString(sum) + "\n"
	return fsutil.WriteAtomic(MacPath(dir), []byte(body), 0o600)
}

func parseMac(raw []byte) ([]byte, error) {
	text := strings.TrimSpace(string(raw))
	lines := strings.Split(text, "\n")
	if len(lines) < 2 || strings.TrimSpace(lines[0]) != "v1" {
		return nil, fmt.Errorf("policy hmac: unrecognized policy.mac")
	}
	sum, err := hex.DecodeString(strings.TrimSpace(lines[1]))
	if err != nil || len(sum) != sha256.Size {
		return nil, fmt.Errorf("policy hmac: unrecognized policy.mac")
	}
	return sum, nil
}

func checksum(master, msg []byte) []byte {
	k := hmac.New(sha256.New, master)
	_, _ = k.Write([]byte(domain))
	mac := hmac.New(sha256.New, k.Sum(nil))
	_, _ = mac.Write(msg)
	return mac.Sum(nil)
}

type canon struct {
	Policies map[string]policyCanon `json:"policies,omitempty"`
	Envs     map[string]envCanon    `json:"envs,omitempty"`
	Groups   map[string]groupCanon  `json:"groups,omitempty"`
}

type policyCanon struct {
	Mode           string               `json:"mode,omitempty"`
	Allow          *[]string            `json:"allow,omitempty"`
	Deny           []string             `json:"deny,omitempty"`
	Confirm        []string             `json:"confirm,omitempty"`
	Capabilities   *config.Capabilities `json:"capabilities,omitempty"`
	ProtectedPaths []string             `json:"protectedPaths,omitempty"`
}

type envCanon struct {
	MaxMode       string `json:"maxMode,omitempty"`
	DefaultPolicy string `json:"defaultPolicy,omitempty"`
	NoDataOutflow bool   `json:"noDataOutflow,omitempty"`
}

type groupCanon struct {
	Env            string               `json:"env,omitempty"`
	Policy         string               `json:"policy,omitempty"`
	Allow          *[]string            `json:"allow,omitempty"`
	Deny           []string             `json:"deny,omitempty"`
	Confirm        []string             `json:"confirm,omitempty"`
	Capabilities   *config.Capabilities `json:"capabilities,omitempty"`
	ProtectedPaths []string             `json:"protectedPaths,omitempty"`
	Hosts          map[string]hostCanon `json:"hosts,omitempty"`
}

type hostCanon struct {
	Policy         string               `json:"policy,omitempty"`
	Allow          *[]string            `json:"allow,omitempty"`
	Deny           []string             `json:"deny,omitempty"`
	Confirm        []string             `json:"confirm,omitempty"`
	Capabilities   *config.Capabilities `json:"capabilities,omitempty"`
	ProtectedPaths []string             `json:"protectedPaths,omitempty"`
}

func canonical(cfg *config.Config) []byte {
	c := canon{}
	if cfg != nil {
		for name, p := range cfg.Policies {
			if p == nil {
				continue
			}
			if c.Policies == nil {
				c.Policies = map[string]policyCanon{}
			}
			c.Policies[name] = policyCanon{
				Mode: string(p.Mode), Allow: copyAllow(p.Allow), Deny: nilEmpty(p.Deny),
				Confirm: nilEmpty(p.Confirm), Capabilities: p.Capabilities, ProtectedPaths: nilEmpty(p.ProtectedPaths),
			}
		}
		for name, e := range cfg.Envs {
			if e == nil {
				continue
			}
			if c.Envs == nil {
				c.Envs = map[string]envCanon{}
			}
			c.Envs[name] = envCanon{MaxMode: string(e.MaxMode), DefaultPolicy: e.DefaultPolicy, NoDataOutflow: e.NoDataOutflow}
		}
		for name, g := range cfg.Groups {
			if g == nil {
				continue
			}
			if c.Groups == nil {
				c.Groups = map[string]groupCanon{}
			}
			gc := groupCanon{
				Env: g.Env, Policy: g.Policy, Allow: copyAllow(g.Allow), Deny: nilEmpty(g.Deny),
				Confirm: nilEmpty(g.Confirm), Capabilities: g.Capabilities, ProtectedPaths: nilEmpty(g.ProtectedPaths),
			}
			for alias, h := range g.Hosts {
				if h == nil {
					continue
				}
				if gc.Hosts == nil {
					gc.Hosts = map[string]hostCanon{}
				}
				gc.Hosts[alias] = hostCanon{
					Policy: h.Policy, Allow: copyAllow(h.Allow), Deny: nilEmpty(h.Deny),
					Confirm: nilEmpty(h.Confirm), Capabilities: h.Capabilities, ProtectedPaths: nilEmpty(h.ProtectedPaths),
				}
			}
			c.Groups[name] = gc
		}
	}
	b, err := json.Marshal(c)
	if err != nil {
		return []byte("{}")
	}
	return b
}

func nilEmpty(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	return append([]string(nil), s...)
}

func copyAllow(s *[]string) *[]string {
	if s == nil {
		return nil
	}
	cp := append([]string(nil), (*s)...)
	return &cp
}
