// Package policyhmac signs and checks the policy-relevant part of hosts.yaml,
// including each host's address, port, user, and auth.
// The sidecar is <config>/policy.mac. A missing file is allowed only until the
// config has been signed (policySigned in hosts.yaml). HMAC does not replace
// the human confirmation gate. Deleting policy.mac without `policy unsign`
// refuses to load. A v1 sidecar does not cover connection identity and must
// be rewritten with `policy sign`.
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
	"sync/atomic"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/config"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/fsutil"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/secrets"
)

const (
	fileName = "policy.mac"
	domainV1 = "ssh-cli-policy-hmac-v1"
	domainV2 = "ssh-cli-policy-hmac-v2"
)

// ErrNeedsResign means policy.mac is a valid v1 sidecar. It does not cover
// host, port, user, or auth, so Load refuses it until `policy sign`.
var ErrNeedsResign = errors.New("policy hmac: policy.mac does not cover connection identity; run ssh-cli policy sign")

// ErrMissingMac means hosts.yaml says the config was signed and policy.mac is gone.
var ErrMissingMac = errors.New("policy hmac: policy.mac missing for a signed config; restore the file or run ssh-cli policy unsign")

var signHold atomic.Int32

// Install attaches verify-on-load and sign-on-save. Config package tests stay
// unsigned until a caller installs the hooks.
func Install() {
	config.VerifyPolicy = Verify
	config.SignOnSave = Sign
	config.BeforeSave = noteSigned
}

// MacPath is the sidecar next to hosts.yaml.
func MacPath(dir string) string { return filepath.Join(dir, fileName) }

func noteSigned(dir string, cfg *config.Config) error {
	if signingPaused() || cfg == nil {
		return nil
	}
	if _, err := secrets.MasterMaterial(dir, false); err != nil {
		if errors.Is(err, secrets.ErrNoMasterKey) {
			return nil
		}
		return err
	}
	cfg.PolicySigned = true
	return nil
}

func signingPaused() bool { return signHold.Load() > 0 }

func withoutSign(fn func() error) error {
	signHold.Add(1)
	defer signHold.Add(-1)
	return fn()
}

// Verify checks policy.mac when it exists. A missing sidecar is allowed only
// for a config that has never been signed.
func Verify(dir string, cfg *config.Config) error {
	raw, err := os.ReadFile(MacPath(dir))
	if errors.Is(err, os.ErrNotExist) {
		if cfg != nil && cfg.PolicySigned {
			return ErrMissingMac
		}
		return nil
	}
	if err != nil {
		return err
	}
	ver, want, err := parseMac(raw)
	if err != nil {
		return err
	}
	key, err := secrets.MasterMaterial(dir, false)
	if err != nil {
		return fmt.Errorf("policy hmac: %w", err)
	}
	switch ver {
	case "v1":
		if hmac.Equal(want, checksum(domainV1, key, canonicalV1(cfg))) {
			return ErrNeedsResign
		}
		return fmt.Errorf("policy hmac mismatch")
	case "v2":
		if !hmac.Equal(want, checksum(domainV2, key, canonical(cfg))) {
			return fmt.Errorf("policy hmac mismatch")
		}
		return nil
	default:
		return fmt.Errorf("policy hmac: unrecognized policy.mac")
	}
}

// Sign writes policy.mac when a master key already exists. With no key it
// leaves any existing sidecar untouched and returns nil.
func Sign(dir string, cfg *config.Config) error {
	if signingPaused() {
		return nil
	}
	key, err := secrets.MasterMaterial(dir, false)
	if err != nil {
		if errors.Is(err, secrets.ErrNoMasterKey) {
			if cfg != nil && cfg.PolicySigned {
				return fmt.Errorf("policy hmac: signed config has no master key")
			}
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

// Remove deletes policy.mac and clears policySigned. The next load is unsigned.
// A later save that still has a master key signs again.
func Remove(dir string) error {
	return withoutSign(func() error {
		clear := func(cfg *config.Config) error {
			cfg.PolicySigned = false
			err := os.Remove(MacPath(dir))
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
			return nil
		}
		err := config.Update(dir, clear)
		if err == nil || (!errors.Is(err, ErrMissingMac) && !errors.Is(err, ErrNeedsResign)) {
			return err
		}
		cfg, rerr := config.ReadUnverified(dir)
		if rerr != nil {
			return rerr
		}
		if err := clear(cfg); err != nil {
			return err
		}
		return config.Save(dir, cfg)
	})
}

func writeMac(dir string, key []byte, cfg *config.Config) error {
	sum := checksum(domainV2, key, canonical(cfg))
	body := "v2\n" + hex.EncodeToString(sum) + "\n"
	return fsutil.WriteAtomic(MacPath(dir), []byte(body), 0o600)
}

func parseMac(raw []byte) (string, []byte, error) {
	text := strings.TrimSpace(string(raw))
	lines := strings.Split(text, "\n")
	if len(lines) < 2 {
		return "", nil, fmt.Errorf("policy hmac: unrecognized policy.mac")
	}
	ver := strings.TrimSpace(lines[0])
	if ver != "v1" && ver != "v2" {
		return "", nil, fmt.Errorf("policy hmac: unrecognized policy.mac")
	}
	sum, err := hex.DecodeString(strings.TrimSpace(lines[1]))
	if err != nil || len(sum) != sha256.Size {
		return "", nil, fmt.Errorf("policy hmac: unrecognized policy.mac")
	}
	return ver, sum, nil
}

func checksum(domain string, master, msg []byte) []byte {
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
	Host           string               `json:"host,omitempty"`
	Port           int                  `json:"port,omitempty"`
	User           string               `json:"user,omitempty"`
	Auth           string               `json:"auth,omitempty"`
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
					Host: strings.TrimSpace(h.Host), Port: h.PortOrDefault(), User: h.User, Auth: hostAuth(h),
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

func hostAuth(h *config.Host) string {
	if h == nil || strings.TrimSpace(h.Auth) == "" {
		return "password"
	}
	return h.Auth
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

// canonicalV1 is the 0.4.1 document. It omits host, port, user, and auth.
// A matching v1 sidecar is rejected with ErrNeedsResign rather than trusted.
type canonV1 struct {
	Policies map[string]policyCanon  `json:"policies,omitempty"`
	Envs     map[string]envCanon     `json:"envs,omitempty"`
	Groups   map[string]groupCanonV1 `json:"groups,omitempty"`
}

type groupCanonV1 struct {
	Env            string                 `json:"env,omitempty"`
	Policy         string                 `json:"policy,omitempty"`
	Allow          *[]string              `json:"allow,omitempty"`
	Deny           []string               `json:"deny,omitempty"`
	Confirm        []string               `json:"confirm,omitempty"`
	Capabilities   *config.Capabilities   `json:"capabilities,omitempty"`
	ProtectedPaths []string               `json:"protectedPaths,omitempty"`
	Hosts          map[string]hostCanonV1 `json:"hosts,omitempty"`
}

type hostCanonV1 struct {
	Policy         string               `json:"policy,omitempty"`
	Allow          *[]string            `json:"allow,omitempty"`
	Deny           []string             `json:"deny,omitempty"`
	Confirm        []string             `json:"confirm,omitempty"`
	Capabilities   *config.Capabilities `json:"capabilities,omitempty"`
	ProtectedPaths []string             `json:"protectedPaths,omitempty"`
}

func canonicalV1(cfg *config.Config) []byte {
	c := canonV1{}
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
				c.Groups = map[string]groupCanonV1{}
			}
			gc := groupCanonV1{
				Env: g.Env, Policy: g.Policy, Allow: copyAllow(g.Allow), Deny: nilEmpty(g.Deny),
				Confirm: nilEmpty(g.Confirm), Capabilities: g.Capabilities, ProtectedPaths: nilEmpty(g.ProtectedPaths),
			}
			for alias, h := range g.Hosts {
				if h == nil {
					continue
				}
				if gc.Hosts == nil {
					gc.Hosts = map[string]hostCanonV1{}
				}
				gc.Hosts[alias] = hostCanonV1{
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
