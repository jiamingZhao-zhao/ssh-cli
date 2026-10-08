// Package config loads and stores hosts.yaml.
//
// A host belongs to exactly one group. The group carries exactly one env label,
// and the host inherits it — hosts cannot set env. Tags select hosts only.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"

	"gopkg.in/yaml.v3"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/fsutil"
)

const (
	// FileName is the config document inside the config directory.
	FileName = "hosts.yaml"
	// KnownHostsName is the TOFU host key store.
	KnownHostsName = "known_hosts"
)

// nameRe matches aliases, group names, env names, and policy names.
var nameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)

// Mode is an ordered permission ceiling: readonly ⊂ standard ⊂ admin.
type Mode string

const (
	ModeUnset    Mode = ""
	ModeReadonly Mode = "readonly"
	ModeStandard Mode = "standard"
	ModeAdmin    Mode = "admin"
)

// Rank returns 1..3, or 0 when unset.
func (m Mode) Rank() int {
	switch m {
	case ModeReadonly:
		return 1
	case ModeStandard:
		return 2
	case ModeAdmin:
		return 3
	default:
		return 0
	}
}

// Valid reports whether m is a known mode. Unset is not valid for maxMode.
func (m Mode) Valid() bool {
	return m == ModeReadonly || m == ModeStandard || m == ModeAdmin
}

// Stricter returns the tighter of a and b. An unset mode does not constrain.
func Stricter(a, b Mode) Mode {
	ar, br := a.Rank(), b.Rank()
	if ar == 0 {
		return b
	}
	if br == 0 {
		return a
	}
	if ar < br {
		return a
	}
	return b
}

// UnmarshalYAML accepts only the three mode names.
func (m *Mode) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind != yaml.ScalarNode {
		return fmt.Errorf("mode must be a string")
	}
	got := Mode(value.Value)
	if got != ModeUnset && !got.Valid() {
		return fmt.Errorf("invalid mode %q (want readonly, standard, or admin)", value.Value)
	}
	*m = got
	return nil
}

// RelayMode is how relay is allowed. Iteration 1 only stores and displays it.
type RelayMode string

const (
	RelayUnset      RelayMode = ""
	RelayAllow      RelayMode = "allow"
	RelayDeny       RelayMode = "deny"
	RelaySourceOnly RelayMode = "source-only"
)

// UnmarshalYAML accepts source-only and bool-like true/false.
func (r *RelayMode) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind != yaml.ScalarNode {
		return fmt.Errorf("relay must be a string or bool")
	}
	switch value.Value {
	case "source-only":
		*r = RelaySourceOnly
	case "allow", "true":
		*r = RelayAllow
	case "deny", "false":
		*r = RelayDeny
	case "":
		*r = RelayUnset
	default:
		return fmt.Errorf("invalid relay %q", value.Value)
	}
	return nil
}

// Capabilities are ability switches. Nil pointers mean "not set at this layer".
type Capabilities struct {
	Upload   *bool     `yaml:"upload,omitempty"`
	Download *bool     `yaml:"download,omitempty"`
	Forward  *bool     `yaml:"forward,omitempty"`
	Relay    RelayMode `yaml:"relay,omitempty"`
	Service  *[]string `yaml:"service,omitempty"`
}

// Policy is a named allow/deny/confirm bundle.
type Policy struct {
	Mode           Mode          `yaml:"mode,omitempty"`
	Allow          *[]string     `yaml:"allow,omitempty"`
	Deny           []string      `yaml:"deny,omitempty"`
	Confirm        []string      `yaml:"confirm,omitempty"`
	Capabilities   *Capabilities `yaml:"capabilities,omitempty"`
	ProtectedPaths []string      `yaml:"protectedPaths,omitempty"`
}

// BreakGlass is stored for a later iteration and is not enforced yet.
type BreakGlass struct {
	Enabled bool   `yaml:"enabled,omitempty"`
	MaxTTL  string `yaml:"maxTtl,omitempty"`
}

// Env is a label definition. It is not a container; groups point at one env.
type Env struct {
	Label         string      `yaml:"label,omitempty"`
	Color         string      `yaml:"color,omitempty"`
	MaxMode       Mode        `yaml:"maxMode,omitempty"`
	DefaultPolicy string      `yaml:"defaultPolicy,omitempty"`
	BreakGlass    *BreakGlass `yaml:"breakGlass,omitempty"`
	NoDataOutflow bool        `yaml:"noDataOutflow,omitempty"`
}

// Group is the structural owner of hosts and of exactly one env label.
type Group struct {
	Env            string           `yaml:"env"`
	Policy         string           `yaml:"policy,omitempty"`
	Allow          *[]string        `yaml:"allow,omitempty"`
	Deny           []string         `yaml:"deny,omitempty"`
	Confirm        []string         `yaml:"confirm,omitempty"`
	Capabilities   *Capabilities    `yaml:"capabilities,omitempty"`
	ProtectedPaths []string         `yaml:"protectedPaths,omitempty"`
	Hosts          map[string]*Host `yaml:"hosts,omitempty"`
}

// Host is connection info plus optional tighter policy. It has no env field.
type Host struct {
	Host           string        `yaml:"host"`
	Port           int           `yaml:"port,omitempty"`
	User           string        `yaml:"user"`
	Auth           string        `yaml:"auth,omitempty"`
	PasswordRef    string        `yaml:"passwordRef,omitempty"`
	Identity       string        `yaml:"identity,omitempty"`
	Tags           []string      `yaml:"tags,omitempty"`
	Policy         string        `yaml:"policy,omitempty"`
	Allow          *[]string     `yaml:"allow,omitempty"`
	Deny           []string      `yaml:"deny,omitempty"`
	Confirm        []string      `yaml:"confirm,omitempty"`
	Capabilities   *Capabilities `yaml:"capabilities,omitempty"`
	ProtectedPaths []string      `yaml:"protectedPaths,omitempty"`
}

// PortOrDefault returns the TCP port, defaulting to 22.
func (h *Host) PortOrDefault() int {
	if h == nil || h.Port == 0 {
		return 22
	}
	return h.Port
}

// Config is the on-disk document.
type Config struct {
	Version  int                `yaml:"version"`
	Default  string             `yaml:"default,omitempty"`
	Policies map[string]*Policy `yaml:"policies,omitempty"`
	Envs     map[string]*Env    `yaml:"envs,omitempty"`
	Groups   map[string]*Group  `yaml:"groups,omitempty"`
	Tasks    map[string]any     `yaml:"tasks,omitempty"`
}

// VerifyPolicy is the extension point for HMAC verification of the policy
// section (PLAN 5.6). The default accepts the file.
var VerifyPolicy = func(data []byte) error { return nil }

// ResolvedHost is a host plus the group and env it inherits.
type ResolvedHost struct {
	Alias    string
	Group    string
	EnvName  string
	Env      *Env
	GroupDef *Group
	Host     *Host
}

// Selector chooses hosts. Empty means the configured default host.
// Hosts, groups, and tags are unioned. Env then filters the union.
type Selector struct {
	Hosts  []string
	Groups []string
	Tags   []string
	Env    string
}

func (s Selector) empty() bool {
	return len(s.Hosts) == 0 && len(s.Groups) == 0 && len(s.Tags) == 0 && s.Env == ""
}

// ValidName reports whether name can be an alias, group, env, or policy.
func ValidName(name string) bool { return nameRe.MatchString(name) }

// Load reads hosts.yaml. A missing file is an empty version-1 config.
func Load(dir string) (*Config, error) {
	path := filepath.Join(dir, FileName)
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return &Config{Version: 1}, nil
	}
	if err != nil {
		return nil, err
	}
	if err := VerifyPolicy(data); err != nil {
		return nil, err
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return &Config{Version: 1}, nil
	}
	if err := rejectHostEnv(data); err != nil {
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if cfg.Version == 0 {
		cfg.Version = 1
	}
	if cfg.Version != 1 {
		return nil, fmt.Errorf("unsupported config version %d", cfg.Version)
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// Save writes the full document atomically. Callers that hold the directory
// lock should use Save; everyone else should use Update.
func Save(dir string, cfg *Config) error {
	if cfg == nil {
		return fmt.Errorf("nil config")
	}
	if cfg.Version == 0 {
		cfg.Version = 1
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(cfg); err != nil {
		return err
	}
	_ = enc.Close()
	return fsutil.WriteAtomic(filepath.Join(dir, FileName), buf.Bytes(), 0o600)
}

// Update locks the config directory, reloads, applies fn, and saves when fn
// returns nil. A single-entry edit therefore rewrites the whole document from
// the latest on-disk copy instead of clobbering concurrent changes.
func Update(dir string, fn func(*Config) error) error {
	return fsutil.WithLock(dir, func() error {
		cfg, err := Load(dir)
		if err != nil {
			return err
		}
		if err := fn(cfg); err != nil {
			return err
		}
		return Save(dir, cfg)
	})
}

// Validate checks structural rules that must hold before a file is trusted.
func (c *Config) Validate() error {
	if c == nil {
		return fmt.Errorf("nil config")
	}
	for name, env := range c.Envs {
		if !ValidName(name) {
			return fmt.Errorf("invalid env name %q", name)
		}
		if env == nil {
			return fmt.Errorf("env %q is null", name)
		}
		if !env.MaxMode.Valid() {
			return fmt.Errorf("env %q: maxMode must be readonly, standard, or admin", name)
		}
		if env.DefaultPolicy != "" && !ValidName(env.DefaultPolicy) {
			return fmt.Errorf("env %q: invalid defaultPolicy %q", name, env.DefaultPolicy)
		}
	}
	for name, pol := range c.Policies {
		if !ValidName(name) {
			return fmt.Errorf("invalid policy name %q", name)
		}
		if pol == nil {
			return fmt.Errorf("policy %q is null", name)
		}
		if pol.Mode != ModeUnset && !pol.Mode.Valid() {
			return fmt.Errorf("policy %q: invalid mode %q", name, pol.Mode)
		}
	}
	seen := map[string]string{}
	for gname, g := range c.Groups {
		if !ValidName(gname) {
			return fmt.Errorf("invalid group name %q", gname)
		}
		if g == nil {
			return fmt.Errorf("group %q is null", gname)
		}
		if g.Env == "" {
			return fmt.Errorf("group %q: env is required", gname)
		}
		if _, ok := c.Envs[g.Env]; !ok {
			return fmt.Errorf("group %q: unknown env %q", gname, g.Env)
		}
		if g.Policy != "" && !ValidName(g.Policy) {
			return fmt.Errorf("group %q: invalid policy %q", gname, g.Policy)
		}
		for alias, h := range g.Hosts {
			if !ValidName(alias) {
				return fmt.Errorf("invalid host alias %q", alias)
			}
			if h == nil {
				return fmt.Errorf("host %q is null", alias)
			}
			if prev, ok := seen[alias]; ok {
				return fmt.Errorf("host alias %q appears in groups %q and %q", alias, prev, gname)
			}
			seen[alias] = gname
			if h.Host == "" {
				return fmt.Errorf("host %q: address is required", alias)
			}
			if h.User == "" {
				return fmt.Errorf("host %q: user is required", alias)
			}
			if h.Port < 0 || h.Port > 65535 {
				return fmt.Errorf("host %q: invalid port %d", alias, h.Port)
			}
			switch h.Auth {
			case "", "password", "key":
			default:
				return fmt.Errorf("host %q: unsupported auth %q", alias, h.Auth)
			}
			if h.Policy != "" && !ValidName(h.Policy) {
				return fmt.Errorf("host %q: invalid policy %q", alias, h.Policy)
			}
		}
	}
	if c.Default != "" {
		if _, ok := seen[c.Default]; !ok {
			return fmt.Errorf("default host %q does not exist", c.Default)
		}
	}
	return nil
}

// Index returns every host keyed by alias.
func (c *Config) Index() map[string]ResolvedHost {
	out := map[string]ResolvedHost{}
	if c == nil {
		return out
	}
	for gname, g := range c.Groups {
		if g == nil {
			continue
		}
		env := c.Envs[g.Env]
		for alias, h := range g.Hosts {
			out[alias] = ResolvedHost{
				Alias:    alias,
				Group:    gname,
				EnvName:  g.Env,
				Env:      env,
				GroupDef: g,
				Host:     h,
			}
		}
	}
	return out
}

// Find returns the host and its group.
func (c *Config) Find(alias string) (ResolvedHost, bool) {
	h, ok := c.Index()[alias]
	return h, ok
}

// Select resolves a selector to concrete hosts.
func (c *Config) Select(sel Selector) ([]ResolvedHost, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	index := c.Index()
	if sel.empty() {
		if c.Default == "" {
			return nil, fmt.Errorf("no host selected and no default host; pass -H, -g, or -t")
		}
		h, ok := index[c.Default]
		if !ok {
			return nil, fmt.Errorf("default host %q not found", c.Default)
		}
		return []ResolvedHost{h}, nil
	}
	var out []ResolvedHost
	seen := map[string]bool{}
	add := func(h ResolvedHost) {
		if seen[h.Alias] {
			return
		}
		seen[h.Alias] = true
		out = append(out, h)
	}
	explicit := map[string]bool{}
	for _, alias := range sel.Hosts {
		h, ok := index[alias]
		if !ok {
			return nil, fmt.Errorf("host %q not found", alias)
		}
		explicit[alias] = true
		add(h)
	}
	for _, gname := range sel.Groups {
		g, ok := c.Groups[gname]
		if !ok {
			return nil, fmt.Errorf("group %q not found", gname)
		}
		aliases := make([]string, 0, len(g.Hosts))
		for alias := range g.Hosts {
			aliases = append(aliases, alias)
		}
		sort.Strings(aliases)
		for _, alias := range aliases {
			add(index[alias])
		}
	}
	if len(sel.Tags) > 0 {
		var matched []string
		for alias, h := range index {
			if hasAnyTag(h.Host.Tags, sel.Tags) {
				matched = append(matched, alias)
			}
		}
		if len(matched) == 0 {
			return nil, fmt.Errorf("no host matches tags %v", sel.Tags)
		}
		sort.Strings(matched)
		for _, alias := range matched {
			add(index[alias])
		}
	}
	if sel.Env != "" {
		if _, ok := c.Envs[sel.Env]; !ok {
			return nil, fmt.Errorf("unknown env %q", sel.Env)
		}
		filtered := make([]ResolvedHost, 0, len(out))
		for _, h := range out {
			if h.EnvName != sel.Env {
				if explicit[h.Alias] {
					return nil, fmt.Errorf("host %q is in env %q, not %q", h.Alias, h.EnvName, sel.Env)
				}
				continue
			}
			filtered = append(filtered, h)
		}
		out = filtered
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no hosts selected")
	}
	return out, nil
}

func hasAnyTag(have, want []string) bool {
	set := map[string]bool{}
	for _, t := range have {
		set[t] = true
	}
	for _, t := range want {
		if set[t] {
			return true
		}
	}
	return false
}

// PasswordRefs returns every passwordRef currently in use.
func (c *Config) PasswordRefs() map[string]int {
	out := map[string]int{}
	for _, g := range c.Groups {
		if g == nil {
			continue
		}
		for _, h := range g.Hosts {
			if h != nil && h.PasswordRef != "" {
				out[h.PasswordRef]++
			}
		}
	}
	return out
}

func rejectHostEnv(data []byte) error {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return err
	}
	if len(doc.Content) == 0 {
		return nil
	}
	root := doc.Content[0]
	groups := mapChild(root, "groups")
	if groups == nil || groups.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(groups.Content); i += 2 {
		gname := groups.Content[i].Value
		gnode := groups.Content[i+1]
		hosts := mapChild(gnode, "hosts")
		if hosts == nil || hosts.Kind != yaml.MappingNode {
			continue
		}
		for j := 0; j+1 < len(hosts.Content); j += 2 {
			alias := hosts.Content[j].Value
			hnode := hosts.Content[j+1]
			if hnode.Kind != yaml.MappingNode {
				continue
			}
			for k := 0; k+1 < len(hnode.Content); k += 2 {
				if hnode.Content[k].Value == "env" {
					return fmt.Errorf("host %q in group %q cannot set env; env is inherited from the group", alias, gname)
				}
			}
		}
	}
	return nil
}

func mapChild(n *yaml.Node, key string) *yaml.Node {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}

// ExpandHome expands a leading ~/ using the current user's home directory.
func ExpandHome(path string) (string, error) {
	if path != "~" && len(path) >= 2 && path[:2] != "~/" && path[:2] != `~\` {
		return path, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	if path == "~" {
		return home, nil
	}
	return filepath.Join(home, path[2:]), nil
}
