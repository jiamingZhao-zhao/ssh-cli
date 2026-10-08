package catalog

import (
	"fmt"
	"sort"
	"strings"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/config"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/guard"
)

// PolicyDraft is a named policy add or edit.
// AllowEmpty stores an empty allow-list (deny every command at this layer).
// UnsetAllow clears the allow-list so the layer does not constrain commands.
// ServiceEmpty stores an empty service-action list.
type PolicyDraft struct {
	Name           string
	Mode           string
	Allow          []string
	Deny           []string
	Confirm        []string
	ProtectedPaths []string
	Upload         *bool
	Download       *bool
	Forward        *bool
	Relay          string
	Service        []string

	Replace      bool
	HasMode      bool
	HasAllow     bool
	AllowEmpty   bool
	UnsetAllow   bool
	HasDeny      bool
	ClearDeny    bool
	HasConfirm   bool
	ClearConfirm bool
	HasPaths     bool
	ClearPaths   bool
	HasUpload    bool
	HasDownload  bool
	HasForward   bool
	HasRelay     bool
	ClearRelay   bool
	HasService   bool
	ServiceEmpty bool
	UnsetService bool
}

// PolicyView is the list form shared by the CLI and the localhost UI.
type PolicyView struct {
	Name           string   `json:"name"`
	Source         string   `json:"source"`
	Mode           string   `json:"mode,omitempty"`
	Allow          []string `json:"allow,omitempty"`
	AllowUniversal bool     `json:"allowUniversal,omitempty"`
	AllowEmpty     bool     `json:"allowEmpty,omitempty"`
	Deny           []string `json:"deny,omitempty"`
	Confirm        []string `json:"confirm,omitempty"`
	ProtectedPaths []string `json:"protectedPaths,omitempty"`
	Upload         *bool    `json:"upload,omitempty"`
	Download       *bool    `json:"download,omitempty"`
	Forward        *bool    `json:"forward,omitempty"`
	Relay          string   `json:"relay,omitempty"`
	Service        []string `json:"service,omitempty"`
	ServiceEmpty   bool     `json:"serviceEmpty,omitempty"`
}

// ListPolicies returns file policies and built-ins. A file entry with a built-in
// name is an override and is what the policy engine will use.
func ListPolicies(cfg *config.Config) []PolicyView {
	names := map[string]bool{}
	for _, n := range guard.BuiltinNames() {
		names[n] = true
	}
	if cfg != nil {
		for n := range cfg.Policies {
			names[n] = true
		}
	}
	ordered := make([]string, 0, len(names))
	for n := range names {
		ordered = append(ordered, n)
	}
	sort.Strings(ordered)
	out := make([]PolicyView, 0, len(ordered))
	for _, name := range ordered {
		_, builtin := guard.Builtin(name)
		_, file := filePolicy(cfg, name)
		source := "file"
		switch {
		case builtin && file:
			source = "override"
		case builtin:
			source = "builtin"
		}
		pol := effectivePolicy(cfg, name)
		out = append(out, viewOf(name, source, pol))
	}
	return out
}

func filePolicy(cfg *config.Config, name string) (*config.Policy, bool) {
	if cfg == nil || cfg.Policies == nil {
		return nil, false
	}
	p, ok := cfg.Policies[name]
	return p, ok && p != nil
}

func effectivePolicy(cfg *config.Config, name string) *config.Policy {
	if p, ok := filePolicy(cfg, name); ok {
		return p
	}
	p, _ := guard.Builtin(name)
	return p
}

func viewOf(name, source string, pol *config.Policy) PolicyView {
	v := PolicyView{Name: name, Source: source, AllowUniversal: true}
	if pol == nil {
		return v
	}
	if pol.Mode != "" {
		v.Mode = string(pol.Mode)
	}
	if pol.Allow == nil {
		v.AllowUniversal = true
	} else {
		v.AllowUniversal = false
		v.Allow = append([]string(nil), (*pol.Allow)...)
		v.AllowEmpty = len(v.Allow) == 0
	}
	v.Deny = append([]string(nil), pol.Deny...)
	v.Confirm = append([]string(nil), pol.Confirm...)
	v.ProtectedPaths = append([]string(nil), pol.ProtectedPaths...)
	if pol.Capabilities != nil {
		v.Upload = pol.Capabilities.Upload
		v.Download = pol.Capabilities.Download
		v.Forward = pol.Capabilities.Forward
		v.Relay = string(pol.Capabilities.Relay)
		if pol.Capabilities.Service != nil {
			v.Service = append([]string(nil), (*pol.Capabilities.Service)...)
			v.ServiceEmpty = len(v.Service) == 0
		}
	}
	return v
}

// AddPolicy writes a new named policy. Built-in names must be overridden with EditPolicy.
func AddPolicy(dir string, in PolicyDraft) error {
	return config.Update(dir, func(cfg *config.Config) error {
		return addPolicy(cfg, in)
	})
}

func addPolicy(cfg *config.Config, in PolicyDraft) error {
	name := strings.TrimSpace(in.Name)
	if !config.ValidName(name) {
		return fmt.Errorf("invalid policy name %q", name)
	}
	if _, ok := filePolicy(cfg, name); ok {
		return fmt.Errorf("policy %q already exists", name)
	}
	if _, ok := guard.Builtin(name); ok {
		return fmt.Errorf("policy %q is built-in; use policy edit to override it", name)
	}
	pol, err := in.materialize()
	if err != nil {
		return err
	}
	if cfg.Policies == nil {
		cfg.Policies = map[string]*config.Policy{}
	}
	cfg.Policies[name] = pol
	return nil
}

// EditPolicy updates a file policy, or writes an override of a built-in.
// Replace stores the draft as the whole policy. Otherwise only Has* fields change.
func EditPolicy(dir string, in PolicyDraft) error {
	return config.Update(dir, func(cfg *config.Config) error {
		return editPolicy(cfg, in)
	})
}

func editPolicy(cfg *config.Config, in PolicyDraft) error {
	name := strings.TrimSpace(in.Name)
	if !config.ValidName(name) {
		return fmt.Errorf("invalid policy name %q", name)
	}
	current, inFile := filePolicy(cfg, name)
	builtin, isBuiltin := guard.Builtin(name)
	if !inFile && !isBuiltin {
		return fmt.Errorf("policy %q not found", name)
	}
	var pol *config.Policy
	var err error
	if in.Replace {
		pol, err = in.materialize()
	} else {
		base := current
		if base == nil {
			base = builtin
		}
		pol, err = overlayPolicy(base, in)
	}
	if err != nil {
		return err
	}
	if cfg.Policies == nil {
		cfg.Policies = map[string]*config.Policy{}
	}
	cfg.Policies[name] = pol
	return nil
}

// RemovePolicy deletes a file entry. A built-in that was overridden becomes the
// built-in again. A custom policy that is still referenced is refused.
func RemovePolicy(dir, name string) error {
	return config.Update(dir, func(cfg *config.Config) error {
		return removePolicy(cfg, name)
	})
}

func removePolicy(cfg *config.Config, name string) error {
	name = strings.TrimSpace(name)
	if _, ok := filePolicy(cfg, name); !ok {
		if _, builtin := guard.Builtin(name); builtin {
			return fmt.Errorf("policy %q is built-in and is not overridden", name)
		}
		return fmt.Errorf("policy %q not found", name)
	}
	if _, builtin := guard.Builtin(name); !builtin {
		if users := policyUsers(cfg, name); len(users) > 0 {
			return fmt.Errorf("policy %q is still used by %s", name, strings.Join(users, ", "))
		}
	}
	delete(cfg.Policies, name)
	return nil
}

func policyUsers(cfg *config.Config, name string) []string {
	var users []string
	for en, env := range cfg.Envs {
		if env != nil && env.DefaultPolicy == name {
			users = append(users, "env "+en)
		}
	}
	for gn, g := range cfg.Groups {
		if g == nil {
			continue
		}
		if g.Policy == name {
			users = append(users, "group "+gn)
		}
		for alias, h := range g.Hosts {
			if h != nil && h.Policy == name {
				users = append(users, "host "+alias)
			}
		}
	}
	sort.Strings(users)
	return users
}

func (d PolicyDraft) materialize() (*config.Policy, error) {
	p := &config.Policy{}
	if strings.TrimSpace(d.Mode) != "" {
		mode := config.Mode(strings.TrimSpace(d.Mode))
		if !mode.Valid() {
			return nil, fmt.Errorf("invalid mode %q", d.Mode)
		}
		p.Mode = mode
	}
	if d.AllowEmpty {
		empty := []string{}
		p.Allow = &empty
	} else if d.HasAllow {
		cp := cleanList(d.Allow)
		if cp == nil {
			cp = []string{}
		}
		p.Allow = &cp
	}
	p.Deny = cleanList(d.Deny)
	p.Confirm = cleanList(d.Confirm)
	p.ProtectedPaths = cleanList(d.ProtectedPaths)
	caps, err := d.capsFromScratch()
	if err != nil {
		return nil, err
	}
	p.Capabilities = caps
	return p, nil
}

func (d PolicyDraft) capsFromScratch() (*config.Capabilities, error) {
	caps := &config.Capabilities{}
	set := false
	if d.Upload != nil {
		caps.Upload = d.Upload
		set = true
	}
	if d.Download != nil {
		caps.Download = d.Download
		set = true
	}
	if d.Forward != nil {
		caps.Forward = d.Forward
		set = true
	}
	if strings.TrimSpace(d.Relay) != "" {
		mode, err := parseRelay(d.Relay)
		if err != nil {
			return nil, err
		}
		caps.Relay = mode
		set = true
	}
	if d.ServiceEmpty {
		empty := []string{}
		caps.Service = &empty
		set = true
	} else if len(d.Service) > 0 || d.HasService {
		cp := cleanList(d.Service)
		if cp == nil {
			cp = []string{}
		}
		caps.Service = &cp
		set = true
	}
	if !set {
		return nil, nil
	}
	return caps, nil
}

func overlayPolicy(base *config.Policy, d PolicyDraft) (*config.Policy, error) {
	if base == nil {
		base = &config.Policy{}
	}
	out := clonePolicy(base)
	if !d.changed() {
		return nil, fmt.Errorf("no changes given")
	}
	if d.HasMode {
		if strings.TrimSpace(d.Mode) == "" {
			out.Mode = ""
		} else {
			mode := config.Mode(strings.TrimSpace(d.Mode))
			if !mode.Valid() {
				return nil, fmt.Errorf("invalid mode %q", d.Mode)
			}
			out.Mode = mode
		}
	}
	switch {
	case d.UnsetAllow:
		out.Allow = nil
	case d.AllowEmpty:
		empty := []string{}
		out.Allow = &empty
	case d.HasAllow:
		cp := cleanList(d.Allow)
		if cp == nil {
			cp = []string{}
		}
		out.Allow = &cp
	}
	if d.ClearDeny {
		out.Deny = nil
	} else if d.HasDeny {
		out.Deny = cleanList(d.Deny)
	}
	if d.ClearConfirm {
		out.Confirm = nil
	} else if d.HasConfirm {
		out.Confirm = cleanList(d.Confirm)
	}
	if d.ClearPaths {
		out.ProtectedPaths = nil
	} else if d.HasPaths {
		out.ProtectedPaths = cleanList(d.ProtectedPaths)
	}
	if err := overlayCaps(out, d); err != nil {
		return nil, err
	}
	return out, nil
}

func (d PolicyDraft) changed() bool {
	return d.HasMode || d.HasAllow || d.AllowEmpty || d.UnsetAllow || d.HasDeny || d.ClearDeny ||
		d.HasConfirm || d.ClearConfirm || d.HasPaths || d.ClearPaths || d.HasUpload || d.HasDownload ||
		d.HasForward || d.HasRelay || d.ClearRelay || d.HasService || d.ServiceEmpty || d.UnsetService
}

func overlayCaps(out *config.Policy, d PolicyDraft) error {
	touch := d.HasUpload || d.HasDownload || d.HasForward || d.HasRelay || d.ClearRelay || d.HasService || d.ServiceEmpty || d.UnsetService
	if !touch {
		return nil
	}
	if out.Capabilities == nil {
		out.Capabilities = &config.Capabilities{}
	}
	caps := out.Capabilities
	if d.HasUpload {
		caps.Upload = cloneBool(d.Upload)
	}
	if d.HasDownload {
		caps.Download = cloneBool(d.Download)
	}
	if d.HasForward {
		caps.Forward = cloneBool(d.Forward)
	}
	if d.ClearRelay {
		caps.Relay = ""
	} else if d.HasRelay {
		mode, err := parseRelay(d.Relay)
		if err != nil {
			return err
		}
		caps.Relay = mode
	}
	switch {
	case d.UnsetService:
		caps.Service = nil
	case d.ServiceEmpty:
		empty := []string{}
		caps.Service = &empty
	case d.HasService:
		cp := cleanList(d.Service)
		if cp == nil {
			cp = []string{}
		}
		caps.Service = &cp
	}
	return nil
}

func parseRelay(s string) (config.RelayMode, error) {
	switch config.RelayMode(strings.TrimSpace(s)) {
	case config.RelayAllow:
		return config.RelayAllow, nil
	case config.RelayDeny:
		return config.RelayDeny, nil
	case config.RelaySourceOnly:
		return config.RelaySourceOnly, nil
	default:
		return "", fmt.Errorf("invalid relay %q (want allow, deny, or source-only)", s)
	}
}

func clonePolicy(p *config.Policy) *config.Policy {
	if p == nil {
		return &config.Policy{}
	}
	out := *p
	if p.Allow != nil {
		cp := append([]string(nil), (*p.Allow)...)
		out.Allow = &cp
	}
	out.Deny = append([]string(nil), p.Deny...)
	out.Confirm = append([]string(nil), p.Confirm...)
	out.ProtectedPaths = append([]string(nil), p.ProtectedPaths...)
	if p.Capabilities != nil {
		c := *p.Capabilities
		c.Upload = cloneBool(p.Capabilities.Upload)
		c.Download = cloneBool(p.Capabilities.Download)
		c.Forward = cloneBool(p.Capabilities.Forward)
		if p.Capabilities.Service != nil {
			s := append([]string(nil), (*p.Capabilities.Service)...)
			c.Service = &s
		}
		out.Capabilities = &c
	}
	return &out
}

func cloneBool(b *bool) *bool {
	if b == nil {
		return nil
	}
	v := *b
	return &v
}
