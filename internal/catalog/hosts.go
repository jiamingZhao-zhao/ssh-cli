package catalog

import (
	"fmt"
	"io"
	"strings"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/config"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/confirmgate"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/guard"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/secrets"
)

// Options configures secret storage. A nil Warn discards keyring warnings.
// HumanConfirm is the typed phrase for a prod leave, host move, address change,
// or policy widen. Actor is stored on the config_change audit record.
type Options struct {
	Warn         io.Writer
	HumanConfirm string
	Actor        string
}

// HostDraft is a host add or edit. Password is never written to hosts.yaml,
// audit records, or API responses. Has* fields distinguish "omitted" from "empty"
// on edit.
type HostDraft struct {
	Alias      string
	Group      string
	Address    string
	Port       *int
	User       string
	Password   string
	Identity   string
	Policy     string
	Tags       []string
	Via        string
	SetDefault bool
	ClearTags  bool
	ClearVia   bool

	HasGroup    bool
	HasAddress  bool
	HasPort     bool
	HasUser     bool
	HasPassword bool
	HasIdentity bool
	HasPolicy   bool
	HasTags     bool
	HasVia      bool
}

// AddHost creates one host. A password is stored through secrets.Store.
func AddHost(dir string, in HostDraft, opt Options) error {
	return config.Update(dir, func(cfg *config.Config) error {
		return addHost(dir, cfg, in, opt)
	})
}

func addHost(dir string, cfg *config.Config, in HostDraft, opt Options) error {
	alias := strings.TrimSpace(in.Alias)
	if !config.ValidName(alias) {
		return fmt.Errorf("invalid host alias %q", alias)
	}
	group := strings.TrimSpace(in.Group)
	address := strings.TrimSpace(in.Address)
	user := strings.TrimSpace(in.User)
	if group == "" || address == "" || user == "" {
		return fmt.Errorf("group, host, and user are required")
	}
	identity := strings.TrimSpace(in.Identity)
	if in.Password != "" && identity != "" {
		return fmt.Errorf("pass only one of password and identity")
	}
	if err := checkPortPtr(in.Port); err != nil {
		return err
	}
	if in.Password == "" && identity == "" {
		return fmt.Errorf("password or identity is required")
	}
	via := strings.TrimSpace(in.Via)
	if err := cfg.CheckJump(alias, via); err != nil {
		return err
	}
	if _, ok := cfg.Find(alias); ok {
		return fmt.Errorf("host %q already exists", alias)
	}
	g, ok := cfg.Groups[group]
	if !ok {
		return fmt.Errorf("group %q not found", group)
	}
	if in.Policy != "" && !guard.KnownPolicy(cfg, in.Policy) {
		return fmt.Errorf("unknown policy %q", in.Policy)
	}
	h := &config.Host{
		Host:   address,
		User:   user,
		Port:   normalizePortPtr(in.Port),
		Tags:   cleanList(in.Tags),
		Policy: in.Policy,
		Via:    via,
	}
	if identity != "" {
		h.Auth = "key"
		h.Identity = identity
	} else {
		h.Auth = "password"
		h.PasswordRef = group + "." + alias
		if err := putSecret(dir, h.PasswordRef, in.Password, opt); err != nil {
			return err
		}
	}
	if g.Hosts == nil {
		g.Hosts = map[string]*config.Host{}
	}
	g.Hosts[alias] = h
	if in.SetDefault {
		cfg.Default = alias
	}
	return nil
}

// UpdateHost edits one host. An empty password does not change the secret.
func UpdateHost(dir string, in HostDraft, opt Options) error {
	var needs []confirmgate.Need
	err := config.Update(dir, func(cfg *config.Config) error {
		n, err := updateHost(dir, cfg, in, opt)
		needs = n
		return err
	})
	if err != nil {
		return err
	}
	confirmgate.RecordOK(dir, opt.Actor, needs)
	return nil
}

func updateHost(dir string, cfg *config.Config, in HostDraft, opt Options) ([]confirmgate.Need, error) {
	alias := strings.TrimSpace(in.Alias)
	if alias == "" {
		return nil, fmt.Errorf("alias is required")
	}
	if in.Password != "" && strings.TrimSpace(in.Identity) != "" {
		return nil, fmt.Errorf("pass only one of password and identity")
	}
	if err := checkPortPtr(in.Port); err != nil {
		return nil, err
	}
	changed := in.HasGroup || in.HasAddress || in.HasPort || in.HasUser || in.HasIdentity ||
		in.HasPassword || in.HasPolicy || in.HasTags || in.HasVia || in.ClearVia ||
		in.SetDefault || in.ClearTags
	if !changed {
		return nil, fmt.Errorf("no changes given")
	}
	if in.ClearTags && in.HasTags {
		return nil, fmt.Errorf("use only one of tags and clearTags")
	}
	if in.ClearVia && in.HasVia {
		return nil, fmt.Errorf("use only one of via and clearVia")
	}
	found, ok := cfg.Find(alias)
	if !ok {
		return nil, fmt.Errorf("host %q not found", alias)
	}
	h := found.Host
	needs, err := hostChangeNeeds(cfg, found, h, in)
	if err != nil {
		return nil, err
	}
	if err := confirmgate.Require(dir, opt.Actor, opt.HumanConfirm, needs); err != nil {
		return nil, err
	}
	oldRef := h.PasswordRef
	if in.HasGroup {
		group := strings.TrimSpace(in.Group)
		g, ok := cfg.Groups[group]
		if !ok {
			return nil, fmt.Errorf("group %q not found", group)
		}
		delete(found.GroupDef.Hosts, alias)
		if g.Hosts == nil {
			g.Hosts = map[string]*config.Host{}
		}
		g.Hosts[alias] = h
		found.GroupDef = g
		found.Group = group
	}
	if in.HasAddress {
		if strings.TrimSpace(in.Address) == "" {
			return nil, fmt.Errorf("empty address")
		}
		h.Host = strings.TrimSpace(in.Address)
	}
	if in.HasPort {
		h.Port = normalizePortPtr(in.Port)
	}
	if in.HasUser {
		if strings.TrimSpace(in.User) == "" {
			return nil, fmt.Errorf("empty user")
		}
		h.User = strings.TrimSpace(in.User)
	}
	if in.HasPolicy {
		if in.Policy != "" && !guard.KnownPolicy(cfg, in.Policy) {
			return nil, fmt.Errorf("unknown policy %q", in.Policy)
		}
		h.Policy = in.Policy
	}
	if in.HasTags {
		h.Tags = cleanList(in.Tags)
	}
	if in.ClearTags {
		h.Tags = nil
	}
	if in.ClearVia {
		h.Via = ""
	}
	if in.HasVia {
		via := strings.TrimSpace(in.Via)
		if err := cfg.CheckJump(alias, via); err != nil {
			return nil, err
		}
		h.Via = via
	}
	if in.SetDefault {
		cfg.Default = alias
	}
	st, err := secrets.Open(dir, secrets.Options{Warn: warnOf(opt)})
	if err != nil {
		return nil, err
	}
	dirty := false
	if in.HasIdentity && strings.TrimSpace(in.Identity) != "" {
		h.Auth = "key"
		h.Identity = strings.TrimSpace(in.Identity)
		h.PasswordRef = ""
	}
	if in.Password != "" {
		h.Auth = "password"
		h.Identity = ""
		if h.PasswordRef == "" {
			h.PasswordRef = found.Group + "." + alias
		}
		if err := st.Put(h.PasswordRef, in.Password); err != nil {
			return nil, err
		}
		dirty = true
	}
	if oldRef != "" && oldRef != h.PasswordRef && cfg.PasswordRefs()[oldRef] == 0 {
		st.Delete(oldRef)
		dirty = true
	}
	if dirty {
		if err := st.Save(); err != nil {
			return nil, err
		}
	}
	return needs, nil
}

func hostChangeNeeds(cfg *config.Config, found config.ResolvedHost, h *config.Host, in HostDraft) ([]confirmgate.Need, error) {
	alias := strings.TrimSpace(in.Alias)
	newGroup := found.Group
	newEnv := found.EnvName
	groupChanged := false
	if in.HasGroup {
		newGroup = strings.TrimSpace(in.Group)
		g, ok := cfg.Groups[newGroup]
		if !ok || g == nil {
			return nil, fmt.Errorf("group %q not found", newGroup)
		}
		groupChanged = newGroup != found.Group
		newEnv = g.Env
	}
	newAddr := h.Host
	addrChanged := false
	if in.HasAddress {
		newAddr = strings.TrimSpace(in.Address)
		addrChanged = newAddr != strings.TrimSpace(h.Host)
	}
	needs := confirmgate.HostNeeds(alias, found.Group, newGroup, found.EnvName, newEnv, h.Host, newAddr, groupChanged, addrChanged)
	if in.HasPolicy && confirmgate.NamedWider(cfg, h.Policy, in.Policy) {
		needs = append(needs, confirmgate.WidenNeed(alias, "host "+alias+" policy would widen"))
	}
	return needs, nil
}

// RemoveHost deletes one host and its secret when nothing else references it.
func RemoveHost(dir, alias string, opt Options) error {
	return config.Update(dir, func(cfg *config.Config) error {
		return removeHost(dir, cfg, alias, opt)
	})
}

func removeHost(dir string, cfg *config.Config, alias string, opt Options) error {
	alias = strings.TrimSpace(alias)
	if alias == "" {
		return fmt.Errorf("alias is required")
	}
	found, ok := cfg.Find(alias)
	if !ok {
		return fmt.Errorf("host %q not found", alias)
	}
	if deps := cfg.JumpDependents(alias); len(deps) > 0 {
		return fmt.Errorf("host %q is the jump host for %s", alias, strings.Join(deps, ", "))
	}
	ref := found.Host.PasswordRef
	delete(found.GroupDef.Hosts, alias)
	if cfg.Default == alias {
		cfg.Default = ""
	}
	if ref != "" && cfg.PasswordRefs()[ref] == 0 {
		st, err := secrets.Open(dir, secrets.Options{Warn: warnOf(opt)})
		if err != nil {
			return err
		}
		st.Delete(ref)
		if err := st.Save(); err != nil {
			return err
		}
	}
	return nil
}

func putSecret(dir, ref, password string, opt Options) error {
	if password == "" {
		return fmt.Errorf("empty password")
	}
	st, err := secrets.Open(dir, secrets.Options{Warn: warnOf(opt)})
	if err != nil {
		return err
	}
	if err := st.Put(ref, password); err != nil {
		return err
	}
	return st.Save()
}

func warnOf(opt Options) io.Writer {
	if opt.Warn == nil {
		return io.Discard
	}
	return opt.Warn
}

func checkPortPtr(port *int) error {
	if port == nil {
		return nil
	}
	if *port < 0 || *port > 65535 {
		return fmt.Errorf("invalid port %d", *port)
	}
	return nil
}

func normalizePortPtr(port *int) int {
	if port == nil || *port == 22 || *port == 0 {
		return 0
	}
	return *port
}
