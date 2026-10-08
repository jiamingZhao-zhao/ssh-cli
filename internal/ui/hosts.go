package ui

import (
	"fmt"
	"io"
	"strings"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/config"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/guard"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/secrets"
)

// HostDraft is a host add or edit. Password is never written to the audit log
// or included in API responses. Has* fields distinguish "omitted" from "empty"
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
	SetDefault bool
	ClearTags  bool

	HasGroup    bool
	HasAddress  bool
	HasPort     bool
	HasUser     bool
	HasPassword bool
	HasIdentity bool
	HasPolicy   bool
	HasTags     bool
}

// AddHost creates one host. A password is stored through secrets.Store.
func AddHost(dir string, in HostDraft) error {
	alias := strings.TrimSpace(in.Alias)
	if !config.ValidName(alias) {
		return fmt.Errorf("invalid host alias")
	}
	if strings.TrimSpace(in.Group) == "" || strings.TrimSpace(in.Address) == "" || strings.TrimSpace(in.User) == "" {
		return fmt.Errorf("group, host, and user are required")
	}
	if in.HasPassword && in.HasIdentity && in.Password != "" && in.Identity != "" {
		return fmt.Errorf("pass only one of password and identity")
	}
	if in.Password != "" && in.Identity != "" {
		return fmt.Errorf("pass only one of password and identity")
	}
	if err := checkPortPtr(in.Port); err != nil {
		return err
	}
	if in.Password == "" && strings.TrimSpace(in.Identity) == "" {
		return fmt.Errorf("password or identity is required")
	}
	password := in.Password
	in.Password = ""
	return config.Update(dir, func(cfg *config.Config) error {
		if _, ok := cfg.Find(alias); ok {
			return fmt.Errorf("host %q already exists", alias)
		}
		g, ok := cfg.Groups[in.Group]
		if !ok {
			return fmt.Errorf("group %q not found", in.Group)
		}
		if in.Policy != "" && !guard.KnownPolicy(cfg, in.Policy) {
			return fmt.Errorf("unknown policy %q", in.Policy)
		}
		h := &config.Host{
			Host:   strings.TrimSpace(in.Address),
			User:   strings.TrimSpace(in.User),
			Port:   normalizePortPtr(in.Port),
			Tags:   cleanTags(in.Tags),
			Policy: in.Policy,
		}
		if strings.TrimSpace(in.Identity) != "" {
			h.Auth = "key"
			h.Identity = strings.TrimSpace(in.Identity)
		} else {
			h.Auth = "password"
			h.PasswordRef = in.Group + "." + alias
			if err := putSecret(dir, h.PasswordRef, password); err != nil {
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
	})
}

// UpdateHost edits one host. An empty password field does not change the secret.
func UpdateHost(dir string, in HostDraft) error {
	alias := strings.TrimSpace(in.Alias)
	if alias == "" {
		return fmt.Errorf("alias is required")
	}
	if in.Password != "" && strings.TrimSpace(in.Identity) != "" {
		return fmt.Errorf("pass only one of password and identity")
	}
	if err := checkPortPtr(in.Port); err != nil {
		return err
	}
	changed := in.HasGroup || in.HasAddress || in.HasPort || in.HasUser || in.HasIdentity ||
		in.HasPassword || in.HasPolicy || in.HasTags || in.SetDefault || in.ClearTags
	if !changed {
		return fmt.Errorf("no changes given")
	}
	if in.ClearTags && in.HasTags {
		return fmt.Errorf("use only one of tags and clearTags")
	}
	password := in.Password
	in.Password = ""
	return config.Update(dir, func(cfg *config.Config) error {
		found, ok := cfg.Find(alias)
		if !ok {
			return fmt.Errorf("host %q not found", alias)
		}
		h := found.Host
		oldRef := h.PasswordRef
		if in.HasGroup {
			group := strings.TrimSpace(in.Group)
			g, ok := cfg.Groups[group]
			if !ok {
				return fmt.Errorf("group %q not found", group)
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
				return fmt.Errorf("empty address")
			}
			h.Host = strings.TrimSpace(in.Address)
		}
		if in.HasPort {
			h.Port = normalizePortPtr(in.Port)
		}
		if in.HasUser {
			if strings.TrimSpace(in.User) == "" {
				return fmt.Errorf("empty user")
			}
			h.User = strings.TrimSpace(in.User)
		}
		if in.HasPolicy {
			if in.Policy != "" && !guard.KnownPolicy(cfg, in.Policy) {
				return fmt.Errorf("unknown policy %q", in.Policy)
			}
			h.Policy = in.Policy
		}
		if in.HasTags {
			h.Tags = cleanTags(in.Tags)
		}
		if in.ClearTags {
			h.Tags = nil
		}
		if in.SetDefault {
			cfg.Default = alias
		}
		st, err := secrets.Open(dir, secrets.Options{Warn: io.Discard})
		if err != nil {
			return err
		}
		dirty := false
		if in.HasIdentity && strings.TrimSpace(in.Identity) != "" {
			h.Auth = "key"
			h.Identity = strings.TrimSpace(in.Identity)
			h.PasswordRef = ""
		}
		if password != "" {
			h.Auth = "password"
			h.Identity = ""
			if h.PasswordRef == "" {
				h.PasswordRef = found.Group + "." + alias
			}
			if err := st.Put(h.PasswordRef, password); err != nil {
				return err
			}
			dirty = true
		}
		if oldRef != "" && oldRef != h.PasswordRef && cfg.PasswordRefs()[oldRef] == 0 {
			st.Delete(oldRef)
			dirty = true
		}
		if dirty {
			return st.Save()
		}
		return nil
	})
}

// RemoveHost deletes one host and its secret when nothing else references it.
func RemoveHost(dir, alias string) error {
	alias = strings.TrimSpace(alias)
	if alias == "" {
		return fmt.Errorf("alias is required")
	}
	return config.Update(dir, func(cfg *config.Config) error {
		found, ok := cfg.Find(alias)
		if !ok {
			return fmt.Errorf("host %q not found", alias)
		}
		ref := found.Host.PasswordRef
		delete(found.GroupDef.Hosts, alias)
		if cfg.Default == alias {
			cfg.Default = ""
		}
		if ref != "" && cfg.PasswordRefs()[ref] == 0 {
			st, err := secrets.Open(dir, secrets.Options{Warn: io.Discard})
			if err != nil {
				return err
			}
			st.Delete(ref)
			if err := st.Save(); err != nil {
				return err
			}
		}
		return nil
	})
}

func putSecret(dir, ref, password string) error {
	if password == "" {
		return fmt.Errorf("empty password")
	}
	st, err := secrets.Open(dir, secrets.Options{Warn: io.Discard})
	if err != nil {
		return err
	}
	if err := st.Put(ref, password); err != nil {
		return err
	}
	return st.Save()
}

func checkPortPtr(port *int) error {
	if port == nil {
		return nil
	}
	if *port < 0 || *port > 65535 {
		return fmt.Errorf("invalid port")
	}
	return nil
}

func normalizePortPtr(port *int) int {
	if port == nil || *port == 22 || *port == 0 {
		return 0
	}
	return *port
}

func cleanTags(tags []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, t := range tags {
		for _, p := range strings.Split(t, ",") {
			p = strings.TrimSpace(p)
			if p == "" || seen[p] {
				continue
			}
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}
