package catalog

import (
	"bytes"
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/config"
)

const maxInventory = 2 << 20

// Change is one import step. It never contains a password.
type Change struct {
	Action string `json:"action"`
	Name   string `json:"name"`
	Detail string `json:"detail,omitempty"`
}

// ImportResult is the plan that was applied, or that dry-run would apply.
type ImportResult struct {
	DryRun             bool     `json:"dryRun"`
	Changes            []Change `json:"changes"`
	PlaintextPasswords int      `json:"plaintextPasswords"`
}

// ImportOptions selects how missing envs and groups are filled in.
type ImportOptions struct {
	DryRun       bool
	SkipExisting bool
	DefaultEnv   string
	DefaultGroup string
	MaxMode      string
	Warn         Options
}

// Import reads an ssh-ops style YAML or JSON inventory and writes hosts.yaml
// plus encrypted secrets. Dry-run writes nothing. The inventory is not fetched
// over the network.
func Import(dir string, data []byte, opt ImportOptions) (ImportResult, error) {
	if opt.MaxMode == "" {
		opt.MaxMode = string(config.ModeStandard)
	}
	if !config.Mode(opt.MaxMode).Valid() {
		return ImportResult{}, fmt.Errorf("max-mode must be readonly, standard, or admin")
	}
	inv, err := ParseInventory(data)
	if err != nil {
		return ImportResult{}, err
	}
	if opt.DryRun {
		cfg, err := config.Load(dir)
		if err != nil {
			return ImportResult{}, err
		}
		return applyInventory(dir, cfg, inv, opt)
	}
	var result ImportResult
	err = config.Update(dir, func(cfg *config.Config) error {
		got, err := applyInventory(dir, cfg, inv, opt)
		if err != nil {
			return err
		}
		result = got
		return nil
	})
	return result, err
}

type inventory struct {
	Default  string
	Policies map[string]*config.Policy
	Envs     map[string]*config.Env
	Groups   []groupSpec
	Servers  []serverSpec
}

type groupSpec struct {
	Name           string
	Env            string
	Policy         string
	ProtectedPaths []string
	Hosts          []serverSpec
}

type serverSpec struct {
	Alias       string
	Address     string
	Port        int
	User        string
	Password    string
	PasswordRef string
	Identity    string
	Auth        string
	Group       string
	Env         string
	Tags        []string
	Policy      string
}

// ParseInventory decodes a YAML or JSON document. Passwords stay on the result
// and are not part of ImportResult.
func ParseInventory(data []byte) (*inventory, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, fmt.Errorf("empty inventory")
	}
	if len(data) > maxInventory {
		return nil, fmt.Errorf("inventory exceeds 2MiB")
	}
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("parse inventory: %w", err)
	}
	if len(root.Content) == 0 || root.Content[0] == nil {
		return nil, fmt.Errorf("empty inventory")
	}
	doc := root.Content[0]
	switch doc.Kind {
	case yaml.SequenceNode:
		servers, err := parseServerList(doc)
		if err != nil {
			return nil, err
		}
		return &inventory{Servers: servers}, nil
	case yaml.MappingNode:
		return parseInventoryMap(doc)
	default:
		return nil, fmt.Errorf("inventory must be a YAML/JSON object or a list of servers")
	}
}

func parseInventoryMap(doc *yaml.Node) (*inventory, error) {
	inv := &inventory{}
	for i := 0; i+1 < len(doc.Content); i += 2 {
		key := doc.Content[i].Value
		val := doc.Content[i+1]
		switch key {
		case "version":
			var version int
			if err := val.Decode(&version); err != nil {
				return nil, fmt.Errorf("version must be a number")
			}
			if version != 0 && version != 1 {
				return nil, fmt.Errorf("unsupported inventory version %d", version)
			}
		case "default":
			if err := val.Decode(&inv.Default); err != nil {
				return nil, fmt.Errorf("default must be a string")
			}
		case "policies":
			pols, err := parsePolicies(val)
			if err != nil {
				return nil, err
			}
			inv.Policies = pols
		case "envs":
			envs, err := parseEnvs(val)
			if err != nil {
				return nil, err
			}
			inv.Envs = envs
		case "groups":
			groups, err := parseGroups(val)
			if err != nil {
				return nil, err
			}
			inv.Groups = groups
		case "servers", "hosts":
			servers, err := parseServersNode(val)
			if err != nil {
				return nil, err
			}
			inv.Servers = append(inv.Servers, servers...)
		default:
			return nil, fmt.Errorf("unknown inventory field %q", key)
		}
	}
	return inv, nil
}

func parsePolicies(node *yaml.Node) (map[string]*config.Policy, error) {
	if node.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("policies must be a map")
	}
	out := map[string]*config.Policy{}
	for i := 0; i+1 < len(node.Content); i += 2 {
		name := node.Content[i].Value
		if !config.ValidName(name) {
			return nil, fmt.Errorf("invalid policy name %q", name)
		}
		if err := rejectSecretFields(node.Content[i+1], "policy "+name); err != nil {
			return nil, err
		}
		var pol config.Policy
		if err := node.Content[i+1].Decode(&pol); err != nil {
			return nil, fmt.Errorf("policy %s: %w", name, err)
		}
		cp := pol
		out[name] = &cp
	}
	return out, nil
}

func parseEnvs(node *yaml.Node) (map[string]*config.Env, error) {
	if node.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("envs must be a map")
	}
	out := map[string]*config.Env{}
	for i := 0; i+1 < len(node.Content); i += 2 {
		name := node.Content[i].Value
		if !config.ValidName(name) {
			return nil, fmt.Errorf("invalid env name %q", name)
		}
		if err := rejectSecretFields(node.Content[i+1], "env "+name); err != nil {
			return nil, err
		}
		var env config.Env
		if err := node.Content[i+1].Decode(&env); err != nil {
			return nil, fmt.Errorf("env %s: %w", name, err)
		}
		cp := env
		out[name] = &cp
	}
	return out, nil
}

func parseGroups(node *yaml.Node) ([]groupSpec, error) {
	if node.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("groups must be a map")
	}
	var out []groupSpec
	for i := 0; i+1 < len(node.Content); i += 2 {
		name := node.Content[i].Value
		body := node.Content[i+1]
		if !config.ValidName(name) {
			return nil, fmt.Errorf("invalid group name %q", name)
		}
		g := groupSpec{Name: name}
		if body.Kind != yaml.MappingNode {
			return nil, fmt.Errorf("group %s must be a map", name)
		}
		for j := 0; j+1 < len(body.Content); j += 2 {
			key := body.Content[j].Value
			val := body.Content[j+1]
			switch key {
			case "env":
				if err := val.Decode(&g.Env); err != nil {
					return nil, fmt.Errorf("group %s: env must be a string", name)
				}
			case "policy":
				if err := val.Decode(&g.Policy); err != nil {
					return nil, fmt.Errorf("group %s: policy must be a string", name)
				}
			case "protectedPaths", "protected_paths":
				paths, err := decodeStringList(val)
				if err != nil {
					return nil, fmt.Errorf("group %s: protectedPaths: %w", name, err)
				}
				g.ProtectedPaths = append(g.ProtectedPaths, paths...)
			case "hosts":
				hosts, err := parseServersNode(val)
				if err != nil {
					return nil, fmt.Errorf("group %s: %w", name, err)
				}
				for i := range hosts {
					if hosts[i].Group == "" {
						hosts[i].Group = name
					} else if hosts[i].Group != name {
						return nil, fmt.Errorf("host %s group %q does not match %q", hosts[i].Alias, hosts[i].Group, name)
					}
				}
				g.Hosts = hosts
			case "allow", "deny", "confirm", "capabilities":
				return nil, fmt.Errorf("group %s: inline %s is not imported; define a named policy instead", name, key)
			default:
				if isSecretField(key) {
					return nil, fmt.Errorf("group %s: field %q looks like a secret; use a host password or identity", name, key)
				}
				return nil, fmt.Errorf("group %s: unknown field %q", name, key)
			}
		}
		out = append(out, g)
	}
	return out, nil
}

func parseServersNode(node *yaml.Node) ([]serverSpec, error) {
	switch node.Kind {
	case yaml.SequenceNode:
		return parseServerList(node)
	case yaml.MappingNode:
		var out []serverSpec
		for i := 0; i+1 < len(node.Content); i += 2 {
			alias := node.Content[i].Value
			spec, err := decodeServer(node.Content[i+1], alias)
			if err != nil {
				return nil, err
			}
			out = append(out, spec)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("servers must be a map or a list")
	}
}

func parseServerList(node *yaml.Node) ([]serverSpec, error) {
	var out []serverSpec
	for i, item := range node.Content {
		spec, err := decodeServer(item, "")
		if err != nil {
			return nil, fmt.Errorf("server %d: %w", i, err)
		}
		if spec.Alias == "" {
			return nil, fmt.Errorf("server %d: alias (or name) is required", i)
		}
		out = append(out, spec)
	}
	return out, nil
}

func decodeServer(node *yaml.Node, alias string) (serverSpec, error) {
	if node.Kind != yaml.MappingNode {
		return serverSpec{}, fmt.Errorf("host %s must be a map", alias)
	}
	var spec serverSpec
	spec.Alias = alias
	for i := 0; i+1 < len(node.Content); i += 2 {
		key := node.Content[i].Value
		val := node.Content[i+1]
		switch key {
		case "alias", "name", "id":
			var s string
			if err := val.Decode(&s); err != nil {
				return serverSpec{}, fmt.Errorf("%s must be a string", key)
			}
			if spec.Alias == "" {
				spec.Alias = s
			} else if s != "" && s != spec.Alias {
				return serverSpec{}, fmt.Errorf("host %s: %s %q does not match the map key", spec.Alias, key, s)
			}
		case "host", "hostname", "address", "ip":
			if err := val.Decode(&spec.Address); err != nil {
				return serverSpec{}, fmt.Errorf("%s must be a string", key)
			}
		case "port":
			port, err := decodePort(val)
			if err != nil {
				return serverSpec{}, err
			}
			spec.Port = port
		case "user", "username":
			if err := val.Decode(&spec.User); err != nil {
				return serverSpec{}, fmt.Errorf("%s must be a string", key)
			}
		case "password", "passwd":
			if err := val.Decode(&spec.Password); err != nil {
				return serverSpec{}, fmt.Errorf("%s must be a string", key)
			}
		case "passwordRef", "password_ref":
			if err := val.Decode(&spec.PasswordRef); err != nil {
				return serverSpec{}, fmt.Errorf("%s must be a string", key)
			}
		case "identity", "identityFile", "identity_file", "key":
			var s string
			if err := val.Decode(&s); err != nil {
				return serverSpec{}, fmt.Errorf("%s must be a string", key)
			}
			if strings.Contains(s, "PRIVATE KEY") || strings.Contains(s, "\n") {
				return serverSpec{}, fmt.Errorf("host %s: %s must be a file path, not key material", aliasOr(spec.Alias, "entry"), key)
			}
			spec.Identity = s
		case "group":
			if err := val.Decode(&spec.Group); err != nil {
				return serverSpec{}, fmt.Errorf("group must be a string")
			}
		case "env", "environment":
			if err := val.Decode(&spec.Env); err != nil {
				return serverSpec{}, fmt.Errorf("env must be a string")
			}
		case "tags", "tag":
			tags, err := decodeStringList(val)
			if err != nil {
				return serverSpec{}, fmt.Errorf("tags: %w", err)
			}
			spec.Tags = append(spec.Tags, tags...)
		case "policy":
			if err := val.Decode(&spec.Policy); err != nil {
				return serverSpec{}, fmt.Errorf("policy must be a string")
			}
		case "auth":
			if err := val.Decode(&spec.Auth); err != nil {
				return serverSpec{}, fmt.Errorf("auth must be a string")
			}
		default:
			if isSecretField(key) {
				return serverSpec{}, fmt.Errorf("host %s: field %q looks like a secret; use password or identity", aliasOr(spec.Alias, "entry"), key)
			}
		}
	}
	spec.Alias = strings.TrimSpace(spec.Alias)
	spec.Address = strings.TrimSpace(spec.Address)
	spec.User = strings.TrimSpace(spec.User)
	spec.Identity = strings.TrimSpace(spec.Identity)
	spec.Group = strings.TrimSpace(spec.Group)
	spec.Env = strings.TrimSpace(spec.Env)
	spec.Policy = strings.TrimSpace(spec.Policy)
	spec.Auth = strings.TrimSpace(spec.Auth)
	spec.Tags = cleanList(spec.Tags)
	return spec, nil
}

func decodePort(val *yaml.Node) (int, error) {
	var n int
	if err := val.Decode(&n); err == nil {
		return n, nil
	}
	var s string
	if err := val.Decode(&s); err != nil {
		return 0, fmt.Errorf("port must be a number")
	}
	if strings.TrimSpace(s) == "" {
		return 0, nil
	}
	var parsed int
	if _, err := fmt.Sscan(strings.TrimSpace(s), &parsed); err != nil {
		return 0, fmt.Errorf("port must be a number")
	}
	return parsed, nil
}

func decodeStringList(val *yaml.Node) ([]string, error) {
	switch val.Kind {
	case yaml.ScalarNode:
		var s string
		if err := val.Decode(&s); err != nil {
			return nil, err
		}
		return cleanList([]string{s}), nil
	case yaml.SequenceNode:
		var items []string
		if err := val.Decode(&items); err != nil {
			return nil, err
		}
		return cleanList(items), nil
	default:
		return nil, fmt.Errorf("must be a string or a list")
	}
}

func rejectSecretFields(node *yaml.Node, where string) error {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		if isSecretField(node.Content[i].Value) {
			return fmt.Errorf("%s: field %q looks like a secret and was not imported", where, node.Content[i].Value)
		}
	}
	return nil
}

func isSecretField(key string) bool {
	switch strings.ToLower(strings.TrimSpace(key)) {
	case "secret", "pass", "passphrase", "privatekey", "private_key", "private-key":
		return true
	default:
		return false
	}
}

func aliasOr(alias, fallback string) string {
	if strings.TrimSpace(alias) == "" {
		return fallback
	}
	return alias
}

func applyInventory(dir string, cfg *config.Config, inv *inventory, opt ImportOptions) (ImportResult, error) {
	result := ImportResult{DryRun: opt.DryRun, Changes: []Change{}}
	if err := applyPolicies(cfg, inv, &result, opt); err != nil {
		return ImportResult{}, err
	}
	if err := applyEnvs(cfg, inv, &result, opt); err != nil {
		return ImportResult{}, err
	}
	if err := applyGroups(cfg, inv, &result, opt); err != nil {
		return ImportResult{}, err
	}
	seen := map[string]bool{}
	var hosts []serverSpec
	for _, g := range inv.Groups {
		hosts = append(hosts, g.Hosts...)
	}
	hosts = append(hosts, inv.Servers...)
	sort.SliceStable(hosts, func(i, j int) bool { return hosts[i].Alias < hosts[j].Alias })
	for _, h := range hosts {
		if h.Alias == "" {
			return ImportResult{}, fmt.Errorf("host is missing an alias")
		}
		if seen[h.Alias] {
			return ImportResult{}, fmt.Errorf("host %q appears more than once", h.Alias)
		}
		seen[h.Alias] = true
		if err := applyServer(dir, cfg, h, &result, opt); err != nil {
			return ImportResult{}, err
		}
	}
	if inv.Default != "" {
		if _, ok := cfg.Find(inv.Default); !ok {
			return ImportResult{}, fmt.Errorf("default host %q is not in the inventory or the config", inv.Default)
		}
		if cfg.Default != inv.Default {
			cfg.Default = inv.Default
			result.Changes = append(result.Changes, Change{Action: "set-default", Name: inv.Default})
		}
	}
	return result, nil
}

func applyPolicies(cfg *config.Config, inv *inventory, result *ImportResult, opt ImportOptions) error {
	names := make([]string, 0, len(inv.Policies))
	for name := range inv.Policies {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		pol := inv.Policies[name]
		if _, ok := filePolicy(cfg, name); ok {
			if opt.SkipExisting {
				result.Changes = append(result.Changes, Change{Action: "skip-policy", Name: name, Detail: "already defined"})
				continue
			}
			return fmt.Errorf("policy %q already exists", name)
		}
		if cfg.Policies == nil {
			cfg.Policies = map[string]*config.Policy{}
		}
		if _, builtin := guardBuiltin(name); builtin {
			result.Changes = append(result.Changes, Change{Action: "override-policy", Name: name})
		} else {
			result.Changes = append(result.Changes, Change{Action: "create-policy", Name: name, Detail: policyDetail(pol)})
		}
		cfg.Policies[name] = pol
	}
	return nil
}

func guardBuiltin(name string) (*config.Policy, bool) {
	return nil, name == "readonly" || name == "standard" || name == "admin"
}

func policyDetail(p *config.Policy) string {
	if p == nil || p.Mode == "" {
		return ""
	}
	return "mode=" + string(p.Mode)
}

func applyEnvs(cfg *config.Config, inv *inventory, result *ImportResult, opt ImportOptions) error {
	names := make([]string, 0, len(inv.Envs))
	for name := range inv.Envs {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		env := inv.Envs[name]
		if env == nil {
			return fmt.Errorf("env %q is null", name)
		}
		if existing, ok := cfg.Envs[name]; ok {
			if opt.SkipExisting {
				result.Changes = append(result.Changes, Change{Action: "skip-env", Name: name, Detail: "already defined"})
				continue
			}
			if existing.MaxMode != env.MaxMode && env.MaxMode != "" {
				return fmt.Errorf("env %q already exists with maxMode %s", name, existing.MaxMode)
			}
			result.Changes = append(result.Changes, Change{Action: "keep-env", Name: name})
			continue
		}
		mode := env.MaxMode
		if mode == "" {
			mode = config.Mode(opt.MaxMode)
		}
		if !mode.Valid() {
			return fmt.Errorf("env %q: maxMode must be readonly, standard, or admin", name)
		}
		if env.DefaultPolicy != "" && !knownAfterImport(cfg, env.DefaultPolicy) {
			return fmt.Errorf("env %s: unknown policy %q", name, env.DefaultPolicy)
		}
		label := env.Label
		if label == "" {
			label = name
		}
		if cfg.Envs == nil {
			cfg.Envs = map[string]*config.Env{}
		}
		cfg.Envs[name] = &config.Env{
			Label:         label,
			Color:         env.Color,
			MaxMode:       mode,
			DefaultPolicy: env.DefaultPolicy,
			BreakGlass:    env.BreakGlass,
			NoDataOutflow: env.NoDataOutflow,
		}
		result.Changes = append(result.Changes, Change{
			Action: "create-env", Name: name, Detail: "maxMode=" + string(mode),
		})
	}
	return nil
}

func knownAfterImport(cfg *config.Config, name string) bool {
	if name == "readonly" || name == "standard" || name == "admin" {
		return true
	}
	_, ok := filePolicy(cfg, name)
	return ok
}

func applyGroups(cfg *config.Config, inv *inventory, result *ImportResult, opt ImportOptions) error {
	groups := append([]groupSpec(nil), inv.Groups...)
	sort.SliceStable(groups, func(i, j int) bool { return groups[i].Name < groups[j].Name })
	for _, g := range groups {
		envName := g.Env
		if envName == "" {
			envName = strings.TrimSpace(opt.DefaultEnv)
		}
		if envName == "" {
			envName = "imported"
		}
		if err := ensureEnv(cfg, envName, opt, result); err != nil {
			return err
		}
		if existing, ok := cfg.Groups[g.Name]; ok && existing != nil {
			if existing.Env != envName {
				return fmt.Errorf("group %q already exists with env %s", g.Name, existing.Env)
			}
			if opt.SkipExisting {
				result.Changes = append(result.Changes, Change{Action: "skip-group", Name: g.Name, Detail: "already defined"})
				continue
			}
			result.Changes = append(result.Changes, Change{Action: "keep-group", Name: g.Name, Detail: "env=" + existing.Env})
			continue
		}
		if g.Policy != "" && !knownAfterImport(cfg, g.Policy) {
			return fmt.Errorf("group %s: unknown policy %q", g.Name, g.Policy)
		}
		if err := addGroup(cfg, GroupDraft{
			Name: g.Name, Env: envName, Policy: g.Policy, ProtectedPaths: g.ProtectedPaths,
		}); err != nil {
			return err
		}
		result.Changes = append(result.Changes, Change{
			Action: "create-group", Name: g.Name, Detail: "env=" + envName,
		})
	}
	return nil
}

func ensureEnv(cfg *config.Config, name string, opt ImportOptions, result *ImportResult) error {
	if _, ok := cfg.Envs[name]; ok {
		return nil
	}
	if err := addEnv(cfg, EnvDraft{Name: name, MaxMode: opt.MaxMode}); err != nil {
		return err
	}
	result.Changes = append(result.Changes, Change{
		Action: "create-env", Name: name, Detail: "maxMode=" + opt.MaxMode,
	})
	return nil
}

func applyServer(dir string, cfg *config.Config, h serverSpec, result *ImportResult, opt ImportOptions) error {
	if !config.ValidName(h.Alias) {
		return fmt.Errorf("invalid host alias %q", h.Alias)
	}
	if _, ok := cfg.Find(h.Alias); ok {
		if opt.SkipExisting {
			result.Changes = append(result.Changes, Change{Action: "skip-host", Name: h.Alias, Detail: "already exists"})
			return nil
		}
		return fmt.Errorf("host %q already exists", h.Alias)
	}
	if strings.ContainsAny(h.Address, " \t\r\n") || h.Address == "" {
		return fmt.Errorf("host %s: address is required", h.Alias)
	}
	if h.User == "" {
		return fmt.Errorf("host %s: user is required", h.Alias)
	}
	if h.Port < 0 || h.Port > 65535 {
		return fmt.Errorf("host %s: invalid port %d", h.Alias, h.Port)
	}
	if h.Password != "" && h.Identity != "" {
		return fmt.Errorf("host %s: pass only one of password and identity", h.Alias)
	}
	group := h.Group
	if group == "" {
		group = strings.TrimSpace(opt.DefaultGroup)
	}
	if group == "" {
		group = "imported"
	}
	if !config.ValidName(group) {
		return fmt.Errorf("host %s: invalid group %q", h.Alias, group)
	}
	envName := h.Env
	if existing, ok := cfg.Groups[group]; ok && existing != nil {
		if envName != "" && envName != existing.Env {
			return fmt.Errorf("host %s: group %s is env %s, not %s", h.Alias, group, existing.Env, envName)
		}
	} else {
		if envName == "" {
			envName = strings.TrimSpace(opt.DefaultEnv)
		}
		if envName == "" {
			envName = "imported"
		}
		if err := ensureEnv(cfg, envName, opt, result); err != nil {
			return err
		}
		if err := addGroup(cfg, GroupDraft{Name: group, Env: envName}); err != nil {
			return err
		}
		result.Changes = append(result.Changes, Change{
			Action: "create-group", Name: group, Detail: "env=" + envName,
		})
	}
	auth := h.Auth
	switch auth {
	case "", "password", "key":
	default:
		return fmt.Errorf("host %s: unsupported auth %q", h.Alias, auth)
	}
	if h.Password == "" && h.Identity == "" && h.PasswordRef == "" {
		return fmt.Errorf("host %s: password, passwordRef, or identity is required", h.Alias)
	}
	port := h.Port
	draft := HostDraft{
		Alias:    h.Alias,
		Group:    group,
		Address:  h.Address,
		User:     h.User,
		Password: h.Password,
		Identity: h.Identity,
		Policy:   h.Policy,
		Tags:     h.Tags,
	}
	if port != 0 {
		draft.Port = &port
		draft.HasPort = true
	}
	detailAuth := "key"
	if h.Password != "" || (h.Identity == "" && h.PasswordRef != "") {
		detailAuth = "password"
	}
	if h.Password != "" {
		result.PlaintextPasswords++
	}
	ref := h.PasswordRef
	if ref == "" {
		ref = group + "." + h.Alias
	}
	var err error
	switch {
	case opt.DryRun && h.Identity != "":
		err = addHostDry(cfg, draft)
	case opt.DryRun:
		err = addHostRef(cfg, draft, ref)
	case h.Password != "" || h.Identity != "":
		err = addHost(dir, cfg, draft, opt.Warn)
	default:
		err = addHostRef(cfg, draft, ref)
	}
	if err != nil {
		return err
	}
	result.Changes = append(result.Changes, Change{
		Action: "add-host",
		Name:   h.Alias,
		Detail: fmt.Sprintf("group=%s host=%s user=%s auth=%s", group, h.Address, h.User, detailAuth),
	})
	return nil
}

func addHostDry(cfg *config.Config, in HostDraft) error {
	return addHostRef(cfg, in, in.Group+"."+strings.TrimSpace(in.Alias))
}

func addHostRef(cfg *config.Config, in HostDraft, ref string) error {
	alias := strings.TrimSpace(in.Alias)
	if _, ok := cfg.Find(alias); ok {
		return fmt.Errorf("host %q already exists", alias)
	}
	g, ok := cfg.Groups[strings.TrimSpace(in.Group)]
	if !ok {
		return fmt.Errorf("group %q not found", in.Group)
	}
	if in.Policy != "" && !knownAfterImport(cfg, in.Policy) {
		return fmt.Errorf("unknown policy %q", in.Policy)
	}
	h := &config.Host{
		Host:   strings.TrimSpace(in.Address),
		User:   strings.TrimSpace(in.User),
		Port:   normalizePortPtr(in.Port),
		Tags:   cleanList(in.Tags),
		Policy: in.Policy,
	}
	if strings.TrimSpace(in.Identity) != "" {
		h.Auth = "key"
		h.Identity = strings.TrimSpace(in.Identity)
	} else {
		h.Auth = "password"
		h.PasswordRef = ref
	}
	if g.Hosts == nil {
		g.Hosts = map[string]*config.Host{}
	}
	g.Hosts[alias] = h
	return nil
}
