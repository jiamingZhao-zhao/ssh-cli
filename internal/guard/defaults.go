package guard

import "github.com/jiamingZhao-zhao/ssh-cli/internal/config"

func list(items ...string) *[]string {
	cp := append([]string(nil), items...)
	return &cp
}

func boolPtr(v bool) *bool { return &v }

// builtinPolicies are used when hosts.yaml does not override the name.
func builtinPolicies() map[string]*config.Policy {
	readonlyAllow := list(
		"ls", "cat", "head", "tail", "grep", "less", "df", "du", "free", "uptime", "ps", "ss", "netstat",
		"docker ps", "docker logs", "docker stats --no-stream",
		"systemctl status", "journalctl", "apps.sh status",
	)
	statusOnly := list("status")
	standardConfirm := list(
		"systemctl restart", "systemctl stop", "docker restart", "docker rm", "apps.sh restart",
	)
	standardDeny := list("docker system prune -a")
	return map[string]*config.Policy{
		"readonly": {
			Mode:  config.ModeReadonly,
			Allow: readonlyAllow,
			Capabilities: &config.Capabilities{
				Upload:   boolPtr(false),
				Download: boolPtr(true),
				Relay:    config.RelaySourceOnly,
				Forward:  boolPtr(false),
				Service:  statusOnly,
			},
		},
		"standard": {
			Mode:    config.ModeStandard,
			Confirm: *standardConfirm,
			Deny:    *standardDeny,
		},
		"admin": {
			Mode: config.ModeAdmin,
		},
	}
}

func lookupPolicy(cfg *config.Config, name string) (*config.Policy, error) {
	if name == "" {
		return nil, nil
	}
	if cfg != nil && cfg.Policies != nil {
		if p, ok := cfg.Policies[name]; ok && p != nil {
			return p, nil
		}
	}
	if p, ok := builtinPolicies()[name]; ok {
		return p, nil
	}
	return nil, errUnknownPolicy(name)
}

type unknownPolicy string

func errUnknownPolicy(name string) error { return unknownPolicy(name) }

func (e unknownPolicy) Error() string { return "unknown policy " + string(e) }

// BuiltinNames are the policies used when hosts.yaml does not override that name.
func BuiltinNames() []string {
	return []string{"readonly", "standard", "admin"}
}

// BuiltinPolicy returns a fresh copy of a built-in policy.
func BuiltinPolicy(name string) (*config.Policy, bool) {
	p, ok := builtinPolicies()[name]
	return p, ok
}

// KnownPolicy reports whether name is built in or defined in cfg.
func KnownPolicy(cfg *config.Config, name string) bool {
	_, err := lookupPolicy(cfg, name)
	return err == nil
}
