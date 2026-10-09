// Package bundle exports and imports hosts, policies, and key references.
// Plaintext passwords, secret bytes, and the master key are rejected.
package bundle

import (
	"bytes"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/config"
)

const Kind = "ssh-cli-config"

// Document is the portable config. Hosts keep passwordRef and identity paths.
type Document struct {
	Kind     string                    `yaml:"kind"`
	Version  int                       `yaml:"version"`
	Default  string                    `yaml:"default,omitempty"`
	Session  *config.SessionDefaults   `yaml:"session,omitempty"`
	Policies map[string]*config.Policy `yaml:"policies,omitempty"`
	Envs     map[string]*config.Env    `yaml:"envs,omitempty"`
	Groups   map[string]*config.Group  `yaml:"groups,omitempty"`
	Tasks    map[string]any            `yaml:"tasks,omitempty"`
}

// Export renders the current config. Built-in env locked fields are omitted;
// import restores them with prepare.
func Export(cfg *config.Config) ([]byte, error) {
	if cfg == nil {
		return nil, fmt.Errorf("nil config")
	}
	doc := Document{
		Kind: Kind, Version: 1, Default: cfg.Default, Session: cfg.Session,
		Policies: cfg.Policies, Groups: cfg.Groups, Tasks: cfg.Tasks,
	}
	for name, env := range cfg.Envs {
		if env == nil {
			continue
		}
		if doc.Envs == nil {
			doc.Envs = map[string]*config.Env{}
		}
		if config.IsBuiltinEnv(name) {
			// Locked fields (label, color, maxMode, defaultPolicy) are restored
			// on load. Keep the fields an operator can actually change.
			doc.Envs[name] = &config.Env{
				NoDataOutflow: env.NoDataOutflow,
				BreakGlass:    env.BreakGlass,
			}
			continue
		}
		doc.Envs[name] = env
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(doc); err != nil {
		return nil, err
	}
	_ = enc.Close()
	if err := rejectSecretKeys(buf.Bytes()); err != nil {
		return nil, err
	}
	if bytes.Contains(bytes.ToLower(buf.Bytes()), []byte("password:")) {
		return nil, fmt.Errorf("export refused: plaintext password field")
	}
	return buf.Bytes(), nil
}

// Apply replaces groups, policies, custom envs, the default host, session
// defaults, and tasks. Built-in envs stay. secrets.json is not touched.
func Apply(cfg *config.Config, data []byte) error {
	if err := rejectSecretKeys(data); err != nil {
		return err
	}
	var doc Document
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("parse config bundle: %w", err)
	}
	if doc.Kind != Kind {
		return fmt.Errorf("config bundle kind must be %s", Kind)
	}
	if doc.Version != 0 && doc.Version != 1 {
		return fmt.Errorf("unsupported config bundle version %d", doc.Version)
	}
	cfg.Default = doc.Default
	cfg.Session = doc.Session
	cfg.Policies = doc.Policies
	cfg.Groups = doc.Groups
	cfg.Tasks = doc.Tasks
	next := map[string]*config.Env{}
	for name, env := range cfg.Envs {
		if config.IsBuiltinEnv(name) && env != nil {
			next[name] = env
		}
	}
	for name, env := range doc.Envs {
		if env == nil {
			continue
		}
		if config.IsBuiltinEnv(name) {
			base := next[name]
			if base == nil {
				canon, ok := config.BuiltinEnv(name)
				if !ok {
					continue
				}
				base = &canon
				next[name] = base
			}
			// The key is present, so false is an explicit value and must not
			// be dropped on the floor during a cross-directory migrate.
			base.NoDataOutflow = env.NoDataOutflow
			if env.BreakGlass != nil {
				bg := *env.BreakGlass
				base.BreakGlass = &bg
			} else {
				base.BreakGlass = nil
			}
			continue
		}
		next[name] = env
	}
	cfg.Envs = next
	return nil
}

func rejectSecretKeys(data []byte) error {
	var node yaml.Node
	if err := yaml.Unmarshal(data, &node); err != nil {
		return fmt.Errorf("parse config bundle: %w", err)
	}
	var bad string
	walk(&node, func(key string) {
		switch strings.ToLower(key) {
		case "password", "secret", "masterkey", "master_key":
			if bad == "" {
				bad = key
			}
		}
	})
	if bad != "" {
		return fmt.Errorf("config bundle refuses plaintext field %q", bad)
	}
	return nil
}

func walk(n *yaml.Node, fn func(string)) {
	if n == nil {
		return
	}
	if n.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(n.Content); i += 2 {
			fn(n.Content[i].Value)
			walk(n.Content[i+1], fn)
		}
		return
	}
	for _, c := range n.Content {
		walk(c, fn)
	}
}
