package confirmgate

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/config"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/fsutil"
)

const bindFile = "cred.bind"

// credBind is one known use of a passwordRef or identity file.
// Lines are kept after the host that created them is deleted, so a later
// import cannot point that credential at a new address without host_move.
type credBind struct {
	Kind  string
	Value string
	Host  string
	Port  int
	User  string
	Env   string
	Alias string
}

func (b credBind) id() string {
	return strings.Join([]string{b.Kind, b.Value, b.Host, strconv.Itoa(b.Port)}, "\x00")
}

// Install records credential bindings after each successful config save.
func Install() {
	config.AfterSave = rememberBindings
}

// ImportNeeds is ConfigNeeds plus bindings saved from earlier configs.
// A host deleted in one import and recreated in the next still has to confirm
// when it reuses passwordRef or identity at a different address.
func ImportNeeds(dir string, prev, next *config.Config) ([]Need, error) {
	if err := ensureBindings(dir, prev); err != nil {
		return nil, err
	}
	extra, err := loadBindings(dir)
	if err != nil {
		return nil, err
	}
	return configNeeds(prev, next, extra)
}

func ensureBindings(dir string, cfg *config.Config) error {
	if strings.TrimSpace(dir) == "" {
		return nil
	}
	path := filepath.Join(dir, bindFile)
	if _, err := os.Stat(path); err == nil {
		return nil
	} else if err != nil && !os.IsNotExist(err) {
		return err
	}
	return writeBindings(dir, bindingsFrom(cfg))
}

func rememberBindings(dir string, cfg *config.Config) error {
	if strings.TrimSpace(dir) == "" || cfg == nil {
		return nil
	}
	cur, err := loadBindings(dir)
	if err != nil {
		return err
	}
	return writeBindings(dir, mergeBindings(cur, bindingsFrom(cfg)))
}

func bindingsFrom(cfg *config.Config) []credBind {
	if cfg == nil {
		return nil
	}
	var out []credBind
	for alias, h := range cfg.Index() {
		if h.Host == nil {
			continue
		}
		out = append(out, bindsFor(alias, h.EnvName, h.Host)...)
	}
	return mergeBindings(nil, out)
}

func bindsFor(alias, env string, h *config.Host) []credBind {
	if h == nil {
		return nil
	}
	var out []credBind
	if ref := strings.TrimSpace(h.PasswordRef); ref != "" {
		if b, ok := newBind("passwordRef", ref, alias, env, h); ok {
			out = append(out, b)
		}
	}
	if id := strings.TrimSpace(h.Identity); id != "" {
		if b, ok := newBind("identity", id, alias, env, h); ok {
			out = append(out, b)
		}
	}
	return out
}

func newBind(kind, value, alias, env string, h *config.Host) (credBind, bool) {
	b := credBind{
		Kind: kind, Value: value, Alias: alias, Env: env,
		Host: strings.TrimSpace(h.Host), Port: h.PortOrDefault(), User: h.User,
	}
	if !fieldOK(b.Kind) || !fieldOK(b.Value) || !fieldOK(b.Host) || !fieldOK(b.User) || !fieldOK(b.Env) || !fieldOK(b.Alias) {
		return credBind{}, false
	}
	return b, true
}

func fieldOK(s string) bool {
	return !strings.ContainsAny(s, "\t\r\n")
}

func mergeBindings(lists ...[]credBind) []credBind {
	seen := map[string]bool{}
	var out []credBind
	for _, list := range lists {
		for _, b := range list {
			if b.Kind == "" || b.Value == "" || seen[b.id()] {
				continue
			}
			seen[b.id()] = true
			out = append(out, b)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		if out[i].Value != out[j].Value {
			return out[i].Value < out[j].Value
		}
		if out[i].Host != out[j].Host {
			return out[i].Host < out[j].Host
		}
		return out[i].Port < out[j].Port
	})
	return out
}

func loadBindings(dir string) ([]credBind, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(filepath.Join(dir, bindFile))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	text := strings.TrimSpace(string(raw))
	if text == "" {
		return nil, nil
	}
	lines := strings.Split(text, "\n")
	if strings.TrimSpace(lines[0]) != "v1" {
		return nil, fmt.Errorf("credential bindings: unrecognized %s", bindFile)
	}
	var out []credBind
	for _, line := range lines[1:] {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) != 7 {
			return nil, fmt.Errorf("credential bindings: unrecognized %s", bindFile)
		}
		port, err := strconv.Atoi(f[3])
		if err != nil || port <= 0 {
			return nil, fmt.Errorf("credential bindings: unrecognized %s", bindFile)
		}
		b := credBind{Kind: f[0], Value: f[1], Host: f[2], Port: port, User: f[4], Env: f[5], Alias: f[6]}
		if (b.Kind != "passwordRef" && b.Kind != "identity") || b.Value == "" || b.Host == "" {
			return nil, fmt.Errorf("credential bindings: unrecognized %s", bindFile)
		}
		out = append(out, b)
	}
	return out, nil
}

func writeBindings(dir string, binds []credBind) error {
	binds = mergeBindings(binds)
	var b strings.Builder
	b.WriteString("v1\n")
	for _, item := range binds {
		fmt.Fprintf(&b, "%s\t%s\t%s\t%d\t%s\t%s\t%s\n", item.Kind, item.Value, item.Host, item.Port, item.User, item.Env, item.Alias)
	}
	return fsutil.WriteAtomic(filepath.Join(dir, bindFile), []byte(b.String()), 0o600)
}
