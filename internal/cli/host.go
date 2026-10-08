package cli

import (
	"fmt"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/config"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/exitcode"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/guard"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/secrets"
)

func (a *App) hostCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "host",
		Short: "Manage hosts",
	}
	cmd.AddCommand(a.hostAdd(), a.hostList(), a.hostRemove(), a.hostEdit())
	return cmd
}

type hostFlags struct {
	group    string
	address  string
	port     int
	user     string
	identity string
	pwStdin  bool
	policy   string
	tags     []string
	def      bool
	clearTag bool
}

func bindHostFlags(cmd *cobra.Command, f *hostFlags, add bool) {
	req := ""
	if add {
		req = " (required)"
	}
	cmd.Flags().StringVar(&f.group, "group", "", "group the host belongs to"+req)
	cmd.Flags().StringVar(&f.address, "host", "", "address or DNS name"+req)
	cmd.Flags().IntVar(&f.port, "port", 0, "port (default 22)")
	cmd.Flags().StringVar(&f.user, "user", "", "login user"+req)
	cmd.Flags().StringVar(&f.identity, "identity", "", "private key path (unencrypted)")
	cmd.Flags().BoolVar(&f.pwStdin, "password-stdin", false, "read the password from stdin")
	cmd.Flags().StringVar(&f.policy, "policy", "", "named policy")
	cmd.Flags().StringArrayVar(&f.tags, "tag", nil, "tag (repeatable; replaces tags on edit)")
	cmd.Flags().BoolVar(&f.def, "set-default", false, "make this the default host")
	if !add {
		cmd.Flags().BoolVar(&f.clearTag, "clear-tags", false, "remove all tags")
	}
}

func (a *App) hostAdd() *cobra.Command {
	var f hostFlags
	cmd := &cobra.Command{
		Use:   "add <alias>",
		Short: "Add one host",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			alias := args[0]
			if !config.ValidName(alias) {
				return exitcode.New(exitcode.Usage, "invalid host alias %q", alias)
			}
			if f.group == "" || f.address == "" || f.user == "" {
				return exitcode.New(exitcode.Usage, "--group, --host, and --user are required")
			}
			if f.identity != "" && f.pwStdin {
				return exitcode.New(exitcode.Usage, "pass only one of --identity and --password-stdin")
			}
			if err := checkPort(f.port); err != nil {
				return err
			}
			var password string
			if f.identity == "" {
				pw, err := readPassword(a.In, a.Err, f.pwStdin)
				if err != nil {
					return err
				}
				password = pw
			}
			return config.Update(a.Dir, func(cfg *config.Config) error {
				if _, ok := cfg.Find(alias); ok {
					return exitcode.New(exitcode.Usage, "host %q already exists", alias)
				}
				g, ok := cfg.Groups[f.group]
				if !ok {
					return exitcode.New(exitcode.Usage, "group %q not found", f.group)
				}
				if f.policy != "" && !guard.KnownPolicy(cfg, f.policy) {
					return exitcode.New(exitcode.Usage, "unknown policy %q", f.policy)
				}
				h := &config.Host{
					Host:   f.address,
					User:   f.user,
					Port:   normalizePort(f.port),
					Tags:   splitList(f.tags),
					Policy: f.policy,
				}
				if f.identity != "" {
					h.Auth = "key"
					h.Identity = f.identity
				} else {
					h.Auth = "password"
					h.PasswordRef = f.group + "." + alias
					st, err := secrets.Open(a.Dir, secrets.Options{Warn: a.Err})
					if err != nil {
						return err
					}
					if err := st.Put(h.PasswordRef, password); err != nil {
						return err
					}
					if err := st.Save(); err != nil {
						return err
					}
				}
				if g.Hosts == nil {
					g.Hosts = map[string]*config.Host{}
				}
				g.Hosts[alias] = h
				if f.def {
					cfg.Default = alias
				}
				return nil
			})
		},
	}
	bindHostFlags(cmd, &f, true)
	return cmd
}

func (a *App) hostList() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List hosts (secrets are never shown)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.Load(a.Dir)
			if err != nil {
				return exitcode.New(exitcode.Usage, "%s", err.Error())
			}
			index := cfg.Index()
			aliases := make([]string, 0, len(index))
			for alias := range index {
				aliases = append(aliases, alias)
			}
			sort.Strings(aliases)
			if a.Env != "" {
				filtered := aliases[:0]
				for _, alias := range aliases {
					if index[alias].EnvName == a.Env {
						filtered = append(filtered, alias)
					}
				}
				aliases = filtered
			}
			type view struct {
				Alias       string   `json:"alias"`
				Group       string   `json:"group"`
				Env         string   `json:"env"`
				Host        string   `json:"host"`
				Port        int      `json:"port"`
				User        string   `json:"user"`
				Auth        string   `json:"auth"`
				Tags        []string `json:"tags,omitempty"`
				PasswordRef string   `json:"passwordRef,omitempty"`
			}
			views := make([]view, 0, len(aliases))
			for _, alias := range aliases {
				h := index[alias]
				views = append(views, view{
					Alias: alias, Group: h.Group, Env: h.EnvName,
					Host: h.Host.Host, Port: h.Host.PortOrDefault(), User: h.Host.User,
					Auth: authLabel(h.Host), Tags: h.Host.Tags, PasswordRef: h.Host.PasswordRef,
				})
			}
			if a.JSON {
				return a.emit(map[string]any{"hosts": views})
			}
			rows := make([][]string, len(views))
			for i, v := range views {
				rows[i] = []string{v.Alias, v.Group, v.Env, v.Host, fmt.Sprintf("%d", v.Port), v.User, v.Auth, strings.Join(v.Tags, ",")}
			}
			a.table([]string{"ALIAS", "GROUP", "ENV", "HOST", "PORT", "USER", "AUTH", "TAGS"}, rows)
			return nil
		},
	}
}

func (a *App) hostRemove() *cobra.Command {
	return &cobra.Command{
		Use:   "remove <alias>",
		Short: "Remove one host",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			alias := args[0]
			return config.Update(a.Dir, func(cfg *config.Config) error {
				found, ok := cfg.Find(alias)
				if !ok {
					return exitcode.New(exitcode.Usage, "host %q not found", alias)
				}
				ref := found.Host.PasswordRef
				delete(found.GroupDef.Hosts, alias)
				if cfg.Default == alias {
					cfg.Default = ""
				}
				if ref != "" && cfg.PasswordRefs()[ref] == 0 {
					st, err := secrets.Open(a.Dir, secrets.Options{Warn: a.Err})
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
		},
	}
}

func (a *App) hostEdit() *cobra.Command {
	var f hostFlags
	cmd := &cobra.Command{
		Use:   "edit <alias>",
		Short: "Edit one host without rewriting the others",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			alias := args[0]
			changed := cmd.Flags().Changed("group") || cmd.Flags().Changed("host") || cmd.Flags().Changed("port") ||
				cmd.Flags().Changed("user") || cmd.Flags().Changed("identity") || cmd.Flags().Changed("password-stdin") ||
				cmd.Flags().Changed("policy") || cmd.Flags().Changed("tag") || cmd.Flags().Changed("set-default") ||
				cmd.Flags().Changed("clear-tags")
			if !changed {
				return exitcode.New(exitcode.Usage, "no changes given")
			}
			if f.clearTag && cmd.Flags().Changed("tag") {
				return exitcode.New(exitcode.Usage, "use only one of --tag and --clear-tags")
			}
			if f.identity != "" && f.pwStdin {
				return exitcode.New(exitcode.Usage, "pass only one of --identity and --password-stdin")
			}
			if err := checkPort(f.port); err != nil {
				return err
			}
			var password string
			if f.pwStdin {
				pw, err := readPassword(a.In, a.Err, true)
				if err != nil {
					return err
				}
				password = pw
			}
			return config.Update(a.Dir, func(cfg *config.Config) error {
				found, ok := cfg.Find(alias)
				if !ok {
					return exitcode.New(exitcode.Usage, "host %q not found", alias)
				}
				h := found.Host
				oldRef := h.PasswordRef
				if cmd.Flags().Changed("group") {
					g, ok := cfg.Groups[f.group]
					if !ok {
						return exitcode.New(exitcode.Usage, "group %q not found", f.group)
					}
					delete(found.GroupDef.Hosts, alias)
					if g.Hosts == nil {
						g.Hosts = map[string]*config.Host{}
					}
					g.Hosts[alias] = h
					found.GroupDef = g
					found.Group = f.group
				}
				if cmd.Flags().Changed("host") {
					if strings.TrimSpace(f.address) == "" {
						return exitcode.New(exitcode.Usage, "empty address")
					}
					h.Host = f.address
				}
				if cmd.Flags().Changed("port") {
					h.Port = normalizePort(f.port)
				}
				if cmd.Flags().Changed("user") {
					if f.user == "" {
						return exitcode.New(exitcode.Usage, "empty user")
					}
					h.User = f.user
				}
				if cmd.Flags().Changed("policy") {
					if f.policy != "" && !guard.KnownPolicy(cfg, f.policy) {
						return exitcode.New(exitcode.Usage, "unknown policy %q", f.policy)
					}
					h.Policy = f.policy
				}
				if cmd.Flags().Changed("tag") {
					h.Tags = splitList(f.tags)
				}
				if f.clearTag {
					h.Tags = nil
				}
				if f.def {
					cfg.Default = alias
				}
				st, err := secrets.Open(a.Dir, secrets.Options{Warn: a.Err})
				if err != nil {
					return err
				}
				dirtySecrets := false
				if f.identity != "" {
					h.Auth = "key"
					h.Identity = f.identity
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
					dirtySecrets = true
				}
				if oldRef != "" && oldRef != h.PasswordRef && cfg.PasswordRefs()[oldRef] == 0 {
					st.Delete(oldRef)
					dirtySecrets = true
				}
				if dirtySecrets {
					if err := st.Save(); err != nil {
						return err
					}
				}
				return nil
			})
		},
	}
	bindHostFlags(cmd, &f, false)
	return cmd
}

func authLabel(h *config.Host) string {
	if h.Auth != "" {
		return h.Auth
	}
	if h.Identity != "" {
		return "key"
	}
	if h.PasswordRef != "" {
		return "password"
	}
	return "unset"
}

func checkPort(port int) error {
	if port < 0 || port > 65535 {
		return exitcode.New(exitcode.Usage, "invalid port %d", port)
	}
	return nil
}

func normalizePort(port int) int {
	if port == 22 {
		return 0
	}
	return port
}

func (a *App) table(headers []string, rows [][]string) {
	p := a.printer()
	p.Table(headers, rows)
}
