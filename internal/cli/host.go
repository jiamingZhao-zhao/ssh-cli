package cli

import (
	"fmt"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/catalog"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/config"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/exitcode"
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
			if f.group == "" || f.address == "" || f.user == "" {
				return exitcode.New(exitcode.Usage, "--group, --host, and --user are required")
			}
			if f.identity != "" && f.pwStdin {
				return exitcode.New(exitcode.Usage, "pass only one of --identity and --password-stdin")
			}
			if err := checkPort(f.port); err != nil {
				return err
			}
			draft := catalog.HostDraft{
				Alias:      alias,
				Group:      f.group,
				Address:    f.address,
				User:       f.user,
				Identity:   f.identity,
				Policy:     f.policy,
				Tags:       splitList(f.tags),
				SetDefault: f.def,
			}
			if f.port != 0 {
				p := f.port
				draft.Port = &p
			}
			if f.identity == "" {
				pw, err := readPassword(a.In, a.Err, f.pwStdin)
				if err != nil {
					return err
				}
				draft.Password = pw
			}
			return catalogErr(catalog.AddHost(a.Dir, draft, catalog.Options{Warn: a.Err}))
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
				Policy      string   `json:"policy,omitempty"`
				PasswordRef string   `json:"passwordRef,omitempty"`
			}
			views := make([]view, 0, len(aliases))
			for _, alias := range aliases {
				h := index[alias]
				views = append(views, view{
					Alias: alias, Group: h.Group, Env: h.EnvName,
					Host: h.Host.Host, Port: h.Host.PortOrDefault(), User: h.Host.User,
					Auth: authLabel(h.Host), Tags: h.Host.Tags, Policy: h.Host.Policy,
					PasswordRef: h.Host.PasswordRef,
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
			return catalogErr(catalog.RemoveHost(a.Dir, args[0], catalog.Options{Warn: a.Err}))
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
			draft := catalog.HostDraft{Alias: alias}
			if cmd.Flags().Changed("group") {
				draft.HasGroup = true
				draft.Group = f.group
			}
			if cmd.Flags().Changed("host") {
				draft.HasAddress = true
				draft.Address = f.address
			}
			if cmd.Flags().Changed("port") {
				draft.HasPort = true
				p := f.port
				draft.Port = &p
			}
			if cmd.Flags().Changed("user") {
				draft.HasUser = true
				draft.User = f.user
			}
			if cmd.Flags().Changed("policy") {
				draft.HasPolicy = true
				draft.Policy = f.policy
			}
			if cmd.Flags().Changed("tag") {
				draft.HasTags = true
				draft.Tags = splitList(f.tags)
			}
			if f.clearTag {
				draft.ClearTags = true
			}
			if f.def {
				draft.SetDefault = true
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
			if cmd.Flags().Changed("identity") {
				draft.HasIdentity = true
				draft.Identity = f.identity
			}
			if f.pwStdin {
				pw, err := readPassword(a.In, a.Err, true)
				if err != nil {
					return err
				}
				draft.HasPassword = true
				draft.Password = pw
			}
			return a.withConfirm(func(phrase string) error {
				return catalog.UpdateHost(a.Dir, draft, catalog.Options{Warn: a.Err, HumanConfirm: phrase})
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

func (a *App) table(headers []string, rows [][]string) {
	p := a.printer()
	p.Table(headers, rows)
}

func catalogErr(err error) error {
	if err == nil {
		return nil
	}
	return exitcode.New(exitcode.Usage, "%s", err.Error())
}
