package cli

import (
	"strings"

	"github.com/spf13/cobra"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/catalog"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/config"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/exitcode"
)

func (a *App) policyList() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List named policies, including built-ins",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.Load(a.Dir)
			if err != nil {
				return exitcode.New(exitcode.Usage, "%s", err.Error())
			}
			views := catalog.ListPolicies(cfg)
			if a.JSON {
				return a.emit(map[string]any{"policies": views})
			}
			rows := make([][]string, len(views))
			for i, v := range views {
				mode := v.Mode
				if mode == "" {
					mode = "-"
				}
				rows[i] = []string{v.Name, v.Source, mode, strings.Join(v.Deny, ", "), strings.Join(v.Confirm, ", ")}
			}
			a.table([]string{"NAME", "SOURCE", "MODE", "DENY", "CONFIRM"}, rows)
			return nil
		},
	}
}

func (a *App) policyAdd() *cobra.Command {
	var d policyFlagSet
	cmd := &cobra.Command{
		Use:   "add <name>",
		Short: "Add a named allow/deny/confirm policy",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			draft, err := d.draft(cmd, args[0], false)
			if err != nil {
				return err
			}
			return catalogErr(catalog.AddPolicy(a.Dir, draft))
		},
	}
	d.bind(cmd)
	return cmd
}

func (a *App) policyEdit() *cobra.Command {
	var d policyFlagSet
	cmd := &cobra.Command{
		Use:   "edit <name>",
		Short: "Edit a named policy, or override a built-in",
		Long:  "Partial flags change only those fields. Overriding readonly, standard, or admin writes a hosts.yaml entry that replaces the built-in of the same name. HMAC signing is not implemented.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			draft, err := d.draft(cmd, args[0], true)
			if err != nil {
				return err
			}
			return a.withConfirm(func(phrase string) error {
				draft.HumanConfirm = phrase
				return catalog.EditPolicy(a.Dir, draft)
			})
		},
	}
	d.bind(cmd)
	cmd.Flags().BoolVar(&d.unsetAllow, "unset-allow", false, "remove the allow-list so this policy does not constrain commands")
	cmd.Flags().BoolVar(&d.clearDeny, "clear-deny", false, "remove deny patterns")
	cmd.Flags().BoolVar(&d.clearConfirm, "clear-confirm", false, "remove confirm patterns")
	cmd.Flags().BoolVar(&d.clearPaths, "clear-protected-paths", false, "remove protected paths")
	cmd.Flags().BoolVar(&d.clearRelay, "clear-relay", false, "remove the relay capability")
	cmd.Flags().BoolVar(&d.unsetService, "unset-service", false, "remove the service-action list")
	return cmd
}

func (a *App) policyRemove() *cobra.Command {
	return &cobra.Command{
		Use:   "remove <name>",
		Short: "Remove a named policy from hosts.yaml",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return catalogErr(catalog.RemovePolicy(a.Dir, args[0]))
		},
	}
}

type policyFlagSet struct {
	mode         string
	allow        []string
	deny         []string
	confirm      []string
	paths        []string
	upload       string
	download     string
	forward      string
	relay        string
	service      []string
	allowEmpty   bool
	serviceEmpty bool
	unsetAllow   bool
	clearDeny    bool
	clearConfirm bool
	clearPaths   bool
	clearRelay   bool
	unsetService bool
}

func (p *policyFlagSet) bind(cmd *cobra.Command) {
	cmd.Flags().StringVar(&p.mode, "mode", "", "readonly, standard, or admin")
	cmd.Flags().StringArrayVar(&p.allow, "allow", nil, "allow pattern (repeatable; replaces the list)")
	cmd.Flags().StringArrayVar(&p.deny, "deny", nil, "deny pattern (repeatable; replaces the list)")
	cmd.Flags().StringArrayVar(&p.confirm, "confirm", nil, "confirm pattern (repeatable; replaces the list)")
	cmd.Flags().StringArrayVar(&p.paths, "protected-path", nil, "protected remote path (repeatable)")
	cmd.Flags().StringVar(&p.upload, "upload", "", "capability: true or false")
	cmd.Flags().StringVar(&p.download, "download", "", "capability: true or false")
	cmd.Flags().StringVar(&p.forward, "forward", "", "capability: true or false")
	cmd.Flags().StringVar(&p.relay, "relay", "", "allow, deny, or source-only")
	cmd.Flags().StringArrayVar(&p.service, "service", nil, "service action (repeatable): status, start, stop, restart, reload")
	cmd.Flags().BoolVar(&p.allowEmpty, "allow-empty", false, "store an empty allow-list (this layer allows nothing)")
	cmd.Flags().BoolVar(&p.serviceEmpty, "service-empty", false, "store an empty service-action list")
}

func (p *policyFlagSet) draft(cmd *cobra.Command, name string, edit bool) (catalog.PolicyDraft, error) {
	if p.allowEmpty && cmd.Flags().Changed("allow") {
		return catalog.PolicyDraft{}, exitcode.New(exitcode.Usage, "use only one of --allow and --allow-empty")
	}
	if p.allowEmpty && p.unsetAllow {
		return catalog.PolicyDraft{}, exitcode.New(exitcode.Usage, "use only one of --allow-empty and --unset-allow")
	}
	if p.serviceEmpty && cmd.Flags().Changed("service") {
		return catalog.PolicyDraft{}, exitcode.New(exitcode.Usage, "use only one of --service and --service-empty")
	}
	if p.serviceEmpty && p.unsetService {
		return catalog.PolicyDraft{}, exitcode.New(exitcode.Usage, "use only one of --service-empty and --unset-service")
	}
	d := catalog.PolicyDraft{
		Name:           name,
		Mode:           p.mode,
		Allow:          splitList(p.allow),
		Deny:           splitList(p.deny),
		Confirm:        splitList(p.confirm),
		ProtectedPaths: splitList(p.paths),
		Relay:          p.relay,
		Service:        splitList(p.service),
		AllowEmpty:     p.allowEmpty,
		UnsetAllow:     p.unsetAllow,
		ServiceEmpty:   p.serviceEmpty,
		UnsetService:   p.unsetService,
		ClearDeny:      p.clearDeny,
		ClearConfirm:   p.clearConfirm,
		ClearPaths:     p.clearPaths,
		ClearRelay:     p.clearRelay,
	}
	if cmd.Flags().Changed("mode") {
		d.HasMode = true
	}
	if cmd.Flags().Changed("allow") {
		d.HasAllow = true
	}
	if cmd.Flags().Changed("deny") {
		d.HasDeny = true
	}
	if cmd.Flags().Changed("confirm") {
		d.HasConfirm = true
	}
	if cmd.Flags().Changed("protected-path") {
		d.HasPaths = true
	}
	if cmd.Flags().Changed("relay") {
		d.HasRelay = true
	}
	if cmd.Flags().Changed("service") {
		d.HasService = true
	}
	var err error
	if d.Upload, d.HasUpload, err = optionalBoolFlag(cmd, "upload", p.upload); err != nil {
		return catalog.PolicyDraft{}, err
	}
	if d.Download, d.HasDownload, err = optionalBoolFlag(cmd, "download", p.download); err != nil {
		return catalog.PolicyDraft{}, err
	}
	if d.Forward, d.HasForward, err = optionalBoolFlag(cmd, "forward", p.forward); err != nil {
		return catalog.PolicyDraft{}, err
	}
	if !edit && !d.HasMode && !d.HasAllow && !d.AllowEmpty && !d.HasDeny && !d.HasConfirm && !d.HasPaths &&
		!d.HasUpload && !d.HasDownload && !d.HasForward && !d.HasRelay && !d.HasService && !d.ServiceEmpty {
		return catalog.PolicyDraft{}, exitcode.New(exitcode.Usage, "set at least one of --mode, --allow, --deny, --confirm, or a capability")
	}
	return d, nil
}

func optionalBoolFlag(cmd *cobra.Command, name, value string) (*bool, bool, error) {
	if !cmd.Flags().Changed(name) {
		return nil, false, nil
	}
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "true", "1", "yes":
		v := true
		return &v, true, nil
	case "false", "0", "no":
		v := false
		return &v, true, nil
	default:
		return nil, false, exitcode.New(exitcode.Usage, "--%s must be true or false", name)
	}
}
