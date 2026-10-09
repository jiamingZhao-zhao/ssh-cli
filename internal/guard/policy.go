// Package guard evaluates the env → group → host policy intersection.
package guard

import (
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/config"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/transfer"
)

// Finding explains one rule that affected a decision.
type Finding struct {
	Layer  string `json:"layer"`
	Kind   string `json:"kind"`
	Detail string `json:"detail"`
}

// Decision is the result of checking one command or capability.
type Decision struct {
	Allowed      bool      `json:"allowed"`
	NeedsConfirm bool      `json:"needsConfirm"`
	Mode         string    `json:"mode"`
	Findings     []Finding `json:"findings,omitempty"`
	Commands     []string  `json:"commands,omitempty"`
}

// Effective is the merged policy for one host.
type Effective struct {
	Mode       config.Mode `json:"mode"`
	Clamped    bool        `json:"modeClamped"`
	Allow      []string    `json:"allow,omitempty"`
	AllowAll   bool        `json:"allowUniversal"`
	AllowEmpty bool        `json:"allowEmpty"`
	Deny       []string    `json:"deny,omitempty"`
	Confirm    []string    `json:"confirm,omitempty"`
	Upload     bool        `json:"-"`
	Download   bool        `json:"-"`
	Relay      string      `json:"-"`
	Forward    bool        `json:"-"`
	Service    []string    `json:"-"`
	ServiceAll bool        `json:"-"`
	Protected  []string    `json:"protectedPaths,omitempty"`
	NoDataOut  bool        `json:"-"`
	Warnings   []string    `json:"warnings,omitempty"`
	layers     []layer
	// fallback is an extra allow-list used when readonly mode had no configured
	// allow-list, including a prod batch forced down to readonly.
	fallback allowSet
}

// Capabilities is the JSON view of ability switches.
type Capabilities struct {
	Upload     bool     `json:"upload"`
	Download   bool     `json:"download"`
	Relay      string   `json:"relay"`
	Forward    bool     `json:"forward"`
	Service    []string `json:"service,omitempty"`
	ServiceAll bool     `json:"serviceAll,omitempty"`
}

// Caps returns the capability view of an effective policy.
func (e Effective) Caps() Capabilities {
	return Capabilities{
		Upload: e.Upload, Download: e.Download, Relay: e.Relay, Forward: e.Forward,
		Service: e.Service, ServiceAll: e.ServiceAll,
	}
}

type layer struct {
	name    string
	mode    config.Mode
	allow   allowSet
	deny    []string
	confirm []string
	caps    *config.Capabilities
	paths   []string
}

// Resolve merges env, group, and host policy. forceReadonly is the batch ceiling
// applied when a multi-host selection includes prod.
func Resolve(cfg *config.Config, h config.ResolvedHost, forceReadonly bool) (Effective, error) {
	if h.Host == nil || h.GroupDef == nil {
		return Effective{}, fmt.Errorf("host %s is incomplete", h.Alias)
	}
	if h.Env == nil {
		return Effective{}, fmt.Errorf("host %s: env %q is not defined", h.Alias, h.EnvName)
	}
	envPol, err := lookupPolicy(cfg, h.Env.DefaultPolicy)
	if err != nil {
		return Effective{}, fmt.Errorf("env %s: %w", h.EnvName, err)
	}
	groupPol, err := lookupPolicy(cfg, h.GroupDef.Policy)
	if err != nil {
		return Effective{}, fmt.Errorf("group %s: %w", h.Group, err)
	}
	var hostPol *config.Policy
	if h.Host.Policy != "" {
		hostPol, err = lookupPolicy(cfg, h.Host.Policy)
		if err != nil {
			return Effective{}, fmt.Errorf("host %s: %w", h.Alias, err)
		}
	}
	layers := []layer{
		compose("env", envPol, nil, nil, nil, nil),
		compose("group", groupPol, h.GroupDef.Allow, h.GroupDef.Deny, h.GroupDef.Confirm, h.GroupDef.Capabilities),
		compose("host", hostPol, h.Host.Allow, h.Host.Deny, h.Host.Confirm, h.Host.Capabilities),
	}
	layers[1].paths = append(layers[1].paths, h.GroupDef.ProtectedPaths...)
	layers[2].paths = append(layers[2].paths, h.Host.ProtectedPaths...)

	var warnings []string
	requested := config.ModeUnset
	clamped := false
	for _, l := range layers {
		if l.mode.Rank() > h.Env.MaxMode.Rank() && l.mode.Valid() && h.Env.MaxMode.Valid() {
			clamped = true
			warnings = append(warnings, fmt.Sprintf("%s policy mode %s exceeds env maxMode %s and was clamped", l.name, l.mode, h.Env.MaxMode))
		}
		requested = config.Stricter(requested, l.mode)
	}
	mode := config.Stricter(requested, h.Env.MaxMode)
	if forceReadonly && mode != config.ModeReadonly {
		mode = config.ModeReadonly
		clamped = true
		warnings = append(warnings, "batch includes prod; effective mode forced to readonly")
	}
	if mode != requested && requested.Valid() && h.Env.MaxMode.Valid() && mode == h.Env.MaxMode && requested != h.Env.MaxMode {
		clamped = true
	}

	allows := make([]allowSet, len(layers))
	for i, l := range layers {
		allows[i] = l.allow
	}
	mergedAllow := intersectAllow(allows)
	fallback := allowSet{universal: true}
	if mode == config.ModeReadonly && mergedAllow.universal {
		fallback = allowFrom(builtinPolicies()["readonly"].Allow)
		mergedAllow = fallback
		warnings = append(warnings, "readonly mode had no allow-list; applied the built-in readonly whitelist")
	}

	deny := []string{}
	confirm := []string{}
	var paths []string
	seenDeny := map[string]bool{}
	seenConfirm := map[string]bool{}
	seenPath := map[string]bool{}
	for _, l := range layers {
		for _, d := range l.deny {
			if seenDeny[d] {
				continue
			}
			seenDeny[d] = true
			deny = append(deny, d)
		}
		for _, c := range l.confirm {
			if seenConfirm[c] {
				continue
			}
			seenConfirm[c] = true
			confirm = append(confirm, c)
		}
		for _, pth := range l.paths {
			if seenPath[pth] {
				continue
			}
			seenPath[pth] = true
			paths = append(paths, pth)
		}
	}
	sort.Strings(paths)

	upload, download, forward, relay := mergeCaps(layers, mode)
	service, serviceAll := mergeService(layers, mode)

	eff := Effective{
		Mode:       mode,
		Clamped:    clamped,
		Allow:      mergedAllow.strings(),
		AllowAll:   mergedAllow.universal,
		AllowEmpty: mergedAllow.empty(),
		Deny:       deny,
		Confirm:    confirm,
		Upload:     upload,
		Download:   download,
		Relay:      string(relay),
		Forward:    forward,
		Service:    service,
		ServiceAll: serviceAll,
		Protected:  paths,
		NoDataOut:  h.Env.NoDataOutflow,
		Warnings:   warnings,
		layers:     layers,
		fallback:   fallback,
	}
	if eff.AllowEmpty {
		eff.Warnings = append(eff.Warnings, "effective allow-list intersection is empty; every command is denied")
	}
	return eff, nil
}

func compose(name string, pol *config.Policy, inlineAllow *[]string, inlineDeny, inlineConfirm []string, inlineCaps *config.Capabilities) layer {
	l := layer{name: name, allow: allowSet{universal: true}}
	var policyAllow *[]string
	if pol != nil {
		l.mode = pol.Mode
		policyAllow = pol.Allow
		l.deny = append([]string(nil), pol.Deny...)
		l.confirm = append([]string(nil), pol.Confirm...)
		l.caps = cloneCaps(pol.Capabilities)
		l.paths = append([]string(nil), pol.ProtectedPaths...)
	}
	l.allow = mergeAllow(policyAllow, inlineAllow)
	l.deny = append(l.deny, inlineDeny...)
	l.confirm = append(l.confirm, inlineConfirm...)
	l.caps = mergeCapPair(l.caps, inlineCaps)
	return l
}

func cloneCaps(c *config.Capabilities) *config.Capabilities {
	if c == nil {
		return nil
	}
	out := *c
	out.Upload = cloneBool(c.Upload)
	out.Download = cloneBool(c.Download)
	out.Forward = cloneBool(c.Forward)
	if c.Service != nil {
		s := append([]string(nil), (*c.Service)...)
		out.Service = &s
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

func mergeAllow(a, b *[]string) allowSet {
	return intersectAllow([]allowSet{allowFrom(a), allowFrom(b)})
}

func mergeCapPair(a, b *config.Capabilities) *config.Capabilities {
	if a == nil && b == nil {
		return nil
	}
	out := cloneCaps(a)
	if out == nil {
		out = &config.Capabilities{}
	}
	if b == nil {
		return out
	}
	out.Upload = andBool(out.Upload, b.Upload)
	out.Download = andBool(out.Download, b.Download)
	out.Forward = andBool(out.Forward, b.Forward)
	if b.Relay != "" && (out.Relay == "" || relayRank(b.Relay) < relayRank(out.Relay)) {
		out.Relay = b.Relay
	}
	if b.Service != nil {
		if out.Service == nil {
			s := append([]string(nil), (*b.Service)...)
			out.Service = &s
		} else {
			merged := intersectStrings(*out.Service, *b.Service)
			out.Service = &merged
		}
	}
	return out
}

func andBool(a, b *bool) *bool {
	if a == nil {
		return cloneBool(b)
	}
	if b == nil {
		return cloneBool(a)
	}
	v := *a && *b
	return &v
}

func relayRank(m config.RelayMode) int {
	switch m {
	case config.RelayDeny:
		return 0
	case config.RelaySourceOnly:
		return 1
	case config.RelayAllow:
		return 2
	default:
		return 3
	}
}

func mergeCaps(layers []layer, mode config.Mode) (upload, download, forward bool, relay config.RelayMode) {
	uploadS, downloadS, forwardS := triUnset, triUnset, triUnset
	relay = config.RelayUnset
	for _, l := range layers {
		if l.caps == nil {
			continue
		}
		uploadS = tightenBool(uploadS, l.caps.Upload)
		downloadS = tightenBool(downloadS, l.caps.Download)
		forwardS = tightenBool(forwardS, l.caps.Forward)
		if l.caps.Relay != "" && (relay == "" || relayRank(l.caps.Relay) < relayRank(relay)) {
			relay = l.caps.Relay
		}
	}
	upload = triOrDefault(uploadS, mode != config.ModeReadonly)
	download = triOrDefault(downloadS, true)
	forward = triOrDefault(forwardS, mode != config.ModeReadonly)
	if relay == config.RelayUnset {
		if mode == config.ModeReadonly {
			relay = config.RelaySourceOnly
		} else {
			relay = config.RelayAllow
		}
	}
	return upload, download, forward, relay
}

type tri int

const (
	triUnset tri = iota
	triTrue
	triFalse
)

func tightenBool(cur tri, v *bool) tri {
	if v == nil {
		return cur
	}
	if !*v {
		return triFalse
	}
	if cur == triFalse {
		return triFalse
	}
	return triTrue
}

func triOrDefault(v tri, def bool) bool {
	switch v {
	case triFalse:
		return false
	case triTrue:
		return true
	default:
		return def
	}
}

func mergeService(layers []layer, mode config.Mode) (items []string, all bool) {
	var cur []string
	set := false
	for _, l := range layers {
		if l.caps == nil || l.caps.Service == nil {
			continue
		}
		if !set {
			cur = append([]string(nil), (*l.caps.Service)...)
			set = true
			continue
		}
		cur = intersectStrings(cur, *l.caps.Service)
	}
	if !set {
		if mode == config.ModeReadonly {
			return []string{"status"}, false
		}
		return nil, true
	}
	sort.Strings(cur)
	return cur, false
}

func intersectStrings(a, b []string) []string {
	have := map[string]bool{}
	for _, s := range a {
		have[s] = true
	}
	var out []string
	seen := map[string]bool{}
	for _, s := range b {
		if have[s] && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// Decide checks a shell command string against eff.
func Decide(eff Effective, command string) Decision {
	dec := Decision{Mode: string(eff.Mode), Allowed: true}
	if why := rawCatastrophe(command); why != "" {
		dec.Allowed = false
		dec.Findings = append(dec.Findings, Finding{Layer: "builtin", Kind: "deny", Detail: why})
		return dec
	}
	pr, err := parseScript(command)
	if err != nil {
		return unparseable(eff, err)
	}
	for _, c := range pr.commands {
		dec.Commands = append(dec.Commands, renderArgs(c.args))
	}
	if pr.obfuscated != "" && eff.Mode != config.ModeAdmin {
		dec.Allowed = false
		dec.NeedsConfirm = false
		dec.Findings = append(dec.Findings, Finding{Layer: "parser", Kind: "obfuscated", Detail: pr.obfuscated})
		return dec
	}
	if pr.unresolved != "" {
		finding := Finding{Layer: "parser", Kind: "unparseable", Detail: pr.unresolved}
		if eff.Mode == config.ModeReadonly {
			dec.Allowed = false
			dec.Findings = append(dec.Findings, finding)
			return dec
		}
		dec.NeedsConfirm = true
		finding.Kind = "confirm"
		dec.Findings = append(dec.Findings, finding)
	}
	if pr.dynamic != "" {
		switch eff.Mode {
		case config.ModeReadonly:
			dec.Allowed = false
			dec.Findings = append(dec.Findings, Finding{Layer: "parser", Kind: "unparseable", Detail: pr.dynamic})
			return dec
		case config.ModeStandard:
			dec.NeedsConfirm = true
			dec.Findings = append(dec.Findings, Finding{Layer: "parser", Kind: "confirm", Detail: pr.dynamic})
		}
	}
	for _, c := range pr.commands {
		if isRedirect(c) {
			if why := builtinDeny(c.args); why != "" {
				dec.Allowed = false
				dec.Findings = append(dec.Findings, Finding{Layer: "builtin", Kind: "deny", Detail: why})
			} else if eff.Mode == config.ModeReadonly {
				dec.Allowed = false
				dec.Findings = append(dec.Findings, Finding{Layer: "mode", Kind: "deny", Detail: "readonly mode refuses write redirects"})
			}
			continue
		}
		if !c.args[0].Static {
			finding := Finding{Layer: "parser", Kind: "unparseable", Detail: "command name is not a static literal"}
			switch eff.Mode {
			case config.ModeReadonly:
				dec.Allowed = false
				dec.Findings = append(dec.Findings, finding)
			case config.ModeStandard:
				dec.NeedsConfirm = true
				finding.Kind = "confirm"
				dec.Findings = append(dec.Findings, finding)
			}
			continue
		}
		if why := builtinDeny(c.args); why != "" {
			dec.Allowed = false
			dec.Findings = append(dec.Findings, Finding{Layer: "builtin", Kind: "deny", Detail: why})
			continue
		}
		if why := semanticDeny(eff.Mode, c.args); why != "" {
			dec.Allowed = false
			dec.Findings = append(dec.Findings, Finding{Layer: "builtin", Kind: "deny", Detail: why})
			continue
		}
		for _, l := range eff.layers {
			if pat, ok := matchAny(l.deny, c.args); ok {
				dec.Allowed = false
				dec.Findings = append(dec.Findings, Finding{
					Layer: l.name, Kind: "deny", Detail: "matches deny pattern " + quote(pat),
				})
			}
		}
		for _, l := range eff.layers {
			if l.allow.universal {
				continue
			}
			if !l.allow.allows(c.args) {
				dec.Allowed = false
				dec.Findings = append(dec.Findings, Finding{
					Layer: l.name, Kind: "allow", Detail: "not in allow-list",
				})
			}
		}
		if !eff.fallback.universal && !eff.fallback.allows(c.args) {
			dec.Allowed = false
			dec.Findings = append(dec.Findings, Finding{
				Layer: "mode", Kind: "allow", Detail: "not in the built-in readonly whitelist",
			})
		}
		for _, l := range eff.layers {
			if pat, ok := matchAny(l.confirm, c.args); ok {
				dec.NeedsConfirm = true
				dec.Findings = append(dec.Findings, Finding{
					Layer: l.name, Kind: "confirm", Detail: "matches confirm pattern " + quote(pat),
				})
			}
		}
	}
	if !dec.Allowed {
		dec.NeedsConfirm = false
	}
	return dec
}

func isRedirect(c command) bool {
	return len(c.args) > 0 && c.args[0].Static && c.args[0].Value == "redirect"
}

func unparseable(eff Effective, err error) Decision {
	dec := Decision{Mode: string(eff.Mode)}
	detail := "command did not parse: " + err.Error()
	switch eff.Mode {
	case config.ModeReadonly:
		dec.Allowed = false
		dec.Findings = []Finding{{Layer: "parser", Kind: "unparseable", Detail: detail}}
	case config.ModeStandard:
		dec.Allowed = true
		dec.NeedsConfirm = true
		dec.Findings = []Finding{{Layer: "parser", Kind: "confirm", Detail: detail}}
	default:
		dec.Allowed = true
	}
	return dec
}

func renderArgs(args []Arg) string {
	parts := make([]string, len(args))
	for i, a := range args {
		parts[i] = a.String()
	}
	return strings.Join(parts, " ")
}

func quote(s string) string { return `"` + s + `"` }

// Merge combines command and capability decisions. Any denial wins, and a
// denial clears confirmation. Confirmation is kept when every part allows it.
func Merge(parts ...Decision) Decision {
	out := Decision{Allowed: true}
	for _, p := range parts {
		if p.Mode != "" {
			out.Mode = p.Mode
		}
		out.Commands = append(out.Commands, p.Commands...)
		out.Findings = append(out.Findings, p.Findings...)
		if !p.Allowed {
			out.Allowed = false
		}
		if p.NeedsConfirm {
			out.NeedsConfirm = true
		}
	}
	if !out.Allowed {
		out.NeedsConfirm = false
	}
	return out
}

// DecideService checks the merged service-action capability.
// An unset capability allows every action except where readonly defaults apply,
// which Resolve already folds into Effective.Service.
func DecideService(eff Effective, action string) Decision {
	dec := Decision{Mode: string(eff.Mode), Allowed: true}
	action = strings.TrimSpace(action)
	if eff.ServiceAll {
		return dec
	}
	for _, item := range eff.Service {
		if item == action {
			return dec
		}
	}
	dec.Allowed = false
	dec.Findings = append(dec.Findings, Finding{
		Layer: "capability", Kind: "deny", Detail: "service action " + action + " is not permitted",
	})
	return dec
}

// DecideCapability checks upload/download (and a protected remote path).
func DecideCapability(eff Effective, capability, remotePath string) Decision {
	dec := Decision{Mode: string(eff.Mode), Allowed: true}
	switch capability {
	case "upload":
		if !eff.Upload {
			dec.Allowed = false
			dec.Findings = append(dec.Findings, Finding{Layer: "capability", Kind: "deny", Detail: "upload is disabled"})
		}
	case "download":
		if !eff.Download {
			dec.Allowed = false
			dec.Findings = append(dec.Findings, Finding{Layer: "capability", Kind: "deny", Detail: "download is disabled"})
		}
		if eff.NoDataOut {
			dec.Allowed = false
			dec.Findings = append(dec.Findings, Finding{Layer: "env", Kind: "deny", Detail: "noDataOutflow forbids download"})
		}
	default:
		dec.Allowed = false
		dec.Findings = append(dec.Findings, Finding{Layer: "capability", Kind: "deny", Detail: "unknown capability " + capability})
	}
	if dec.Allowed && capability == "upload" && remotePath != "" && pathProtected(eff.Protected, remotePath) {
		dec.NeedsConfirm = true
		dec.Findings = append(dec.Findings, Finding{
			Layer: "protected", Kind: "confirm", Detail: "path is protected: " + remotePath,
		})
	}
	return dec
}

// DecideRelay checks a stream from src to dst. Source may be allow or
// source-only. Destination must be allow. A protected destination needs confirm.
// noDataOutflow on the source blocks a different destination env.
func DecideRelay(src, dst Effective, srcEnv, dstEnv, destPath string, allowCross bool) Decision {
	dec := Decision{Mode: string(dst.Mode), Allowed: true}
	if srcEnv != dstEnv && !allowCross {
		dec.Allowed = false
		dec.Findings = append(dec.Findings, Finding{Layer: "env", Kind: "deny", Detail: "cross-env relay requires --allow-cross-env"})
	}
	if src.NoDataOut && srcEnv != dstEnv {
		dec.Allowed = false
		dec.Findings = append(dec.Findings, Finding{Layer: "env", Kind: "deny", Detail: "noDataOutflow forbids relay to another env"})
	}
	if !relaySourceOK(src.Relay) {
		dec.Allowed = false
		dec.Findings = append(dec.Findings, Finding{Layer: "capability", Kind: "deny", Detail: "relay source is not allowed"})
	}
	if dst.Relay != string(config.RelayAllow) {
		dec.Allowed = false
		dec.Findings = append(dec.Findings, Finding{Layer: "capability", Kind: "deny", Detail: "relay destination is not allowed"})
	}
	if dec.Allowed && destPath != "" && pathProtected(dst.Protected, destPath) {
		dec.NeedsConfirm = true
		dec.Findings = append(dec.Findings, Finding{Layer: "protected", Kind: "confirm", Detail: "path is protected: " + destPath})
	}
	return dec
}

func relaySourceOK(mode string) bool {
	switch config.RelayMode(mode) {
	case config.RelayAllow, config.RelaySourceOnly:
		return true
	default:
		return false
	}
}

func pathProtected(protected []string, remote string) bool {
	remote = path.Clean(transfer.RestoreRemotePath(remote))
	for _, p := range protected {
		p = path.Clean(p)
		if remote == p || strings.HasPrefix(remote, p+"/") {
			return true
		}
	}
	return false
}
