package ui

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

func readRaw(r *http.Request) (map[string]json.RawMessage, error) {
	if r.URL.Query().Has("password") || strings.Contains(r.URL.RawQuery, "password=") {
		return nil, fmt.Errorf("password must be sent in the request body")
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	ct := r.Header.Get("Content-Type")
	if strings.Contains(ct, "json") || (len(body) > 0 && body[0] == '{') {
		var raw map[string]json.RawMessage
		if err := json.Unmarshal(body, &raw); err != nil {
			return nil, fmt.Errorf("invalid JSON body")
		}
		if raw == nil {
			raw = map[string]json.RawMessage{}
		}
		return raw, nil
	}
	r.Body = io.NopCloser(strings.NewReader(string(body)))
	if err := r.ParseForm(); err != nil {
		return nil, err
	}
	raw := map[string]json.RawMessage{}
	for k, vals := range r.PostForm {
		if len(vals) == 0 {
			continue
		}
		b, err := json.Marshal(vals[0])
		if err != nil {
			return nil, err
		}
		raw[k] = b
	}
	return raw, nil
}

func rawString(raw map[string]json.RawMessage, key string) (string, bool, error) {
	v, ok := raw[key]
	if !ok {
		return "", false, nil
	}
	var s string
	if err := json.Unmarshal(v, &s); err != nil {
		return "", true, fmt.Errorf("invalid %s", key)
	}
	return s, true, nil
}

// rawList reports whether key was present. A JSON null or blank string yields
// a nil slice (unset). A JSON array, including an empty one, yields a non-nil
// slice.
func rawList(raw map[string]json.RawMessage, key string) (bool, *[]string, error) {
	v, ok := raw[key]
	if !ok {
		return false, nil, nil
	}
	if len(v) == 0 || string(v) == "null" {
		return true, nil, nil
	}
	var items []string
	if err := json.Unmarshal(v, &items); err == nil {
		cleaned := cleanLines(items)
		return true, &cleaned, nil
	}
	var s string
	if err := json.Unmarshal(v, &s); err != nil {
		return true, nil, fmt.Errorf("invalid %s", key)
	}
	if strings.TrimSpace(s) == "" {
		return true, nil, nil
	}
	cleaned := cleanLines([]string{s})
	return true, &cleaned, nil
}

func cleanLines(items []string) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, item := range items {
		for _, line := range strings.Split(item, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || seen[line] {
				continue
			}
			seen[line] = true
			out = append(out, line)
		}
	}
	return out
}

func cloneListPtr(in *[]string) *[]string {
	if in == nil {
		return nil
	}
	cp := append([]string(nil), (*in)...)
	return &cp
}

func groupFromMap(raw map[string]json.RawMessage) (GroupDraft, error) {
	var d GroupDraft
	name, _, err := rawString(raw, "name")
	if err != nil {
		return GroupDraft{}, err
	}
	d.Name = name
	if s, ok, err := rawString(raw, "env"); err != nil {
		return GroupDraft{}, err
	} else if ok {
		d.HasEnv = true
		d.Env = s
	}
	if s, ok, err := rawString(raw, "policy"); err != nil {
		return GroupDraft{}, err
	} else if ok {
		d.HasPolicy = true
		d.Policy = s
	}
	if err := fillRuleFields(raw, &d.Allow, &d.Deny, &d.Confirm, &d.HasAllow, &d.HasDeny, &d.HasConfirm); err != nil {
		return GroupDraft{}, err
	}
	if ok, list, err := rawList(raw, "protectedPaths"); err != nil {
		return GroupDraft{}, err
	} else if ok {
		d.HasProtected = true
		if list != nil {
			d.Protected = *list
		}
	}
	return d, nil
}

func policyFromMap(raw map[string]json.RawMessage) (PolicyDraft, error) {
	var d PolicyDraft
	name, _, err := rawString(raw, "name")
	if err != nil {
		return PolicyDraft{}, err
	}
	d.Name = name
	if s, ok, err := rawString(raw, "mode"); err != nil {
		return PolicyDraft{}, err
	} else if ok {
		d.HasMode = true
		d.Mode = s
	}
	if err := fillRuleFields(raw, &d.Allow, &d.Deny, &d.Confirm, &d.HasAllow, &d.HasDeny, &d.HasConfirm); err != nil {
		return PolicyDraft{}, err
	}
	return d, nil
}

func envFromMap(raw map[string]json.RawMessage) (EnvDraft, error) {
	var d EnvDraft
	name, _, err := rawString(raw, "name")
	if err != nil {
		return EnvDraft{}, err
	}
	d.Name = name
	if s, ok, err := rawString(raw, "label"); err != nil {
		return EnvDraft{}, err
	} else if ok {
		d.HasLabel = true
		d.Label = s
	}
	if s, ok, err := rawString(raw, "color"); err != nil {
		return EnvDraft{}, err
	} else if ok {
		d.HasColor = true
		d.Color = s
	}
	if s, ok, err := rawString(raw, "maxMode"); err != nil {
		return EnvDraft{}, err
	} else if ok {
		d.HasMaxMode = true
		d.MaxMode = s
	}
	if s, ok, err := rawString(raw, "defaultPolicy"); err != nil {
		return EnvDraft{}, err
	} else if ok {
		d.HasDefaultPolicy = true
		d.DefaultPolicy = s
	}
	if v, ok := raw["noDataOutflow"]; ok {
		d.HasNoDataOutflow = true
		d.NoDataOutflow = truthy(v)
	}
	return d, nil
}

func tagEditFromMap(raw map[string]json.RawMessage) (string, []string, []string, error) {
	group, ok, err := rawString(raw, "group")
	if err != nil {
		return "", nil, nil, err
	}
	if !ok {
		group, _, err = rawString(raw, "name")
		if err != nil {
			return "", nil, nil, err
		}
	}
	_, add, err := rawList(raw, "add")
	if err != nil {
		return "", nil, nil, err
	}
	_, remove, err := rawList(raw, "remove")
	if err != nil {
		return "", nil, nil, err
	}
	var addItems, removeItems []string
	if add != nil {
		addItems = *add
	}
	if remove != nil {
		removeItems = *remove
	}
	return group, addItems, removeItems, nil
}

func fillRuleFields(raw map[string]json.RawMessage, allow **[]string, deny, confirm *[]string, hasAllow, hasDeny, hasConfirm *bool) error {
	if ok, list, err := rawList(raw, "allow"); err != nil {
		return err
	} else if ok {
		*hasAllow = true
		*allow = list
	}
	if ok, list, err := rawList(raw, "deny"); err != nil {
		return err
	} else if ok {
		*hasDeny = true
		if list != nil {
			*deny = *list
		}
	}
	if ok, list, err := rawList(raw, "confirm"); err != nil {
		return err
	} else if ok {
		*hasConfirm = true
		if list != nil {
			*confirm = *list
		}
	}
	return nil
}

func nameFromMap(raw map[string]json.RawMessage) (string, error) {
	name, _, err := rawString(raw, "name")
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(name) == "" {
		name, _, err = rawString(raw, "alias")
		if err != nil {
			return "", err
		}
	}
	return name, nil
}
