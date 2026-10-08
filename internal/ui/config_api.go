package ui

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/catalog"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/config"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/sshclient"
)

func (s *service) addEnv(w http.ResponseWriter, r *http.Request) {
	draft, err := envDraftFromRequest(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := catalog.AddEnv(s.dir, draft); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *service) updateEnv(w http.ResponseWriter, r *http.Request) {
	draft, err := envDraftFromRequest(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := catalog.EditEnv(s.dir, draft); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *service) removeEnv(w http.ResponseWriter, r *http.Request) {
	name, err := nameFromRequest(r, "name")
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := catalog.RemoveEnv(s.dir, name); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *service) addGroup(w http.ResponseWriter, r *http.Request) {
	draft, err := groupDraftFromRequest(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := catalog.AddGroup(s.dir, draft); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *service) updateGroup(w http.ResponseWriter, r *http.Request) {
	draft, err := groupDraftFromRequest(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := catalog.EditGroup(s.dir, draft); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *service) removeGroup(w http.ResponseWriter, r *http.Request) {
	name, err := nameFromRequest(r, "name")
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := catalog.RemoveGroup(s.dir, name); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *service) setGroupEnv(w http.ResponseWriter, r *http.Request) {
	raw, err := readObject(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	name, _ := stringField(raw, "name")
	envName, _ := stringField(raw, "env")
	prev, err := catalog.SetGroupEnv(s.dir, name, envName)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	resp := map[string]any{"ok": true}
	if prev == "prod" && envName != "prod" {
		resp["warning"] = "group " + name + " env changed from prod to " + envName
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *service) addPolicy(w http.ResponseWriter, r *http.Request) {
	draft, err := policyDraftFromRequest(r, false)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := catalog.AddPolicy(s.dir, draft); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *service) updatePolicy(w http.ResponseWriter, r *http.Request) {
	draft, err := policyDraftFromRequest(r, true)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := catalog.EditPolicy(s.dir, draft); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *service) removePolicy(w http.ResponseWriter, r *http.Request) {
	name, err := nameFromRequest(r, "name")
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := catalog.RemovePolicy(s.dir, name); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *service) knownHosts(w http.ResponseWriter, r *http.Request) {
	entries, err := sshclient.ListKnownHosts(filepath.Join(s.dir, config.KnownHostsName))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"knownHosts": entries})
}

func (s *service) removeKnownHost(w http.ResponseWriter, r *http.Request) {
	marker, err := nameFromRequest(r, "marker")
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	n, err := sshclient.RemoveKnownHost(filepath.Join(s.dir, config.KnownHostsName), marker)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "removed": n})
}

func envDraftFromRequest(r *http.Request) (catalog.EnvDraft, error) {
	raw, err := readObject(r)
	if err != nil {
		return catalog.EnvDraft{}, err
	}
	var d catalog.EnvDraft
	d.Name, _ = stringField(raw, "name")
	if v, ok := raw["label"]; ok {
		d.HasLabel = true
		_ = json.Unmarshal(v, &d.Label)
	}
	if v, ok := raw["color"]; ok {
		d.HasColor = true
		_ = json.Unmarshal(v, &d.Color)
	}
	if v, ok := raw["maxMode"]; ok {
		d.HasMaxMode = true
		_ = json.Unmarshal(v, &d.MaxMode)
	}
	if v, ok := raw["defaultPolicy"]; ok {
		d.HasDefaultPolicy = true
		_ = json.Unmarshal(v, &d.DefaultPolicy)
	}
	if v, ok := raw["clearDefaultPolicy"]; ok && truthy(v) {
		d.ClearDefaultPolicy = true
	}
	if v, ok := raw["noDataOutflow"]; ok {
		d.HasNoDataOutflow = true
		d.NoDataOutflow = truthy(v)
	}
	return d, nil
}

func groupDraftFromRequest(r *http.Request) (catalog.GroupDraft, error) {
	raw, err := readObject(r)
	if err != nil {
		return catalog.GroupDraft{}, err
	}
	var d catalog.GroupDraft
	d.Name, _ = stringField(raw, "name")
	d.Env, _ = stringField(raw, "env")
	if v, ok := raw["policy"]; ok {
		d.HasPolicy = true
		_ = json.Unmarshal(v, &d.Policy)
	}
	if v, ok := raw["clearPolicy"]; ok && truthy(v) {
		d.ClearPolicy = true
	}
	if v, ok := raw["protectedPaths"]; ok {
		d.HasPaths = true
		paths, err := stringListField(v)
		if err != nil {
			return catalog.GroupDraft{}, err
		}
		d.ProtectedPaths = paths
	}
	return d, nil
}

func policyDraftFromRequest(r *http.Request, replace bool) (catalog.PolicyDraft, error) {
	raw, err := readObject(r)
	if err != nil {
		return catalog.PolicyDraft{}, err
	}
	var d catalog.PolicyDraft
	d.Name, _ = stringField(raw, "name")
	d.Replace = replace
	if v, ok := raw["mode"]; ok {
		d.HasMode = true
		_ = json.Unmarshal(v, &d.Mode)
	}
	if v, ok := raw["allow"]; ok {
		d.HasAllow = true
		items, err := stringListField(v)
		if err != nil {
			return catalog.PolicyDraft{}, err
		}
		d.Allow = items
	}
	if v, ok := raw["allowEmpty"]; ok && truthy(v) {
		d.AllowEmpty = true
	}
	if v, ok := raw["unsetAllow"]; ok && truthy(v) {
		d.UnsetAllow = true
	}
	if v, ok := raw["deny"]; ok {
		d.HasDeny = true
		items, err := stringListField(v)
		if err != nil {
			return catalog.PolicyDraft{}, err
		}
		d.Deny = items
	}
	if v, ok := raw["confirm"]; ok {
		d.HasConfirm = true
		items, err := stringListField(v)
		if err != nil {
			return catalog.PolicyDraft{}, err
		}
		d.Confirm = items
	}
	if v, ok := raw["protectedPaths"]; ok {
		d.HasPaths = true
		items, err := stringListField(v)
		if err != nil {
			return catalog.PolicyDraft{}, err
		}
		d.ProtectedPaths = items
	}
	if v, ok := raw["upload"]; ok {
		b, err := boolPtrField(v)
		if err != nil {
			return catalog.PolicyDraft{}, err
		}
		d.HasUpload = true
		d.Upload = b
	}
	if v, ok := raw["download"]; ok {
		b, err := boolPtrField(v)
		if err != nil {
			return catalog.PolicyDraft{}, err
		}
		d.HasDownload = true
		d.Download = b
	}
	if v, ok := raw["forward"]; ok {
		b, err := boolPtrField(v)
		if err != nil {
			return catalog.PolicyDraft{}, err
		}
		d.HasForward = true
		d.Forward = b
	}
	if v, ok := raw["relay"]; ok {
		d.HasRelay = true
		_ = json.Unmarshal(v, &d.Relay)
	}
	if v, ok := raw["service"]; ok {
		d.HasService = true
		items, err := stringListField(v)
		if err != nil {
			return catalog.PolicyDraft{}, err
		}
		d.Service = items
	}
	if v, ok := raw["serviceEmpty"]; ok && truthy(v) {
		d.ServiceEmpty = true
	}
	return d, nil
}

func nameFromRequest(r *http.Request, key string) (string, error) {
	raw, err := readObject(r)
	if err != nil {
		return "", err
	}
	s, ok := stringField(raw, key)
	if !ok || s == "" {
		return "", fmt.Errorf("%s is required", key)
	}
	return s, nil
}

func readObject(r *http.Request) (map[string]json.RawMessage, error) {
	if r.URL.Query().Has("password") || strings.Contains(r.URL.RawQuery, "password=") {
		return nil, errPasswordQuery
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	ct := r.Header.Get("Content-Type")
	if strings.Contains(ct, "json") || (len(body) > 0 && body[0] == '{') {
		var raw map[string]json.RawMessage
		if err := json.Unmarshal(body, &raw); err != nil {
			return nil, errInvalidJSON
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

func stringField(raw map[string]json.RawMessage, key string) (string, bool) {
	v, ok := raw[key]
	if !ok {
		return "", false
	}
	var s string
	if json.Unmarshal(v, &s) != nil {
		return "", true
	}
	return strings.TrimSpace(s), true
}

func stringListField(v json.RawMessage) ([]string, error) {
	var list []string
	if err := json.Unmarshal(v, &list); err == nil {
		return list, nil
	}
	var s string
	if err := json.Unmarshal(v, &s); err != nil {
		return nil, errInvalidList
	}
	return splitCSV(s), nil
}

func boolPtrField(v json.RawMessage) (*bool, error) {
	var b bool
	if json.Unmarshal(v, &b) == nil {
		return &b, nil
	}
	var s string
	if json.Unmarshal(v, &s) != nil {
		return nil, errInvalidBool
	}
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "on", "yes":
		t := true
		return &t, nil
	case "0", "false", "off", "no":
		f := false
		return &f, nil
	default:
		return nil, errInvalidBool
	}
}

type uiError string

func (e uiError) Error() string { return string(e) }

const (
	errPasswordQuery uiError = "password must be sent in the request body"
	errInvalidJSON   uiError = "invalid JSON body"
	errInvalidList   uiError = "invalid list"
	errInvalidBool   uiError = "invalid boolean"
)
