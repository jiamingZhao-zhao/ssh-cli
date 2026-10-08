package ui

import (
	"net/http"
	"path/filepath"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/catalog"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/config"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/sshclient"
)

func (s *service) setGroupEnv(w http.ResponseWriter, r *http.Request) {
	raw, err := readRaw(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	name, err := nameFromMap(raw)
	if err != nil || name == "" {
		writeErr(w, http.StatusBadRequest, "name is required")
		return
	}
	envName, ok, err := rawString(raw, "env")
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if !ok || envName == "" {
		writeErr(w, http.StatusBadRequest, "env is required")
		return
	}
	if _, err := catalog.SetGroupEnv(s.dir, name, envName); err != nil {
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
	raw, err := readRaw(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	marker, ok, err := rawString(raw, "marker")
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if !ok || marker == "" {
		writeErr(w, http.StatusBadRequest, "marker is required")
		return
	}
	n, err := sshclient.RemoveKnownHost(filepath.Join(s.dir, config.KnownHostsName), marker)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "removed": n})
}
