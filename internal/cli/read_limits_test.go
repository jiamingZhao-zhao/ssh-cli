package cli

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/exitcode"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/history"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/remote"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/transfer"
)

func TestStructuredReadLimitsPreserveRecords(t *testing.T) {
	files := []transfer.FileEntry{{Name: "资料", Path: "/资料"}, {Name: strings.Repeat("x", 200), Path: "/long"}, {Name: "ok", Path: "/ok"}}
	got, cut := limitRecords(files, 100, 1000)
	if !cut || len(got) != 2 || got[0].Name != "资料" || got[1].Name != "ok" {
		t.Fatalf("files %#v truncated=%v", got, cut)
	}
	raw, _ := json.Marshal(got)
	if !utf8.Valid(raw) {
		t.Fatal("invalid UTF-8")
	}
	entries := []history.Line{{Command: "echo 你好"}, {Command: strings.Repeat("x", 200)}}
	selected, cut := limitRecords(entries, 80, 1000)
	if !cut || len(selected) != 1 || selected[0].Command != entries[0].Command {
		t.Fatalf("history %+v", selected)
	}
	keys := []remote.AuthorizedKey{{Fingerprint: "SHA256:a"}, {Fingerprint: "SHA256:b"}}
	first, _ := json.Marshal(keys[0])
	selectedKeys, cut := limitRecords(keys, 0, len(first))
	if !cut || len(selectedKeys) != 1 || selectedKeys[0].Fingerprint != "SHA256:a" {
		t.Fatalf("keys %+v", selectedKeys)
	}
	unlimited, cut := limitRecords(files, 0, 0)
	if cut || len(unlimited) != len(files) {
		t.Fatal("zero limits should be unlimited")
	}
}

func TestGuidanceDistinguishesFailures(t *testing.T) {
	cases := []struct {
		code          int
		message, kind string
	}{
		{exitcode.HostKey, "changed host key", "host_key_changed"},
		{exitcode.Auth, "authentication failed", "authentication_failed"},
		{exitcode.Connect, "jump hop failed", "jump_route_failed"},
		{exitcode.Connect, "deadline exceeded", "timeout"},
		{exitcode.Connect, "no such host", "name_resolution_failed"},
		{exitcode.Connect, "connection refused", "network_unreachable"},
		{exitcode.Connect, "response lost", "connection_or_execution_unknown"},
	}
	for _, tc := range cases {
		if got := errorGuidance(tc.code, tc.message); got.Kind != tc.kind || got.NextAction == "" {
			t.Errorf("%s => %+v", tc.message, got)
		}
	}
}
