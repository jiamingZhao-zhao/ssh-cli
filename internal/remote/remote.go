// Package remote builds the fixed commands used by status, service, and keys.
// The commands go through the same policy check as exec. Nothing here dials SSH.
package remote

import (
	"fmt"
	"regexp"
	"strings"

	"golang.org/x/crypto/ssh"
)

// Probe is one read-only status command.
type Probe struct {
	Name    string `json:"name"`
	Command string `json:"command"`
}

// StatusProbes are the fixed health checks. Each command is on the built-in
// readonly allow-list (cat, uptime, free, df, ss).
func StatusProbes() []Probe {
	return []Probe{
		{Name: "hostname", Command: "cat /etc/hostname"},
		{Name: "uptime", Command: "uptime"},
		{Name: "load", Command: "cat /proc/loadavg"},
		{Name: "memory", Command: "free"},
		{Name: "disk", Command: "df -h"},
		{Name: "listen", Command: "ss -lnt"},
	}
}

// StatusCommand is the audit string for a full status pass.
func StatusCommand() string {
	probes := StatusProbes()
	parts := make([]string, len(probes))
	for i, p := range probes {
		parts[i] = p.Command
	}
	return strings.Join(parts, "; ")
}

var serviceNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9@._+-]{0,127}$`)

var serviceActions = map[string]bool{
	"status":  true,
	"start":   true,
	"stop":    true,
	"restart": true,
	"reload":  true,
}

// ServiceCommand returns systemctl <action> <name> after checking the action
// whitelist and the service-name pattern. The name is not passed to a shell.
func ServiceCommand(action, name string) (string, error) {
	action = strings.TrimSpace(action)
	name = strings.TrimSpace(name)
	if !serviceActions[action] {
		return "", fmt.Errorf("service action must be status, start, stop, restart, or reload")
	}
	if !serviceNameRe.MatchString(name) {
		return "", fmt.Errorf("invalid service name %q", name)
	}
	return "systemctl " + action + " " + name, nil
}

// ValidateRemotePath accepts a single literal remote path with no shell syntax.
func ValidateRemotePath(p string) (string, error) {
	p = strings.TrimSpace(p)
	if p == "" {
		return "", fmt.Errorf("empty path")
	}
	if len(p) > 512 {
		return "", fmt.Errorf("path is too long")
	}
	if strings.ContainsAny(p, " \t\r\n'\"\\$;|&<>*?(){}[]`") {
		return "", fmt.Errorf("path %q contains characters that are not allowed", p)
	}
	if strings.HasPrefix(p, "-") {
		return "", fmt.Errorf("path must not start with '-'")
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." {
			return "", fmt.Errorf("path must not contain ..")
		}
	}
	return p, nil
}

// CatCommand reads a remote file. The path must already be validated.
func CatCommand(path string) string { return "cat -- " + path }

// ListCommand asks for a long listing so the caller can read an mtime.
// The path must already be validated. ls is on the readonly allow-list.
func ListCommand(path string) string { return "ls -l --time-style=long-iso -- " + path }

var mtimeRe = regexp.MustCompile(`\d{4}-\d{2}-\d{2} \d{2}:\d{2}`)

// ParseListMTime returns the first GNU long-iso timestamp in ls output.
func ParseListMTime(s string) string { return mtimeRe.FindString(s) }

// AuthorizedKey is one public key from an authorized_keys file.
type AuthorizedKey struct {
	Line        int    `json:"line"`
	Type        string `json:"type"`
	Fingerprint string `json:"fingerprint"`
	Comment     string `json:"comment,omitempty"`
}

// ParseAuthorizedKeys parses authorized_keys text. Blank lines and comments are
// skipped. Malformed lines are returned as warnings; valid keys are kept.
func ParseAuthorizedKeys(data []byte) ([]AuthorizedKey, []string) {
	var keys []AuthorizedKey
	var warnings []string
	lineNo := 0
	for _, line := range strings.Split(string(data), "\n") {
		lineNo++
		trim := strings.TrimSpace(line)
		if trim == "" || strings.HasPrefix(trim, "#") {
			continue
		}
		pub, comment, _, _, err := ssh.ParseAuthorizedKey([]byte(trim))
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("line %d: %s", lineNo, err.Error()))
			continue
		}
		keys = append(keys, AuthorizedKey{
			Line:        lineNo,
			Type:        pub.Type(),
			Fingerprint: ssh.FingerprintSHA256(pub),
			Comment:     comment,
		})
	}
	if keys == nil {
		keys = []AuthorizedKey{}
	}
	return keys, warnings
}
