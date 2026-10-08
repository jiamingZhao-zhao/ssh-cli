// Package version is the ssh-cli build identity.
//
// Release builds override the variables with -ldflags:
//
//	-X github.com/jiamingZhao-zhao/ssh-cli/internal/version.Version=<semver>
//	-X github.com/jiamingZhao-zhao/ssh-cli/internal/version.Commit=<sha>
//	-X github.com/jiamingZhao-zhao/ssh-cli/internal/version.Date=<rfc3339>
//
// Local builds keep Version "dev" and leave Commit and Date empty.
package version

import "strings"

// Version, Commit, and Date are overridden with -ldflags at release time.
var (
	Version = "dev"
	Commit  = ""
	Date    = ""
)

// String is the single user-facing version line.
// version, --version, -V, and -version all print it.
func String() string {
	s := "ssh-cli " + Version
	if Commit == "" && Date == "" {
		return s
	}
	commit := Commit
	if commit == "" {
		commit = "unknown"
	}
	if Date == "" {
		return s + " (" + commit + ")"
	}
	return s + " (" + commit + ", " + Date + ")"
}

// Info is the JSON form of the build identity.
func Info() map[string]string {
	return map[string]string{
		"name":    "ssh-cli",
		"version": Version,
		"commit":  Commit,
		"date":    Date,
		"line":    String(),
	}
}

// ReleaseVersion strips one leading v so asset names and comparisons share a form.
func ReleaseVersion(tag string) string {
	tag = strings.TrimSpace(tag)
	if strings.HasPrefix(tag, "v") || strings.HasPrefix(tag, "V") {
		return tag[1:]
	}
	return tag
}
