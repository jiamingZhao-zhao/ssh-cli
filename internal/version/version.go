// Package version is the ssh-cli build identity.
package version

// Version is overridden with -ldflags at release time.
var Version = "0.1.0-dev"

// String is the user-facing version line.
func String() string { return "ssh-cli " + Version }
