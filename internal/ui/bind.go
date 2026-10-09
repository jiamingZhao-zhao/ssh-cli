package ui

import (
	"fmt"
	"net"
	"strings"
)

// CheckBind accepts loopback addresses. Empty host, wildcards, and other
// addresses are refused unless allowNonLoopback is set.
func CheckBind(addr string, allowNonLoopback bool) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid listen address %q", addr)
	}
	if port == "" {
		return fmt.Errorf("invalid listen address %q", addr)
	}
	if loopbackHost(host) {
		return nil
	}
	if allowNonLoopback {
		return nil
	}
	return fmt.Errorf("refusing to bind %s: the UI listens on 127.0.0.1 only; pass --allow-non-loopback to override (prints a one-time bearer token, not for public networks)", addr)
}

// WarnNonLoopback reports whether addr is not a loopback bind.
// Invalid addresses are not treated as a non-loopback warning.
func WarnNonLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	return !loopbackHost(host)
}

func loopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
