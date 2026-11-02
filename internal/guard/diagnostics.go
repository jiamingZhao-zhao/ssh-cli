package guard

import (
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

func ipQueryFlag(s string) bool {
	switch s {
	case "-br", "-brief", "-o", "-oneline", "-4", "-6", "-j", "-json", "-p", "-pretty":
		return true
	}
	return false
}

// Positive grammars are intentional. Reject unknown interpreter/network flags
// rather than trying to enumerate every way those tools can write or execute.
func diagnosticDeny(name string, args []Arg) string {
	switch name {
	case "env", "printenv":
		return "readonly refuses environment dumps; use a specific non-secret query"
	case "curl", "wget", "jps", "java", "diff", "sha256sum", "md5sum", "zcat", "zgrep", "zless", "sed", "awk", "docker", "ping", "nc", "lsof":
	default:
		return ""
	}
	v := make([]string, len(args))
	for i, a := range args {
		if !a.Static {
			return name + " query arguments must be static literals"
		}
		v[i] = a.Value
	}
	ok := false
	switch name {
	case "curl":
		ok = loopbackHEAD(v)
	case "wget":
		ok = loopbackWgetHEAD(v)
	case "jps":
		ok = true
		for _, s := range v[1:] {
			if len(s) < 2 || !strings.HasPrefix(s, "-") || strings.Trim(s[1:], "ql") != "" {
				ok = false // -m/-v/-J can expose secrets or alter JVM execution.
			}
		}
	case "java":
		ok = len(v) == 2 && (v[1] == "-version" || v[1] == "--version")
	case "sed":
		ok = sedQuery(v)
	case "awk":
		ok = awkQuery(v)
	case "docker":
		return dockerQuery(v)
	case "ping":
		ok = boundedPing(v)
	case "nc":
		ok = boundedNC(v)
	case "diff":
		ok = fileQuery(v[1:], "uUbBwiqrsNy", map[string]bool{"--brief": true, "--unified": true, "--recursive": true}, 2)
	case "sha256sum", "md5sum":
		ok = fileQuery(v[1:], "btc", map[string]bool{"--binary": true, "--text": true, "--check": true, "--status": true, "--quiet": true}, -1)
	case "zcat":
		ok = fileQuery(v[1:], "fq", map[string]bool{"--force": true, "--quiet": true}, -1)
	case "zless":
		// Avoid invoking an interactive pager in an unattended diagnostic.
		return "readonly diagnostics use zcat/zgrep instead of an interactive zless pager"
	case "zgrep":
		ok = fileQuery(v[1:], "EFivnchHwxab", map[string]bool{}, -1)
	case "lsof":
		ok = true
		for _, s := range v[1:] {
			if s != "-n" && s != "-P" && s != "-nP" && s != "-Pn" && s != "-i" && !regexp.MustCompile(`^-i(TCP|UDP)?(:[0-9]{1,5})?$`).MatchString(s) && !regexp.MustCompile(`^-p[0-9]+$`).MatchString(s) {
				ok = false
			}
		}
	}
	if !ok {
		return name + " options are outside the supported readonly query form; see diagnostics help"
	}
	return ""
}

func fileQuery(args []string, short string, long map[string]bool, operands int) bool {
	end := false
	n := 0
	for _, s := range args {
		if !end && s == "--" {
			end = true
			continue
		}
		if !end && strings.HasPrefix(s, "-") && s != "-" {
			if long[s] {
				continue
			}
			if strings.HasPrefix(s, "--") || strings.Trim(s[1:], short) != "" {
				return false
			}
			continue
		}
		n++
	}
	return operands < 0 || n == operands
}

var sedSlice = regexp.MustCompile(`^([0-9]+|\$)(,([0-9]+|\$))?p$`)
var sedRegexPrint = regexp.MustCompile(`^/(?:[^/\\\r\n]|\\.)+/p$`)
var awkPrint = regexp.MustCompile(`^(?:/(?:[^/\\\r\n]|\\.)+/[ \t]*)?\{[ \t]*print[ \t]+(\$[0-9]+|NF|NR)([ \t]*,[ \t]*(\$[0-9]+|NF|NR))*[ \t]*\}$`)

func sedQuery(v []string) bool {
	// Start with the high-frequency slice form; -e/-f and e/r/w commands can
	// execute programs or access extra files even without -i.
	return len(v) >= 3 && v[1] == "-n" && (sedSlice.MatchString(v[2]) || sedRegexPrint.MatchString(v[2])) && fileQuery(v[3:], "", map[string]bool{}, -1)
}

func awkQuery(v []string) bool {
	i := 1
	if len(v) > 2 && v[i] == "-F" {
		i += 2
	} else if len(v) > 1 && strings.HasPrefix(v[i], "-F") && len(v[i]) > 2 {
		i++
	}
	if i >= len(v) || !awkPrint.MatchString(v[i]) {
		return false
	}
	for _, s := range v[i+1:] {
		// awk treats NAME=value operands as assignments even after --.
		if strings.Contains(s, "=") || strings.HasPrefix(s, "-") && s != "-" {
			return false
		}
	}
	return true
}

func loopbackHEAD(v []string) bool {
	if len(v) < 3 || (v[1] != "-q" && v[1] != "--disable") {
		return false // Disable ~/.curlrc before any other option.
	}
	head, proxy, bounded := false, false, false
	urls := 0
	for i := 2; i < len(v); i++ {
		s := v[i]
		switch s {
		case "-I", "--head":
			head = true
		case "-s", "-S", "-sS", "--silent", "--show-error":
		case "-sI", "-Is", "-sSI":
			head = true
		case "--noproxy":
			i++
			if i >= len(v) || v[i] != "*" {
				return false
			}
			proxy = true
		case "-m", "--max-time", "--connect-timeout":
			i++
			if i >= len(v) {
				return false
			}
			n, e := strconv.ParseFloat(v[i], 64)
			if e != nil || !(n > 0 && n <= 30) {
				return false
			}
			if s != "--connect-timeout" {
				bounded = true
			}
		case "-o", "--output":
			i++
			if i >= len(v) || v[i] != "/dev/null" {
				return false
			}
		default:
			if strings.HasPrefix(s, "-") {
				return false
			}
			u, e := url.Parse(s)
			if e != nil || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.Fragment != "" || u.RawQuery != "" {
				return false
			}
			h := u.Hostname()
			// A hosts file or DNS can map localhost elsewhere. Literal addresses
			// keep the actual destination inside the requested network boundary.
			if h != "127.0.0.1" && h != "::1" {
				return false
			}
			// curl URL glob expansion can issue many requests despite one URL.
			if strings.ContainsAny(u.EscapedPath(), "{}[]") {
				return false
			}
			if port := u.Port(); port != "" {
				n, e := strconv.Atoi(port)
				if e != nil || n < 1 || n > 65535 {
					return false
				}
			}
			urls++
		}
	}
	// HEAD still invokes an application endpoint: this is bounded probing,
	// not a promise that a poorly designed HTTP application has no side effects.
	return head && proxy && bounded && urls == 1
}

// Wget reads startup files and may persist HSTS metadata by default. Permit
// only a fully explicit GNU Wget HEAD form that disables those behaviours,
// proxies, redirects and retries. It is intentionally not a general wget rule.
func loopbackWgetHEAD(v []string) bool {
	if len(v) < 2 || v[1] != "--no-config" {
		return false
	}
	required := map[string]bool{"--no-proxy": false, "--no-netrc": false, "--no-hsts": false, "--no-cookies": false, "--method=HEAD": false, "--max-redirect=0": false, "--tries=1": false, "--output-document=/dev/null": false}
	timeout := false
	urls := 0
	for _, arg := range v[2:] {
		if _, ok := required[arg]; ok {
			required[arg] = true
			continue
		}
		if arg == "--quiet" || arg == "-q" || arg == "--server-response" || arg == "-S" {
			continue
		}
		if strings.HasPrefix(arg, "--timeout=") {
			n, e := strconv.Atoi(strings.TrimPrefix(arg, "--timeout="))
			if e != nil || n < 1 || n > 30 {
				return false
			}
			timeout = true
			continue
		}
		if strings.HasPrefix(arg, "-") {
			return false
		}
		u, e := url.Parse(arg)
		if e != nil || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.Fragment != "" || u.RawQuery != "" || (u.Hostname() != "127.0.0.1" && u.Hostname() != "::1") || strings.ContainsAny(u.EscapedPath(), "{}[]") {
			return false
		}
		if port := u.Port(); port != "" {
			n, e := strconv.Atoi(port)
			if e != nil || n < 1 || n > 65535 {
				return false
			}
		}
		urls++
	}
	for _, present := range required {
		if !present {
			return false
		}
	}
	return timeout && urls == 1
}

func boundedPing(v []string) bool {
	count, host := false, false
	for i := 1; i < len(v); i++ {
		switch v[i] {
		case "-n", "-4", "-6":
		case "-c", "-W":
			flag := v[i]
			i++
			if i >= len(v) {
				return false
			}
			n, e := strconv.Atoi(v[i])
			if e != nil || n < 1 || n > 5 {
				return false
			}
			if flag == "-c" {
				count = true
			}
		default:
			if host || !diagnosticHost(v[i]) {
				return false
			}
			host = true
		}
	}
	return count && host
}

func boundedNC(v []string) bool {
	zero, wait := false, false
	var operands []string
	for i := 1; i < len(v); i++ {
		switch v[i] {
		case "-z", "-vz", "-zv":
			zero = true
		case "-n", "-v":
		case "-w":
			i++
			if i >= len(v) {
				return false
			}
			n, e := strconv.Atoi(v[i])
			if e != nil || n < 1 || n > 5 {
				return false
			}
			wait = true
		default:
			if strings.HasPrefix(v[i], "-") {
				return false
			}
			operands = append(operands, v[i])
		}
	}
	if len(operands) != 2 || !diagnosticHost(operands[0]) {
		return false
	}
	p, e := strconv.Atoi(operands[1])
	return zero && wait && e == nil && p > 0 && p <= 65535
}

var queryHost = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]*$`)

func diagnosticHost(v string) bool { return net.ParseIP(v) != nil || queryHost.MatchString(v) }

var inspectFormats = map[string]bool{
	"{{json .NetworkSettings.Networks}}": true, "{{json .Mounts}}": true,
	"{{json .NetworkSettings.Ports}}": true, "{{json .HostConfig.PortBindings}}": true,
	"{{.NetworkSettings.IPAddress}}": true, "{{.State.Status}}": true,
	"{{.State.Running}}": true, "{{.State.Restarting}}": true,
	"{{.State.ExitCode}}": true, "{{.State.StartedAt}}": true,
	"{{.Config.Image}}": true, "{{.Id}}": true, "{{.Name}}": true,
}

func dockerQuery(v []string) string {
	if len(v) < 2 || strings.HasPrefix(v[1], "-") {
		return "readonly docker queries use the local default daemon without global overrides"
	}
	if v[1] == "logs" {
		for _, s := range v[2:] {
			if strings.HasPrefix(s, "--follow") || strings.HasPrefix(s, "-") && !strings.HasPrefix(s, "--") && strings.Contains(s, "f") {
				return "readonly diagnostics refuse docker logs follow; use --tail"
			}
		}
	}
	if v[1] == "stats" {
		// A later --no-stream=false overrides the allow-list prefix and would
		// otherwise start an unbounded streaming command.
		for _, s := range v[2:] {
			if strings.HasPrefix(s, "--no-stream=") && s != "--no-stream=true" {
				return "readonly diagnostics refuse streaming docker stats"
			}
		}
	}
	if v[1] == "inspect" {
		i := 2
		if i >= len(v) {
			return "docker inspect requires a selected non-secret --format"
		}
		format := ""
		if v[i] == "--format" || v[i] == "-f" {
			i++
			if i < len(v) {
				format = v[i]
				i++
			}
		} else if strings.HasPrefix(v[i], "--format=") {
			format = strings.TrimPrefix(v[i], "--format=")
			i++
		}
		if !inspectFormats[format] || i >= len(v) {
			return "docker inspect requires a selected non-secret --format (network, mounts, status, image or id)"
		}
		for _, s := range v[i:] {
			if s == "" || strings.HasPrefix(s, "-") {
				return "docker inspect accepts literal object names only"
			}
		}
	}
	if v[1] == "compose" {
		if len(v) < 3 || v[2] != "ps" || !fileQuery(v[3:], "aq", map[string]bool{"--all": true, "--quiet": true}, -1) {
			return "readonly docker compose supports ps without project/config overrides"
		}
	}
	return ""
}
