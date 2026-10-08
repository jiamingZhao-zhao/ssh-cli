package update

import (
	"strconv"
	"strings"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/version"
)

type semver struct {
	major, minor, patch int
	pre                 []string
}

// compareSemver reports how current relates to latest.
// It returns -1 when current is older, 0 when equal, and 1 when newer.
// A non-semver current build such as "dev" is older than any valid release.
func compareSemver(current, latest string) (int, error) {
	rel, ok := parseSemver(version.ReleaseVersion(latest))
	if !ok {
		return 0, errUsage("latest version %q is not semver", latest)
	}
	cur, ok := parseSemver(version.ReleaseVersion(current))
	if !ok {
		return -1, nil
	}
	return cur.cmp(rel), nil
}

func parseSemver(s string) (semver, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return semver{}, false
	}
	if i := strings.IndexByte(s, '+'); i >= 0 {
		s = s[:i]
	}
	var pre string
	if i := strings.IndexByte(s, '-'); i >= 0 {
		pre = s[i+1:]
		s = s[:i]
		if pre == "" {
			return semver{}, false
		}
	}
	parts := strings.Split(s, ".")
	if len(parts) == 0 || len(parts) > 3 {
		return semver{}, false
	}
	nums := [3]int{}
	for i, p := range parts {
		if !plainNumber(p) {
			return semver{}, false
		}
		n, err := strconv.Atoi(p)
		if err != nil {
			return semver{}, false
		}
		nums[i] = n
	}
	var ids []string
	if pre != "" {
		ids = strings.Split(pre, ".")
		for _, id := range ids {
			if id == "" || !validID(id) {
				return semver{}, false
			}
		}
	}
	return semver{major: nums[0], minor: nums[1], patch: nums[2], pre: ids}, true
}

func plainNumber(s string) bool {
	if s == "" {
		return false
	}
	if len(s) > 1 && s[0] == '0' {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func validID(s string) bool {
	numeric := true
	for _, c := range s {
		switch {
		case c >= '0' && c <= '9':
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c == '-':
			numeric = false
		default:
			return false
		}
	}
	if numeric && len(s) > 1 && s[0] == '0' {
		return false
	}
	return true
}

func (s semver) cmp(o semver) int {
	if c := cmpInt(s.major, o.major); c != 0 {
		return c
	}
	if c := cmpInt(s.minor, o.minor); c != 0 {
		return c
	}
	if c := cmpInt(s.patch, o.patch); c != 0 {
		return c
	}
	return cmpPre(s.pre, o.pre)
}

func cmpPre(a, b []string) int {
	switch {
	case len(a) == 0 && len(b) == 0:
		return 0
	case len(a) == 0:
		return 1
	case len(b) == 0:
		return -1
	}
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		if c := cmpID(a[i], b[i]); c != 0 {
			return c
		}
	}
	return cmpInt(len(a), len(b))
}

func cmpID(a, b string) int {
	ai, aErr := strconv.Atoi(a)
	bi, bErr := strconv.Atoi(b)
	aNum := aErr == nil && plainNumber(a)
	bNum := bErr == nil && plainNumber(b)
	switch {
	case aNum && bNum:
		return cmpInt(ai, bi)
	case aNum:
		return -1
	case bNum:
		return 1
	}
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}

func cmpInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}
