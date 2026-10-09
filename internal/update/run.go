package update

import (
	"context"
	"net/http"
	"os"
	"path/filepath"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/exitcode"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/version"
)

// CurrentBinary locates the executable update replaces. Tests override it.
var CurrentBinary = os.Executable

// Options controls one opt-in update. Run is the only entry point; nothing updates in the background.
type Options struct {
	Repo    string
	Current string
	GOOS    string
	GOARCH  string
	Check   bool
	Force   bool
	Client  *http.Client
	// ExePath replaces CurrentBinary when set (tests).
	ExePath string
	// Confirm runs after a release is chosen and before any download.
	// Check-only and already-current runs do not call it.
	// A nil Confirm allows the install (tests). The CLI passes a TTY check.
	Confirm func(latest string) error
	// AllowMissingChecksum installs when checksums.txt is absent.
	// The default refuses that install.
	AllowMissingChecksum bool
}

// Result is the outcome of a check or install.
type Result struct {
	Current          string `json:"current"`
	Latest           string `json:"latest"`
	Asset            string `json:"asset,omitempty"`
	UpdateAvailable  bool   `json:"updateAvailable"`
	Ahead            bool   `json:"ahead"`
	Installed        bool   `json:"installed"`
	ChecksumVerified bool   `json:"checksumVerified"`
	Warning          string `json:"warning,omitempty"`
	Restart          bool   `json:"restart,omitempty"`
}

// Run looks up the latest GitHub release and, unless Check is set, replaces the current executable.
// force installs even when the current version is not older. A missing checksums.txt
// refuses the install unless AllowMissingChecksum is set. A present checksum that
// does not match is an error. Check-only still reports the missing file as Warning.
func Run(ctx context.Context, opt Options) (Result, error) {
	if opt.Current == "" {
		opt.Current = version.Version
	}
	repo := opt.Repo
	if repo == "" {
		repo = DefaultRepo
	}
	rel, err := fetchRelease(ctx, opt.Client, repo)
	if err != nil {
		return Result{}, err
	}
	selected, err := rel.asset(AssetName(rel.version, opt.GOOS, opt.GOARCH))
	if err != nil {
		return Result{}, err
	}
	available, ahead, err := relation(opt.Current, rel.version)
	if err != nil {
		return Result{}, err
	}
	res := Result{
		Current:         opt.Current,
		Latest:          rel.version,
		Asset:           selected.name,
		UpdateAvailable: available,
		Ahead:           ahead,
	}
	sums, sumsListed := rel.checksums()
	trySums := sumsListed || rel.prefix != ""
	if !trySums {
		res.Warning = noChecksumWarning
	}
	if opt.Check || (!available && !opt.Force) {
		return res, nil
	}
	if !trySums && !opt.AllowMissingChecksum {
		return res, errUsage("refusing to install without checksums.txt")
	}
	if opt.Confirm != nil {
		if err := opt.Confirm(rel.version); err != nil {
			return res, err
		}
	}
	body, err := httpGet(ctx, opt.Client, selected.url)
	if err != nil {
		return res, err
	}
	if trySums {
		sumBody, missing, err := httpGetOptional(ctx, opt.Client, sums.url)
		if err != nil {
			return res, err
		}
		if missing {
			if sumsListed || !opt.AllowMissingChecksum {
				return res, errUsage("refusing to install without checksums.txt")
			}
			res.Warning = noChecksumWarning
		} else {
			parsed, err := ParseChecksums(sumBody)
			if err != nil {
				return res, err
			}
			if err := verifyChecksum(selected.name, body, parsed); err != nil {
				return res, err
			}
			res.ChecksumVerified = true
			res.Warning = ""
		}
	}
	bin, err := extractBinary(selected.name, opt.GOOS, body)
	if err != nil {
		return res, err
	}
	dest, err := locateBinary(opt.ExePath)
	if err != nil {
		return res, err
	}
	if err := ReplaceBinary(dest, bin); err != nil {
		return res, exitcode.New(exitcode.Usage, "replace %s: %s", dest, err.Error())
	}
	res.Installed = true
	res.Restart = true
	return res, nil
}

func relation(current, latest string) (available, ahead bool, err error) {
	cmp, err := compareSemver(current, latest)
	if err != nil {
		return false, false, err
	}
	return cmp < 0, cmp > 0, nil
}

func locateBinary(explicit string) (string, error) {
	path := explicit
	var err error
	if path == "" {
		path, err = CurrentBinary()
		if err != nil {
			return "", exitcode.New(exitcode.Usage, "locate executable: %s", err.Error())
		}
	}
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		path = resolved
	}
	return path, nil
}
