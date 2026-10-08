package update

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/exitcode"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/version"
)

// APIBase is the GitHub API origin. Tests point it at an httptest server.
var APIBase = "https://api.github.com"

// DefaultRepo is used when SSH_CLI_REPO and --repo are empty.
const DefaultRepo = "jiamingZhao-zhao/ssh-cli"

const noChecksumWarning = "release has no checksums.txt; the asset will not be verified"

var repoPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)

type release struct {
	tag     string
	version string
	assets  []asset
}

func fetchRelease(ctx context.Context, client *http.Client, repo string) (*release, error) {
	if !repoPattern.MatchString(repo) {
		return nil, exitcode.New(exitcode.Usage, "invalid repo %q (want owner/name)", repo)
	}
	body, err := httpGet(ctx, client, strings.TrimRight(APIBase, "/")+"/repos/"+repo+"/releases/latest")
	if err != nil {
		return nil, err
	}
	var doc struct {
		TagName string `json:"tag_name"`
		Assets  []struct {
			Name string `json:"name"`
			URL  string `json:"browser_download_url"`
		} `json:"assets"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, exitcode.New(exitcode.Usage, "invalid release JSON")
	}
	if doc.TagName == "" {
		return nil, exitcode.New(exitcode.Usage, "release has no tag_name")
	}
	rel := &release{tag: doc.TagName, version: version.ReleaseVersion(doc.TagName)}
	for _, a := range doc.Assets {
		rel.assets = append(rel.assets, asset{name: a.Name, url: a.URL})
	}
	return rel, nil
}

func httpGet(ctx context.Context, client *http.Client, rawURL string) ([]byte, error) {
	if client == nil {
		client = &http.Client{Timeout: 60 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, exitcode.New(exitcode.Usage, "bad release URL")
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "ssh-cli/"+version.Version)
	resp, err := client.Do(req)
	if err != nil {
		return nil, exitcode.New(exitcode.Connect, "fetch %s: %s", rawURL, err.Error())
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxArchive+1))
	if err != nil {
		return nil, exitcode.New(exitcode.Connect, "read %s: %s", rawURL, err.Error())
	}
	if len(body) > maxArchive {
		return nil, exitcode.New(exitcode.Usage, "response from %s exceeds %d bytes", rawURL, maxArchive)
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil, exitcode.New(exitcode.Usage, "no published release (%s)", rawURL)
	}
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode >= 500 || resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
			return nil, exitcode.New(exitcode.Connect, "release API returned %d", resp.StatusCode)
		}
		return nil, exitcode.New(exitcode.Usage, "release API returned %d", resp.StatusCode)
	}
	return body, nil
}

func errUsage(format string, args ...any) error {
	return exitcode.New(exitcode.Usage, format, args...)
}
