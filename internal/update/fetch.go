package update

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/exitcode"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/version"
)

// ReleaseBase is the GitHub site used to resolve /releases/latest and to
// download /releases/download/<tag>/ assets. Tests point it at an httptest server.
// Anonymous updates use this origin and do not call the REST API.
var ReleaseBase = "https://github.com"

// APIBase is the GitHub API origin. It is used only when GITHUB_TOKEN is set
// and the direct release lookup failed. Tests may point it at an httptest server.
var APIBase = "https://api.github.com"

// DefaultRepo is used when SSH_CLI_REPO and --repo are empty.
const DefaultRepo = "jiamingZhao-zhao/ssh-cli"

const noChecksumWarning = "release has no checksums.txt; the asset will not be verified"

var (
	repoPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)
	tagPattern  = regexp.MustCompile(`^[A-Za-z0-9._+-]+$`)
	canonHref   = regexp.MustCompile(`(?i)rel=["']canonical["'][^>]*href=["']([^"']+)["']|href=["']([^"']+)["'][^>]*rel=["']canonical["']`)
)

type release struct {
	tag     string
	version string
	// prefix is set for the direct download path:
	// <ReleaseBase>/<repo>/releases/download/<tag>
	// Asset names are known, so the release listing API is not required.
	// An empty prefix means assets came from the optional API fallback.
	prefix string
	assets []asset
}

func fetchRelease(ctx context.Context, client *http.Client, repo string) (*release, error) {
	if !repoPattern.MatchString(repo) {
		return nil, exitcode.New(exitcode.Usage, "invalid repo %q (want owner/name)", repo)
	}
	rel, err := fetchReleaseDirect(ctx, client, repo)
	if err == nil {
		return rel, nil
	}
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		return nil, err
	}
	apiRel, apiErr := fetchReleaseAPI(ctx, client, repo, token)
	if apiErr != nil {
		return nil, err
	}
	return apiRel, nil
}

func fetchReleaseDirect(ctx context.Context, client *http.Client, repo string) (*release, error) {
	raw := strings.TrimRight(ReleaseBase, "/") + "/" + repo + "/releases/latest"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return nil, exitcode.New(exitcode.Usage, "bad release URL")
	}
	req.Header.Set("Accept", "text/html")
	req.Header.Set("User-Agent", userAgent())
	resp, err := clientNoRedirect(client).Do(req)
	if err != nil {
		return nil, exitcode.New(exitcode.Connect, "fetch %s: %s", raw, err.Error())
	}
	defer resp.Body.Close()

	switch {
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		loc, locErr := resp.Location()
		if locErr != nil || loc == nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
			return nil, exitcode.New(exitcode.Usage, "release lookup returned a redirect without a tag")
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return releaseFromTag(repo, tagFromURL(loc))
	case resp.StatusCode == http.StatusOK:
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		if readErr != nil {
			return nil, exitcode.New(exitcode.Connect, "read %s: %s", raw, readErr.Error())
		}
		if tag := tagFromURL(resp.Request.URL); tag != "" && tagPattern.MatchString(tag) {
			return releaseFromTag(repo, tag)
		}
		if tag := tagFromHTML(body); tag != "" {
			return releaseFromTag(repo, tag)
		}
		return nil, exitcode.New(exitcode.Usage, "release page did not include a tag")
	case resp.StatusCode == http.StatusNotFound:
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return nil, exitcode.New(exitcode.Usage, "no published release (%s)", raw)
	default:
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return nil, statusErr("release lookup", resp.StatusCode)
	}
}

func fetchReleaseAPI(ctx context.Context, client *http.Client, repo, token string) (*release, error) {
	raw := strings.TrimRight(APIBase, "/") + "/repos/" + repo + "/releases/latest"
	body, err := httpGetToken(ctx, client, raw, token)
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
	if !tagPattern.MatchString(doc.TagName) {
		return nil, exitcode.New(exitcode.Usage, "invalid release tag %q", doc.TagName)
	}
	rel := &release{tag: doc.TagName, version: version.ReleaseVersion(doc.TagName)}
	if rel.version == "" || !tagPattern.MatchString(rel.version) {
		return nil, exitcode.New(exitcode.Usage, "invalid release tag %q", doc.TagName)
	}
	for _, a := range doc.Assets {
		rel.assets = append(rel.assets, asset{name: a.Name, url: a.URL})
	}
	return rel, nil
}

func releaseFromTag(repo, tag string) (*release, error) {
	if tag == "" || !tagPattern.MatchString(tag) {
		return nil, exitcode.New(exitcode.Usage, "invalid release tag %q", tag)
	}
	ver := version.ReleaseVersion(tag)
	if ver == "" || !tagPattern.MatchString(ver) {
		return nil, exitcode.New(exitcode.Usage, "invalid release tag %q", tag)
	}
	prefix := strings.TrimRight(ReleaseBase, "/") + "/" + repo + "/releases/download/" + tag
	return &release{tag: tag, version: ver, prefix: prefix}, nil
}

func (r *release) asset(name string) (asset, error) {
	if r.prefix != "" {
		return asset{name: name, url: r.prefix + "/" + name}, nil
	}
	for _, a := range r.assets {
		if a.name == name {
			if a.url == "" {
				return asset{}, errUsage("asset %s has no download URL", name)
			}
			return a, nil
		}
	}
	return asset{}, errUsage("no release asset %s", name)
}

// checksums reports the manifest URL.
// listed is true when the API response included checksums.txt.
// Direct downloads always have a URL; a 404 there means the file was not published.
func (r *release) checksums() (a asset, listed bool) {
	if r.prefix != "" {
		return asset{name: ChecksumsName, url: r.prefix + "/" + ChecksumsName}, false
	}
	a, ok := findAsset(r.assets, ChecksumsName)
	return a, ok
}

func tagFromURL(u *url.URL) string {
	if u == nil {
		return ""
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	for i := 0; i+2 < len(parts); i++ {
		if parts[i] == "releases" && parts[i+1] == "tag" {
			return parts[i+2]
		}
	}
	return ""
}

func tagFromHTML(body []byte) string {
	if m := canonHref.FindSubmatch(body); m != nil {
		raw := string(m[1])
		if raw == "" {
			raw = string(m[2])
		}
		if u, err := url.Parse(raw); err == nil {
			if tag := tagFromURL(u); tag != "" {
				return tag
			}
		}
	}
	return ""
}

func clientNoRedirect(base *http.Client) *http.Client {
	c := &http.Client{Timeout: 60 * time.Second}
	if base != nil {
		clone := *base
		c = &clone
		if c.Timeout == 0 {
			c.Timeout = 60 * time.Second
		}
	}
	// Stop before following /releases/latest so the Location header still
	// carries /releases/tag/<tag>. Download requests use the caller's client
	// and may follow the asset CDN redirect.
	c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return c
}

func userAgent() string {
	return "ssh-cli/" + version.Version
}

func httpGet(ctx context.Context, client *http.Client, rawURL string) ([]byte, error) {
	return httpGetToken(ctx, client, rawURL, "")
}

func httpGetToken(ctx context.Context, client *http.Client, rawURL, token string) ([]byte, error) {
	body, _, err := httpGetStatus(ctx, client, rawURL, token)
	return body, err
}

// httpGetOptional returns missing=true on HTTP 404 without an error.
func httpGetOptional(ctx context.Context, client *http.Client, rawURL string) ([]byte, bool, error) {
	body, status, err := httpGetStatus(ctx, client, rawURL, "")
	if status == http.StatusNotFound {
		return nil, true, nil
	}
	return body, false, err
}

func httpGetStatus(ctx context.Context, client *http.Client, rawURL, token string) ([]byte, int, error) {
	if client == nil {
		client = &http.Client{Timeout: 60 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, 0, exitcode.New(exitcode.Usage, "bad release URL")
	}
	req.Header.Set("User-Agent", userAgent())
	if token != "" {
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, exitcode.New(exitcode.Connect, "fetch %s: %s", rawURL, err.Error())
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxArchive+1))
	if err != nil {
		return nil, resp.StatusCode, exitcode.New(exitcode.Connect, "read %s: %s", rawURL, err.Error())
	}
	if len(body) > maxArchive {
		return nil, resp.StatusCode, exitcode.New(exitcode.Usage, "response from %s exceeds %d bytes", rawURL, maxArchive)
	}
	if resp.StatusCode == http.StatusNotFound {
		kind := "release download"
		if token != "" {
			kind = "release API"
		}
		return nil, resp.StatusCode, exitcode.New(exitcode.Usage, "no published release (%s returned %d via %s)", rawURL, resp.StatusCode, kind)
	}
	if resp.StatusCode != http.StatusOK {
		kind := "release download"
		if token != "" {
			kind = "release API"
		}
		return nil, resp.StatusCode, statusErr(kind, resp.StatusCode)
	}
	return body, resp.StatusCode, nil
}

func statusErr(kind string, code int) error {
	if code >= 500 || code == http.StatusForbidden || code == http.StatusTooManyRequests {
		return exitcode.New(exitcode.Connect, "%s returned %d", kind, code)
	}
	return exitcode.New(exitcode.Usage, "%s returned %d", kind, code)
}

func errUsage(format string, args ...any) error {
	return exitcode.New(exitcode.Usage, format, args...)
}
