package transfer

import (
	"fmt"
	"os"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

const maxListEntries = 2000

// FileEntry is one remote name. The list is read-only: it does not create,
// rename, or remove anything.
type FileEntry struct {
	Name  string `json:"name"`
	Path  string `json:"path"`
	Dir   bool   `json:"dir"`
	Link  bool   `json:"link,omitempty"`
	Size  int64  `json:"size"`
	Mode  string `json:"mode"`
	MTime string `json:"mtime"`
}

// Crumb is one breadcrumb segment.
type Crumb struct {
	Name string `json:"name"`
	Path string `json:"path"`
}

// Listing is a directory read.
type Listing struct {
	Path      string      `json:"path"`
	Parent    string      `json:"parent,omitempty"`
	Crumbs    []Crumb     `json:"crumbs"`
	Entries   []FileEntry `json:"entries"`
	Truncated bool        `json:"truncated,omitempty"`
}

// CleanListPath accepts a remote directory. Empty means the login directory.
// NUL and newlines are rejected. ".." segments are cleaned by path.Clean later.
func CleanListPath(p string) (string, error) {
	p = strings.TrimSpace(p)
	if p == "" {
		return ".", nil
	}
	if strings.ContainsRune(p, 0) || strings.ContainsAny(p, "\r\n") {
		return "", fmt.Errorf("invalid path")
	}
	if len(p) > 1024 {
		return "", fmt.Errorf("path is too long")
	}
	return RestoreRemotePath(p), nil
}

// List reads one remote directory over SFTP. It does not follow directory
// symlinks and does not modify the tree.
func List(client *ssh.Client, remote string) (Listing, error) {
	remote, err := CleanListPath(remote)
	if err != nil {
		return Listing{}, err
	}
	sf, err := sftp.NewClient(client)
	if err != nil {
		return Listing{}, err
	}
	defer sf.Close()
	home, err := sf.RealPath(".")
	if err != nil {
		return Listing{}, fmt.Errorf("remote working directory: %w", err)
	}
	target, err := resolveListPath(home, remote)
	if err != nil {
		return Listing{}, err
	}
	info, err := sf.Stat(target)
	if err != nil {
		return Listing{}, err
	}
	if !info.IsDir() {
		return Listing{}, fmt.Errorf("%s is not a directory", target)
	}
	entries, err := sf.ReadDir(target)
	if err != nil {
		return Listing{}, err
	}
	out := make([]FileEntry, 0, len(entries))
	truncated := false
	for _, item := range entries {
		if len(out) == maxListEntries {
			truncated = true
			break
		}
		name := item.Name()
		if name == "." || name == ".." || name == "" || strings.ContainsAny(name, "/\\\x00") {
			continue
		}
		mode := item.Mode()
		full := path.Join(target, name)
		out = append(out, FileEntry{
			Name:  name,
			Path:  full,
			Dir:   mode.IsDir(),
			Link:  mode&os.ModeSymlink != 0,
			Size:  item.Size(),
			Mode:  mode.String(),
			MTime: item.ModTime().UTC().Format(time.RFC3339),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Dir != out[j].Dir {
			return out[i].Dir
		}
		return out[i].Name < out[j].Name
	})
	parent := ""
	if target != "/" && path.Dir(target) != target {
		parent = path.Dir(target)
	}
	return Listing{
		Path: target, Parent: parent, Crumbs: crumbs(target),
		Entries: out, Truncated: truncated,
	}, nil
}

func resolveListPath(home, remote string) (string, error) {
	switch remote {
	case "", ".", "~":
		return path.Clean(home), nil
	}
	if strings.HasPrefix(remote, "~/") {
		remote = path.Join(home, remote[2:])
	}
	return AbsRemote(home, remote)
}

func crumbs(clean string) []Crumb {
	clean = path.Clean(clean)
	if clean == "/" {
		return []Crumb{{Name: "/", Path: "/"}}
	}
	parts := strings.Split(strings.TrimPrefix(clean, "/"), "/")
	out := []Crumb{{Name: "/", Path: "/"}}
	cur := ""
	for _, part := range parts {
		if part == "" {
			continue
		}
		cur = path.Join(cur, part)
		if !strings.HasPrefix(cur, "/") {
			cur = "/" + cur
		}
		out = append(out, Crumb{Name: part, Path: cur})
	}
	return out
}
