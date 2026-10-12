package ui

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// errPickCancelled means the operator closed the folder dialog without choosing.
var errPickCancelled = errors.New("cancelled")

// chooseDownloadDir opens a native directory dialog and returns a cleaned absolute path.
// Tests replace it so the UI handler does not pop a dialog.
var chooseDownloadDir = chooseDownloadDirOS

func (s *service) pickDownloadDirAPI(w http.ResponseWriter, r *http.Request) {
	dir, err := chooseDownloadDir(r.Context())
	if errors.Is(err, errPickCancelled) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "cancelled": true})
		return
	}
	if err != nil {
		writeFail(w, err)
		return
	}
	cleaned, err := cleanPickedDir(dir)
	if err != nil {
		writeFail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "path": cleaned})
}

func chooseDownloadDirOS(ctx context.Context) (string, error) {
	switch runtime.GOOS {
	case "windows":
		script := `Add-Type -AssemblyName System.Windows.Forms; $d = New-Object System.Windows.Forms.FolderBrowserDialog; $d.Description = '选择下载保存目录'; $d.ShowNewFolderButton = $true; if ($d.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { Write-Output $d.SelectedPath }`
		return runDirPicker(ctx, "powershell", "-NoProfile", "-STA", "-Command", script)
	case "darwin":
		return runDirPicker(ctx, "osascript", "-e", `POSIX path of (choose folder with prompt "选择下载保存目录")`)
	default:
		if path, err := exec.LookPath("zenity"); err == nil {
			return runDirPicker(ctx, path, "--file-selection", "--directory", "--title=选择下载保存目录")
		}
		if path, err := exec.LookPath("kdialog"); err == nil {
			return runDirPicker(ctx, path, "--getexistingdirectory", ".", "--title", "选择下载保存目录")
		}
		return "", fmt.Errorf("没有可用的目录选择器，请安装 zenity 或 kdialog")
	}
}

func runDirPicker(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	out := strings.TrimSpace(stdout.String())
	if err != nil {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		if out == "" {
			return "", errPickCancelled
		}
		return "", fmt.Errorf("选择目录失败")
	}
	if out == "" {
		return "", errPickCancelled
	}
	return cleanPickedDir(out)
}

// revealSpec is a local file or its folder, opened in the system file manager.
type revealSpec struct {
	path string
	dir  string
	file bool
}

// openLocal shows a finished download in Explorer, Finder, or the desktop file manager.
// Tests replace it so the handler does not launch a GUI.
var openLocal = openLocalOS

func (s *service) revealDownloadAPI(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Path string `json:"path"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
		writeFail(w, err)
		return
	}
	spec, err := revealTarget(body.Path)
	if err != nil {
		writeFail(w, err)
		return
	}
	if err := openLocal(r.Context(), spec); err != nil {
		writeFail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "path": spec.dir})
}

func revealTarget(raw string) (revealSpec, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return revealSpec{}, fmt.Errorf("没有可打开的路径")
	}
	cleaned := filepath.Clean(raw)
	if !filepath.IsAbs(cleaned) {
		return revealSpec{}, fmt.Errorf("路径不是绝对路径")
	}
	st, err := os.Stat(cleaned)
	if err != nil {
		return revealSpec{}, fmt.Errorf("找不到这个文件")
	}
	if st.IsDir() {
		return revealSpec{path: cleaned, dir: cleaned}, nil
	}
	return revealSpec{path: cleaned, dir: filepath.Dir(cleaned), file: true}, nil
}

func openLocalOS(ctx context.Context, spec revealSpec) error {
	switch runtime.GOOS {
	case "windows":
		arg := spec.path
		if spec.file {
			arg = "/select," + spec.path
		}
		return exec.CommandContext(ctx, "explorer", arg).Start()
	case "darwin":
		if spec.file {
			return exec.CommandContext(ctx, "open", "-R", spec.path).Start()
		}
		return exec.CommandContext(ctx, "open", spec.path).Start()
	default:
		if path, err := exec.LookPath("xdg-open"); err == nil {
			return exec.CommandContext(ctx, path, spec.dir).Start()
		}
		return fmt.Errorf("没有可用的文件管理器")
	}
}

func cleanPickedDir(dir string) (string, error) {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return "", errPickCancelled
	}
	dir = filepath.Clean(dir)
	if !filepath.IsAbs(dir) {
		return "", fmt.Errorf("选择的目录不是绝对路径")
	}
	st, err := os.Stat(dir)
	if err != nil {
		return "", fmt.Errorf("打不开所选目录")
	}
	if !st.IsDir() {
		return "", fmt.Errorf("所选位置不是目录")
	}
	return dir, nil
}
