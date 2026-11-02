package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/fsutil"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// A daemon from an older installed build may enforce an older readonly policy.
// Only implicitly reuse a process built from exactly the same binary.
func executableDigest() (string, error) {
	path, err := os.Executable()
	if err != nil {
		return "", err
	}
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (a *App) verifyAutoReuseCapabilities() error {
	sock, tokenPath := daemonPaths(a.Dir)
	token, err := os.ReadFile(tokenPath)
	if err != nil {
		return err
	}
	digest, err := executableDigest()
	if err != nil {
		return err
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "unix", sock)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
	req, err := http.NewRequest("GET", "http://localhost/capabilities", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var info struct {
		Protocol   string `json:"protocol"`
		Executable string `json:"executableSha256"`
	}
	if resp.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&info) != nil || info.Protocol != "bounded-exec-v1" || info.Executable != digest {
		return fmt.Errorf("existing daemon is incompatible or from a different binary; stop it or use --direct")
	}
	return nil
}

func (a *App) stopReuseDaemon(ctx context.Context) error {
	sock, tokenPath := daemonPaths(a.Dir)
	token, err := os.ReadFile(tokenPath)
	if os.IsNotExist(err) {
		if _, sockErr := os.Lstat(sock); os.IsNotExist(sockErr) {
			fmt.Fprintln(a.Out, "reuse daemon is not running")
			return nil
		}
		return fmt.Errorf("reuse socket exists but daemon token is missing; verify the process before cleanup")
	}
	if err != nil {
		return err
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "unix", sock)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	req, err := http.NewRequestWithContext(ctx, "POST", "http://localhost/stop", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("cannot contact reuse daemon; verify it is running: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusConflict {
		return fmt.Errorf("reuse daemon is busy; wait for running commands to finish and retry")
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("reuse daemon refused stop (HTTP %d); an older daemon may not support this command", resp.StatusCode)
	}
	var reply struct {
		Stopping bool `json:"stopping"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&reply); err != nil || !reply.Stopping {
		return fmt.Errorf("reuse daemon stop reply was incomplete; check its state")
	}
	timer := time.NewTimer(3 * time.Second)
	defer timer.Stop()
	tick := time.NewTicker(25 * time.Millisecond)
	defer tick.Stop()
	for {
		if _, err := os.Lstat(sock); os.IsNotExist(err) {
			fmt.Fprintln(a.Out, "reuse daemon stopped")
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			return fmt.Errorf("stop accepted but socket remains; check daemon state")
		case <-tick.C:
		}
	}
}

func (a *App) ensureAutoDaemon() error {
	// Serialize starters separately: the child takes the normal config lock.
	lockDir := filepath.Join(a.Dir, "reuse-start")
	if err := os.MkdirAll(lockDir, 0700); err != nil {
		return err
	}
	return fsutil.WithLock(lockDir, func() error {
		sock, token := daemonPaths(a.Dir)
		ready := func() bool {
			b, e := os.ReadFile(token)
			if e != nil || len(b) != 64 {
				return false
			}
			c, e := net.DialTimeout("unix", sock, 100*time.Millisecond)
			if e != nil {
				return false
			}
			c.Close()
			return true
		}
		if ready() {
			return nil
		}
		if _, e := os.Lstat(sock); e == nil {
			return fmt.Errorf("reuse socket exists but is unavailable; verify old daemon stopped before removing it")
		}
		exe, e := os.Executable()
		if e != nil {
			return e
		}
		sink, e := os.OpenFile(os.DevNull, os.O_RDWR, 0)
		if e != nil {
			return e
		}
		defer sink.Close()
		child := exec.Command(exe, "--config", a.Dir, "daemon", "serve", "--idle-exit", "180s")
		child.Stdin = sink
		child.Stdout = sink
		child.Stderr = sink
		detachDaemon(child)
		if e = child.Start(); e != nil {
			return e
		}
		go child.Wait()
		ctx := a.OperationContext
		if ctx == nil {
			ctx = context.Background()
		}
		timer := time.NewTimer(5 * time.Second)
		defer timer.Stop()
		tick := time.NewTicker(25 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-timer.C:
				return fmt.Errorf("auto daemon did not become ready; no command was sent")
			case <-tick.C:
				if ready() {
					return nil
				}
			}
		}
	})
}
