package cli

import (
	"context"
	"fmt"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/fsutil"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

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
