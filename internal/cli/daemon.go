package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/audit"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/config"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/exitcode"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/fsutil"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/guard"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/session"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/sshclient"
	"github.com/spf13/cobra"
)

type daemonRequest struct {
	Readonly bool          `json:"readonly,omitempty"`
	Alias    string        `json:"alias"`
	Command  string        `json:"command"`
	Timeout  time.Duration `json:"timeout"`
}
type daemonReply struct {
	Code         int    `json:"code"`
	Stdout       string `json:"stdout"`
	Stderr       string `json:"stderr"`
	Error        string `json:"error,omitempty"`
	Outcome      string `json:"outcome"`
	Truncated    bool   `json:"truncated"`
	AuditWarning bool   `json:"auditWarning,omitempty"`
}

func daemonPaths(dir string) (string, string) {
	return filepath.Join(dir, "reuse.sock"), filepath.Join(dir, "reuse.token")
}

func (a *App) daemonCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "daemon", Short: "Optional local connection reuse for non-confirming exec calls"}
	var idleExit time.Duration
	serve := &cobra.Command{Use: "serve", Short: "Run the local reuse service in the foreground until interrupted", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt)
		defer stop()
		if idleExit < 0 {
			return fmt.Errorf("idle exit must be non-negative")
		}
		return a.serveDaemonWithIdle(ctx, idleExit)
	}}
	serve.Flags().DurationVar(&idleExit, "idle-exit", 0, "exit after this idle duration (0: keep running)")
	cmd.AddCommand(serve)
	return cmd
}

func (a *App) serveDaemon(ctx context.Context) error { return a.serveDaemonWithIdle(ctx, 0) }
func (a *App) serveDaemonWithIdle(ctx context.Context, idleExit time.Duration) error {
	if err := os.MkdirAll(a.Dir, 0o700); err != nil {
		return err
	}
	sock, tokenPath := daemonPaths(a.Dir)
	var ln net.Listener
	var token string
	err := fsutil.WithLock(a.Dir, func() error {
		// A live socket is never removed; failure other than refusal is also
		// treated conservatively rather than replacing another service.
		if _, err := os.Lstat(sock); err == nil {
			conn, e := net.DialTimeout("unix", sock, time.Second)
			if e == nil {
				conn.Close()
				return fmt.Errorf("reuse daemon is already running")
			}
			return fmt.Errorf("reuse socket already exists; after confirming the old process stopped, remove %s manually", sock)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		var secret [32]byte
		if _, err := rand.Read(secret[:]); err != nil {
			return err
		}
		token = hex.EncodeToString(secret[:])
		var e error
		ln, e = net.Listen("unix", sock)
		if e != nil {
			return fmt.Errorf("local socket unavailable (Windows requires AF_UNIX support): %w", e)
		}
		if e = os.Chmod(sock, 0o600); e != nil {
			ln.Close()
			os.Remove(sock)
			return e
		}
		if e = fsutil.WriteAtomic(tokenPath, []byte(token), 0o600); e != nil {
			ln.Close()
			os.Remove(sock)
			return e
		}
		return nil
	})
	if err != nil {
		return err
	}
	defer func() { ln.Close(); os.Remove(sock); os.Remove(tokenPath) }()
	cfg, err := config.Load(a.Dir)
	if err != nil {
		return err
	}
	idle, life := session.DefaultIdle, session.DefaultMaxLife
	if cfg.Session != nil {
		idle, err = session.ParseWindow(cfg.Session.Idle, idle)
		if err != nil {
			return err
		}
		life, err = session.ParseWindow(cfg.Session.MaxLife, life)
		if err != nil {
			return err
		}
	}
	pool, err := session.New(idle, life, func(ctx context.Context, alias, fingerprint string) (*sshclient.Client, error) {
		cfg, err := config.Load(a.Dir)
		if err != nil {
			return nil, err
		}
		h, ok := cfg.Find(alias)
		if !ok || cfg.SessionFingerprint(h) != fingerprint {
			return nil, fmt.Errorf("host identity changed")
		}
		// Each pool dial owns the request context without mutating shared App state.
		dialer := &App{Dir: a.Dir, Err: a.Err, Insecure: a.Insecure, OperationContext: ctx}
		return dialer.dial(h, 0)
	}, nil)
	if err != nil {
		return err
	}
	defer pool.Shutdown()
	loopCtx, stopLoop := context.WithCancel(ctx)
	defer stopLoop()
	go pool.Loop(loopCtx)
	slots := make(chan struct{}, 4)
	var activityMu sync.Mutex
	lastActivity := time.Now()
	active := 0
	closing := false
	expired := make(chan struct{})
	if idleExit > 0 {
		go func() {
			interval := idleExit / 4
			if interval > time.Second {
				interval = time.Second
			}
			if interval < time.Millisecond {
				interval = time.Millisecond
			}
			tick := time.NewTicker(interval)
			defer tick.Stop()
			for {
				select {
				case <-loopCtx.Done():
					return
				case <-tick.C:
					activityMu.Lock()
					should := active == 0 && time.Since(lastActivity) >= idleExit
					if should {
						closing = true
					}
					activityMu.Unlock()
					if should {
						close(expired)
						return
					}
				}
			}
		}()
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		got := r.Header.Get("Authorization")
		if len(got) != len("Bearer "+token) || subtle.ConstantTimeCompare([]byte(got), []byte("Bearer "+token)) != 1 {
			http.Error(w, "unauthorized", 401)
			return
		}
		if r.Method != "POST" || r.URL.Path != "/exec" {
			http.NotFound(w, r)
			return
		}
		activityMu.Lock()
		if closing {
			activityMu.Unlock()
			http.Error(w, "daemon exiting; command not started", 503)
			return
		}
		active++
		activityMu.Unlock()
		defer func() { activityMu.Lock(); active--; lastActivity = time.Now(); activityMu.Unlock() }()
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		default:
			_ = json.NewEncoder(w).Encode(daemonReply{Error: "reuse service busy; command not started", Outcome: "not_started"})
			return
		}
		var in daemonRequest
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in) != nil || in.Alias == "" || strings.TrimSpace(in.Command) == "" {
			http.Error(w, "invalid request", 400)
			return
		}
		_ = json.NewEncoder(w).Encode(a.daemonExec(r.Context(), pool, in))
	})
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second}
	done := make(chan error, 1)
	go func() { done <- server.Serve(ln) }()
	fmt.Fprintln(a.Err, "Local reuse service ready. CLI exec --daemon uses this service; Ctrl+C closes pooled connections.")
	select {
	case <-expired:
		_ = server.Close()
		pool.Shutdown()
		return nil
	case <-ctx.Done():
		pool.Shutdown()
		_ = server.Close()
		return nil
	case err := <-done:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func (a *App) daemonExec(parent context.Context, pool *session.Pool, in daemonRequest) daemonReply {
	fail := func(err error) daemonReply { return daemonReply{Error: err.Error(), Outcome: "not_started"} }
	cfg, err := config.Load(a.Dir)
	if err != nil {
		return fail(err)
	}
	h, ok := cfg.Find(in.Alias)
	if !ok {
		return fail(fmt.Errorf("unknown host %s", in.Alias))
	}
	eff, err := guard.Resolve(cfg, h, false)
	if err != nil {
		return fail(err)
	}
	dec := guard.Decide(eff, in.Command)
	if in.Readonly && eff.Mode != config.ModeReadonly {
		return fail(fmt.Errorf("automatic reuse requires readonly policy"))
	}
	if !dec.Allowed || dec.NeedsConfirm {
		result := fail(fmt.Errorf("reuse service refuses denied or confirmation-required commands; use direct CLI with a TTY"))
		_, auditErr := audit.Append(a.Dir, audit.Record{Op: audit.OpPolicyCheck, Host: h.Alias, Group: h.Group, Env: h.EnvName, Command: in.Command, Status: audit.StatusDenied, DeniedByPolicy: true, Source: audit.SourceCLI, Reason: "reuse_policy_check"})
		result.AuditWarning = auditErr != nil
		return result
	}
	if err := audit.Preflight(a.Dir, audit.SourceCLI, "daemon exec"); err != nil {
		return fail(err)
	}
	if in.Timeout < 0 || in.Timeout > time.Hour {
		return fail(fmt.Errorf("reuse timeout must be 0..1h"))
	}
	if in.Timeout == 0 {
		in.Timeout = time.Minute
	}
	ctx, cancel := context.WithTimeout(parent, in.Timeout)
	defer cancel()
	fp := cfg.SessionFingerprint(h)
	a.daemonAdmission.Lock()
	want := map[string]string{}
	for alias, h := range cfg.Index() {
		want[alias] = cfg.SessionFingerprint(h)
	}
	pool.Retain(want)
	if _, exists := pool.Client(h.Alias, fp); !exists && len(pool.List()) >= 16 {
		a.daemonAdmission.Unlock()
		return fail(fmt.Errorf("reuse host limit reached (16)"))
	}
	if err := pool.OpenConn(ctx, h.Alias, fp); err != nil {
		a.daemonAdmission.Unlock()
		return fail(err)
	}
	a.daemonAdmission.Unlock()
	start := time.Now()
	out, stderr := &daemonCapture{}, &daemonCapture{}
	res := daemonReply{Outcome: "completed"}
	err = pool.Use(h.Alias, fp, func() error {
		raw, ok := pool.Client(h.Alias, fp)
		if !ok {
			return fmt.Errorf("session closed")
		}
		var stdout, errout io.Writer = out, stderr
		if eff.NoDataOut {
			stdout, errout = io.Discard, io.Discard
		}
		var err error
		res.Code, err = sshclient.RunChannel(ctx, raw, in.Command, stdout, errout, nil)
		return err
	})
	if err != nil {
		res.Error, res.Outcome = err.Error(), "unknown"
	}
	res.Stdout, res.Stderr, res.Truncated = out.String(), stderr.String(), out.cut || stderr.cut
	summary := res.Stdout + res.Stderr
	if eff.NoDataOut {
		summary = guard.OutflowDiscarded
	}
	status, code := statusOf(res.Code, err)
	_, auditErr := audit.Append(a.Dir, audit.Record{Host: h.Alias, Group: h.Group, Env: h.EnvName, Op: audit.OpExec, Source: audit.SourceCLI, Command: in.Command, Status: status, ExitCode: &code, ResultSummary: summary, DurationMS: time.Since(start).Milliseconds(), Reason: "connection_reuse"})
	res.AuditWarning = auditErr != nil
	return res
}

type daemonCapture struct {
	bytes.Buffer
	cut bool
}

func (b *daemonCapture) Write(p []byte) (int, error) {
	n := len(p)
	left := (64 << 10) - b.Len()
	if n > left {
		b.cut = true
		p = p[:left]
	}
	b.Buffer.Write(p)
	return n, nil
}

func (a *App) runViaDaemon(p planned, command string, stdout, stderr io.Writer, timeout time.Duration) (int, error) {
	sock, tokenPath := daemonPaths(a.Dir)
	token, err := os.ReadFile(tokenPath)
	if err != nil {
		return 0, exitcode.New(exitcode.Connect, "reuse daemon unavailable; start ssh-cli daemon serve: %s", err.Error())
	}
	body, err := json.Marshal(daemonRequest{Alias: p.host.Alias, Command: command, Timeout: timeout, Readonly: a.AutoDaemon})
	if err != nil {
		return 0, err
	}
	ctx := context.Background()
	if a.OperationContext != nil {
		ctx = a.OperationContext
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "unix", sock)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: time.Hour + 10*time.Second}
	r, err := http.NewRequestWithContext(ctx, "POST", "http://localhost/exec", bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	r.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
	r.Header.Set("Content-Type", "application/json")
	// Exactly one attempt. No automatic fallback, reconnect or write replay.
	resp, err := client.Do(r)
	if err != nil {
		return 0, exitcode.New(exitcode.Connect, "reuse reply lost; verify remote state before retry: %s", err.Error())
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return 0, exitcode.New(exitcode.Connect, "reuse service rejected request: HTTP %d", resp.StatusCode)
	}
	var result daemonReply
	if json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&result) != nil {
		return 0, exitcode.New(exitcode.Connect, "incomplete reuse result; verify remote state")
	}
	if result.AuditWarning {
		fmt.Fprintln(a.Err, "warning: daemon audit write failed; do not repeat the command")
	}
	if result.Error != "" {
		return 0, exitcode.New(exitcode.Connect, "%s (outcome=%s)", result.Error, result.Outcome)
	}
	if result.Outcome != "completed" {
		return 0, exitcode.New(exitcode.Connect, "reuse result unknown; verify remote state")
	}
	_, _ = io.WriteString(stdout, result.Stdout)
	_, _ = io.WriteString(stderr, result.Stderr)
	if result.Truncated {
		if w, ok := stdout.(*outputLimiter); ok {
			w.cut = true
		}
		if w, ok := stderr.(*outputLimiter); ok {
			w.cut = true
		}
		fmt.Fprintln(a.Err, "warning: reuse output truncated to 64 KiB per stream")
	}
	return result.Code, nil
}
