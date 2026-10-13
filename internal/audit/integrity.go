package audit

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/config"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/fsutil"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/secrets"
)

const integrityName = "integrity.json"

type verifiedFile struct {
	head     chainHead
	size     int64
	modified time.Time
}

var verified = struct {
	sync.Mutex
	files map[string]verifiedFile
}{files: map[string]verifiedFile{}}

// Only the append fast path uses this metadata cache. Explicit verification
// always reads every byte. This is not a defense against a same-account process
// able to forge both file timestamps and local key material.
func checkAppendChain(path string, want chainHead, tracked bool, key []byte) error {
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) && !tracked {
		return nil
	}
	if err != nil {
		return err
	}
	verified.Lock()
	prior, cached := verified.files[path]
	verified.Unlock()
	if cached && prior.head == want && prior.size == info.Size() && prior.modified.Equal(info.ModTime()) {
		return nil
	}
	got, err := readChain(path, key)
	if err != nil {
		return err
	}
	if got != want {
		return fmt.Errorf("audit integrity mismatch: %s", filepath.Base(path))
	}
	rememberVerified(path, got)
	return nil
}

func rememberVerified(path string, head chainHead) {
	info, err := os.Stat(path)
	if err != nil {
		return
	}
	verified.Lock()
	defer verified.Unlock()
	if len(verified.files) >= 64 {
		clear(verified.files)
	}
	verified.files[path] = verifiedFile{head, info.Size(), info.ModTime()}
}

// The signed manifest anchors a per-day HMAC chain over exact JSONL bytes.
// It detects changes, deletion and truncation against this checkpoint. An
// attacker with the master key, or an old copy of BOTH log and checkpoint, is
// outside this local integrity boundary; export checkpoints to a trusted store.
type chainHead struct {
	Bytes int64  `json:"bytes"`
	Lines int    `json:"lines"`
	Head  string `json:"head"`
}
type integrityState struct {
	Version int                  `json:"version"`
	Files   map[string]chainHead `json:"files"`
	MAC     string               `json:"mac"`
}

func auditSettings(dir string) (*config.AuditSettings, error) {
	cfg, err := config.Load(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return cfg.Audit, nil
}

func chainMAC(key []byte, domain string, data []byte) string {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(domain))
	h.Write([]byte{0})
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}

func loadIntegrity(dir string) (*integrityState, []byte, error) {
	p := filepath.Join(dir, DirName, integrityName)
	raw, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		settings, e := auditSettings(dir)
		if e != nil {
			return nil, nil, e
		}
		if settings != nil && settings.Integrity {
			return nil, nil, fmt.Errorf("audit integrity checkpoint is missing")
		}
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	key, err := secrets.MasterMaterial(dir, false)
	if err != nil {
		return nil, nil, err
	}
	var state integrityState
	if json.Unmarshal(raw, &state) != nil || state.Version != 1 || state.Files == nil {
		return nil, nil, fmt.Errorf("invalid audit integrity checkpoint")
	}
	want := state.MAC
	state.MAC = ""
	body, _ := json.Marshal(state)
	if !hmac.Equal([]byte(want), []byte(chainMAC(key, "ssh-cli-audit-manifest-v1", body))) {
		return nil, nil, fmt.Errorf("audit integrity checkpoint HMAC mismatch")
	}
	state.MAC = want
	return &state, key, nil
}

func saveIntegrity(dir string, state *integrityState, key []byte) error {
	state.MAC = ""
	body, err := json.Marshal(state)
	if err != nil {
		return err
	}
	state.MAC = chainMAC(key, "ssh-cli-audit-manifest-v1", body)
	body, err = json.Marshal(state)
	if err != nil {
		return err
	}
	return fsutil.WriteAtomic(filepath.Join(dir, DirName, integrityName), body, 0o600)
}

func advanceChain(head chainHead, day string, line, key []byte) chainHead {
	head.Head = chainMAC(key, "ssh-cli-audit-line-v1:"+day+":"+head.Head, line)
	head.Bytes += int64(len(line) + 1)
	head.Lines++
	return head
}

func readChain(path string, key []byte) (chainHead, error) {
	f, err := os.Open(path)
	if err != nil {
		return chainHead{}, err
	}
	defer f.Close()
	var head chainHead
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 512<<10)
	for sc.Scan() {
		if _, ok := decodeLine(sc.Text()); !ok {
			return head, fmt.Errorf("invalid audit record in %s", filepath.Base(path))
		}
		head = advanceChain(head, filepath.Base(path), sc.Bytes(), key)
	}
	if err := sc.Err(); err != nil {
		return head, err
	}
	st, err := f.Stat()
	if err != nil {
		return head, err
	}
	if st.Size() != head.Bytes {
		return head, fmt.Errorf("incomplete audit record in %s", filepath.Base(path))
	}
	return head, nil
}

func verifyIntegrity(dir string, state *integrityState, key []byte) error {
	files, err := dataFiles(dir)
	if err != nil {
		return err
	}
	if len(files) != len(state.Files) {
		return fmt.Errorf("audit integrity file set changed")
	}
	for _, path := range files {
		want, ok := state.Files[filepath.Base(path)]
		if !ok {
			return fmt.Errorf("untracked audit file %s", filepath.Base(path))
		}
		got, err := readChain(path, key)
		if err != nil {
			return err
		}
		if got != want {
			return fmt.Errorf("audit integrity mismatch: %s", filepath.Base(path))
		}
	}
	return nil
}

// VerifyIntegrity does not repair, re-sign, or silently accept altered logs.
func VerifyIntegrity(dir string) error {
	return fsutil.WithLock(filepath.Join(dir, DirName), func() error {
		state, key, err := loadIntegrity(dir)
		if err != nil {
			return err
		}
		if state == nil {
			return fmt.Errorf("audit integrity is not enabled; run audit protect")
		}
		return verifyIntegrity(dir, state, key)
	})
}

// Protect snapshots existing logs as a baseline, preserving every original byte.
// Once enabled it refuses to bless a changed baseline on a repeated invocation.
func Protect(dir string) error {
	if err := os.MkdirAll(filepath.Join(dir, DirName), 0o700); err != nil {
		return err
	}
	err := fsutil.WithLock(filepath.Join(dir, DirName), func() error {
		state, key, err := loadIntegrity(dir)
		if err != nil {
			return err
		}
		if state != nil {
			return verifyIntegrity(dir, state, key)
		}
		key, err = secrets.MasterMaterial(dir, true)
		if err != nil {
			return err
		}
		state = &integrityState{Version: 1, Files: map[string]chainHead{}}
		files, err := dataFiles(dir)
		if err != nil {
			return err
		}
		for _, path := range files {
			head, err := readChain(path, key)
			if err != nil {
				return err
			}
			state.Files[filepath.Base(path)] = head
		}
		return saveIntegrity(dir, state, key)
	})
	if err != nil {
		return err
	}
	return config.Update(dir, func(cfg *config.Config) error {
		if cfg.Audit == nil {
			cfg.Audit = &config.AuditSettings{}
		}
		cfg.Audit.Integrity = true
		return nil
	})
}

// Maintain is explicit opt-in; only whole expired days are removed. It runs at
// process start so no persistent background worker or new dependency is needed.
func Maintain(dir string) error {
	settings, err := auditSettings(dir)
	if err != nil {
		return err
	}
	if settings == nil {
		return nil
	}
	if settings.Integrity {
		if err := VerifyIntegrity(dir); err != nil {
			return err
		}
	}
	if settings.RetentionDays == 0 {
		return nil
	}
	now := time.Now()
	cutoff := now.AddDate(0, 0, -settings.RetentionDays)
	// Align to midnight so Cleanup never rewrites a retained chain's boundary day.
	cutoff = time.Date(cutoff.Year(), cutoff.Month(), cutoff.Day(), 0, 0, 0, 0, cutoff.Location())
	result, err := Cleanup(dir, now.Sub(cutoff), now)
	if err != nil {
		return err
	}
	if result.Removed > 0 {
		_, err = Append(dir, Record{Op: OpConfigChange, Status: StatusOK, Reason: fmt.Sprintf("audit retention=%d days; removed=%d records, files=%d; cutoff=%s", settings.RetentionDays, result.Removed, result.FilesDeleted, cutoff.Format(time.RFC3339))})
	}
	return err
}

// Preflight is opt-in fail-closed admission. It proves a record can be persisted
// before dispatch; disk failures that happen later still produce a warning.
func Preflight(dir, source, operation string) error {
	settings, err := auditSettings(dir)
	if err != nil {
		return err
	}
	if settings == nil || !settings.RequireWritable {
		return nil
	}
	_, err = Append(dir, Record{Op: OpPolicyCheck, Source: source, Actor: source, Status: StatusOK, Command: operation, Reason: "audit_preflight"})
	return err
}
