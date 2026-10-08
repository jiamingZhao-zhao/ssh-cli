package audit

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/fsutil"
)

// Filter selects records. Zero values do not constrain.
// Until is exclusive. Since is inclusive.
type Filter struct {
	Hosts    []string
	Groups   []string
	Env      string
	Status   string
	Since    time.Time
	Until    time.Time
	HasSince bool
	HasUntil bool
}

// List scans JSONL files in chronological order and calls fn for each match.
// Days outside the window are skipped. The first record at or after Until stops the scan.
func List(dir string, f Filter, fn func(Record) error) error {
	files, err := dataFiles(dir)
	if err != nil {
		return err
	}
	for _, path := range files {
		day, ok := fileDay(path)
		if !ok {
			continue
		}
		if f.HasSince && day.Before(dayStart(f.Since)) {
			continue
		}
		if f.HasUntil && day.After(dayStart(f.Until)) {
			break
		}
		stop, err := scanFile(path, -1, func(rec Record) (bool, error) {
			when, ok := matchTime(rec, f)
			if !ok {
				if stopAfterUntil(when, f) {
					return true, nil
				}
				return false, nil
			}
			if !matchFields(rec, f) {
				return false, nil
			}
			if err := fn(rec); err != nil {
				return true, err
			}
			return false, nil
		})
		if err != nil {
			return err
		}
		if stop {
			return nil
		}
	}
	return nil
}

// ListNewest returns up to limit matching records, newest first.
// Once the limit is filled it does not open older files.
func ListNewest(dir string, f Filter, limit int) ([]Record, error) {
	if limit <= 0 {
		limit = 200
	}
	files, err := dataFiles(dir)
	if err != nil {
		return nil, err
	}
	need := limit
	var parts [][]Record
	for i := len(files) - 1; i >= 0 && need > 0; i-- {
		day, ok := fileDay(files[i])
		if !ok {
			continue
		}
		if f.HasUntil && day.After(dayStart(f.Until)) {
			continue
		}
		if f.HasSince && day.Before(dayStart(f.Since)) {
			break
		}
		chunk, err := ringMatch(files[i], f, need)
		if err != nil {
			return nil, err
		}
		if len(chunk) == 0 {
			continue
		}
		parts = append(parts, chunk)
		need -= len(chunk)
	}
	var out []Record
	for i := len(parts) - 1; i >= 0; i-- {
		out = append(out, parts[i]...)
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out, nil
}

// Show finds one record by id and stops at the first match.
func Show(dir, id string) (Record, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return Record{}, fmt.Errorf("empty audit id")
	}
	if hint, ok := idFile(dir, id); ok {
		rec, found, err := findID(hint, id)
		if err != nil || found {
			return rec, err
		}
	}
	files, err := dataFiles(dir)
	if err != nil {
		return Record{}, err
	}
	for _, path := range files {
		rec, found, err := findID(path, id)
		if err != nil {
			return Record{}, err
		}
		if found {
			return rec, nil
		}
	}
	return Record{}, fmt.Errorf("audit id %q not found", id)
}

// Tail calls fn with the last n records. When follow is set it then waits for
// newly appended lines until ctx is cancelled. The follow offset is the file
// size snapshotted under the audit lock before the initial window is read, so
// a line written after that snapshot is delivered exactly once.
func Tail(ctx context.Context, dir string, n int, follow bool, fn func(Record) error) error {
	if n < 0 {
		n = 0
	}
	if ctx == nil {
		ctx = context.Background()
	}
	auditDir := filepath.Join(dir, DirName)
	files, end, err := snapshot(auditDir)
	if err != nil {
		return err
	}
	recs, err := lastN(files, end, n)
	if err != nil {
		return err
	}
	for _, rec := range recs {
		if err := fn(rec); err != nil {
			return err
		}
	}
	if !follow {
		return nil
	}
	var path string
	if len(files) > 0 {
		path = files[len(files)-1]
	}
	return followFrom(ctx, auditDir, path, end, fn)
}

func snapshot(auditDir string) ([]string, int64, error) {
	if err := os.MkdirAll(auditDir, 0o700); err != nil {
		return nil, 0, err
	}
	var files []string
	var end int64
	err := fsutil.WithLock(auditDir, func() error {
		list, err := jsonlFiles(auditDir)
		if err != nil {
			return err
		}
		files = list
		if len(files) == 0 {
			return nil
		}
		fi, err := os.Stat(files[len(files)-1])
		if err != nil {
			return err
		}
		end = fi.Size()
		return nil
	})
	return files, end, err
}

func lastN(files []string, newestSize int64, n int) ([]Record, error) {
	if n == 0 || len(files) == 0 {
		return nil, nil
	}
	need := n
	var parts [][]Record
	for i := len(files) - 1; i >= 0 && need > 0; i-- {
		limit := int64(-1)
		if i == len(files)-1 {
			limit = newestSize
		}
		chunk, err := ringAll(files[i], limit, need)
		if err != nil {
			return nil, err
		}
		if len(chunk) == 0 {
			continue
		}
		parts = append(parts, chunk)
		need -= len(chunk)
	}
	var out []Record
	for i := len(parts) - 1; i >= 0; i-- {
		out = append(out, parts[i]...)
	}
	return out, nil
}

func followFrom(ctx context.Context, auditDir, path string, offset int64, fn func(Record) error) error {
	var pending []byte
	tick := time.NewTicker(200 * time.Millisecond)
	defer tick.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return nil
		}
		path, offset, pending = roll(auditDir, path, offset, pending)
		recs, err := readAppended(path, &offset, &pending)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		for _, rec := range recs {
			if err := fn(rec); err != nil {
				return err
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		}
	}
}

func roll(auditDir, path string, offset int64, pending []byte) (string, int64, []byte) {
	files, err := jsonlFiles(auditDir)
	if err != nil || len(files) == 0 {
		return path, offset, pending
	}
	newest := files[len(files)-1]
	if path == "" || newest > path {
		return newest, 0, nil
	}
	return path, offset, pending
}

func readAppended(path string, offset *int64, pending *[]byte) ([]Record, error) {
	if path == "" {
		return nil, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if _, err := f.Seek(*offset, io.SeekStart); err != nil {
		return nil, err
	}
	buf := make([]byte, 32*1024)
	var recs []Record
	for {
		n, err := f.Read(buf)
		if n > 0 {
			*pending = append(*pending, buf[:n]...)
			*offset += int64(n)
			for {
				i := bytesIndex(*pending, '\n')
				if i < 0 {
					break
				}
				line := string((*pending)[:i])
				*pending = append([]byte(nil), (*pending)[i+1:]...)
				if rec, ok := decodeLine(line); ok {
					recs = append(recs, rec)
				}
			}
			if len(*pending) > 512*1024 {
				*pending = (*pending)[len(*pending)-512*1024:]
			}
		}
		if err == io.EOF {
			return recs, nil
		}
		if err != nil {
			return recs, err
		}
	}
}

func bytesIndex(b []byte, c byte) int {
	for i, x := range b {
		if x == c {
			return i
		}
	}
	return -1
}

func ringAll(path string, limit int64, n int) ([]Record, error) {
	ring := make([]Record, 0, n)
	_, err := scanFile(path, limit, func(rec Record) (bool, error) {
		ring = pushRing(ring, rec, n)
		return false, nil
	})
	return ring, err
}

func ringMatch(path string, f Filter, n int) ([]Record, error) {
	ring := make([]Record, 0, n)
	_, err := scanFile(path, -1, func(rec Record) (bool, error) {
		when, ok := matchTime(rec, f)
		if !ok {
			if stopAfterUntil(when, f) {
				return true, nil
			}
			return false, nil
		}
		if !matchFields(rec, f) {
			return false, nil
		}
		ring = pushRing(ring, rec, n)
		return false, nil
	})
	return ring, err
}

func pushRing(ring []Record, rec Record, n int) []Record {
	if n <= 0 {
		return ring
	}
	if len(ring) < n {
		return append(ring, rec)
	}
	copy(ring, ring[1:])
	ring[n-1] = rec
	return ring
}

func stopAfterUntil(when time.Time, f Filter) bool {
	return f.HasUntil && !when.IsZero() && !when.Before(f.Until)
}

func matchTime(rec Record, f Filter) (time.Time, bool) {
	when, err := ParseStamp(rec.Time)
	if err != nil {
		return time.Time{}, false
	}
	if f.HasSince && when.Before(f.Since) {
		return when, false
	}
	if f.HasUntil && !when.Before(f.Until) {
		return when, false
	}
	return when, true
}

func matchFields(rec Record, f Filter) bool {
	if len(f.Hosts) > 0 && !contains(f.Hosts, rec.Host) {
		return false
	}
	if len(f.Groups) > 0 && !contains(f.Groups, rec.Group) {
		return false
	}
	if f.Env != "" && rec.Env != f.Env {
		return false
	}
	if f.Status != "" && rec.Status != f.Status {
		return false
	}
	return true
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

func findID(path, id string) (Record, bool, error) {
	var found Record
	ok := false
	_, err := scanFile(path, -1, func(rec Record) (bool, error) {
		if rec.ID == id {
			found = rec
			ok = true
			return true, nil
		}
		return false, nil
	})
	return found, ok, err
}

func idFile(dir, id string) (string, bool) {
	if len(id) < 8 || !digits(id[:8]) {
		return "", false
	}
	name := id[0:4] + "-" + id[4:6] + "-" + id[6:8] + ".jsonl"
	path := filepath.Join(dir, DirName, name)
	if _, err := os.Stat(path); err != nil {
		return "", false
	}
	return path, true
}

func digits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// scanFile reads complete JSON lines. limit < 0 reads the whole file.
// The callback's true return stops the scan.
func scanFile(path string, limit int64, fn func(Record) (bool, error)) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	defer f.Close()
	var r io.Reader = f
	if limit >= 0 {
		r = io.LimitReader(f, limit)
	}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 512*1024)
	for sc.Scan() {
		rec, ok := decodeLine(sc.Text())
		if !ok {
			continue
		}
		stop, err := fn(rec)
		if err != nil || stop {
			return stop, err
		}
	}
	if err := sc.Err(); err != nil {
		if strings.Contains(err.Error(), "token too long") {
			return false, nil
		}
		return false, err
	}
	return false, nil
}

func decodeLine(line string) (Record, bool) {
	line = strings.TrimSpace(line)
	if line == "" || line[0] != '{' {
		return Record{}, false
	}
	var rec Record
	if err := json.Unmarshal([]byte(line), &rec); err != nil {
		return Record{}, false
	}
	if rec.ID == "" || rec.Time == "" {
		return Record{}, false
	}
	return rec, true
}

func dataFiles(configDir string) ([]string, error) {
	return jsonlFiles(filepath.Join(configDir, DirName))
}

func jsonlFiles(auditDir string) ([]string, error) {
	entries, err := os.ReadDir(auditDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var files []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".jsonl") {
			continue
		}
		if _, ok := fileDay(name); !ok {
			continue
		}
		files = append(files, filepath.Join(auditDir, name))
	}
	sort.Strings(files)
	return files, nil
}

func fileDay(path string) (time.Time, bool) {
	base := strings.TrimSuffix(filepath.Base(path), ".jsonl")
	t, err := time.ParseInLocation("2006-01-02", base, time.Local)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

func dayStart(t time.Time) time.Time {
	t = t.In(time.Local)
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.Local)
}
