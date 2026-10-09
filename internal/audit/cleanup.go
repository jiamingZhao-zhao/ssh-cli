package audit

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/fsutil"
)

// MinAge is the youngest entry Cleanup will delete. Shorter windows are refused.
const MinAge = 30 * 24 * time.Hour

// CleanupResult reports a streaming delete of entries older than the cutoff.
type CleanupResult struct {
	Cutoff       time.Time `json:"cutoff"`
	Removed      int       `json:"removed"`
	Kept         int       `json:"kept"`
	FilesDeleted int       `json:"filesDeleted"`
	BytesFreed   int64     `json:"bytesFreed"`
}

// Cleanup deletes audit entries strictly older than now-minAge.
// minAge must be at least 30 days. Whole day files whose last instant is at
// or before the cutoff are removed. The boundary day is streamed to a temp file.
func Cleanup(dir string, minAge time.Duration, now time.Time) (CleanupResult, error) {
	if minAge < MinAge {
		return CleanupResult{}, fmt.Errorf("refusing to delete audit entries newer than 30 days")
	}
	if now.IsZero() {
		now = time.Now()
	}
	cutoff := now.Add(-minAge)
	auditDir := filepath.Join(dir, DirName)
	var result CleanupResult
	result.Cutoff = cutoff
	err := fsutil.WithLock(auditDir, func() error {
		if err := os.MkdirAll(auditDir, 0o700); err != nil {
			return err
		}
		files, err := jsonlFiles(auditDir)
		if err != nil {
			return err
		}
		for _, path := range files {
			day, ok := fileDay(path)
			if !ok {
				continue
			}
			info, err := os.Stat(path)
			if err != nil {
				return err
			}
			dayEnd := day.Add(24 * time.Hour)
			if !dayEnd.After(cutoff) {
				removed, err := countLines(path)
				if err != nil {
					return err
				}
				if err := os.Remove(path); err != nil {
					return err
				}
				result.Removed += removed
				result.FilesDeleted++
				result.BytesFreed += info.Size()
				continue
			}
			if !day.Before(cutoff) {
				n, err := countLines(path)
				if err != nil {
					return err
				}
				result.Kept += n
				continue
			}
			removed, kept, freed, err := rewriteOlder(path, cutoff, info.Size())
			if err != nil {
				return err
			}
			result.Removed += removed
			result.Kept += kept
			result.BytesFreed += freed
		}
		return nil
	})
	return result, err
}

func countLines(path string) (int, error) {
	n := 0
	_, err := scanFile(path, -1, func(Record) (bool, error) {
		n++
		return false, nil
	})
	return n, err
}

func rewriteOlder(path string, cutoff time.Time, before int64) (removed, kept int, freed int64, err error) {
	in, err := os.Open(path)
	if err != nil {
		return 0, 0, 0, err
	}
	defer in.Close()
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".audit-rewrite-*")
	if err != nil {
		return 0, 0, 0, err
	}
	tmpName := tmp.Name()
	defer func() {
		if tmpName != "" {
			_ = os.Remove(tmpName)
		}
	}()
	w := bufio.NewWriter(tmp)
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 64*1024), 512*1024)
	for sc.Scan() {
		line := sc.Text()
		rec, ok := decodeLine(line)
		if !ok {
			continue
		}
		when, perr := ParseStamp(rec.Time)
		if perr != nil || when.Before(cutoff) {
			removed++
			continue
		}
		if _, err := w.WriteString(line); err != nil {
			_ = tmp.Close()
			return 0, 0, 0, err
		}
		if err := w.WriteByte('\n'); err != nil {
			_ = tmp.Close()
			return 0, 0, 0, err
		}
		kept++
	}
	if err := sc.Err(); err != nil {
		_ = tmp.Close()
		return 0, 0, 0, err
	}
	if err := w.Flush(); err != nil {
		_ = tmp.Close()
		return 0, 0, 0, err
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return 0, 0, 0, err
	}
	if err := tmp.Close(); err != nil {
		return 0, 0, 0, err
	}
	if kept == 0 {
		if err := os.Remove(path); err != nil {
			return 0, 0, 0, err
		}
		_ = os.Remove(tmpName)
		tmpName = ""
		return removed, 0, before, nil
	}
	if err := fsutil.Replace(tmpName, path); err != nil {
		return 0, 0, 0, err
	}
	tmpName = ""
	info, err := os.Stat(path)
	if err != nil {
		return removed, kept, 0, err
	}
	freed = before - info.Size()
	if freed < 0 {
		freed = 0
	}
	return removed, kept, freed, nil
}
