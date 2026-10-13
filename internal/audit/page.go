package audit

import (
	"fmt"
	"os"
)

const (
	// DefaultPageSize is the audit page length when the caller does not choose one.
	DefaultPageSize = 50
	// MaxPageSize is the largest page the API or CLI will return.
	MaxPageSize = 200
)

// Page is one newest-first window of a filtered scan.
type Page struct {
	Records  []Record `json:"records"`
	Page     int      `json:"page"`
	PageSize int      `json:"pageSize"`
	Total    int      `json:"total"`
}

// Stats is the on-disk audit log, independent of the current filter.
type Stats struct {
	Bytes   int64 `json:"bytes"`
	Files   int   `json:"files"`
	Entries int   `json:"entries"`
}

// QueryPage returns one page of matches, newest first.
// It reads each matching day once, newest first, keeping only one page.
func QueryPage(dir string, f Filter, page, size int) (Page, error) {
	if page < 1 {
		page = 1
	}
	if size <= 0 {
		size = DefaultPageSize
	}
	if size > MaxPageSize {
		size = MaxPageSize
	}
	files, err := dataFiles(dir)
	if err != nil {
		return Page{}, err
	}
	out := Page{Page: page, PageSize: size, Records: []Record{}}
	// Avoid arithmetic overflow even for malformed API page parameters.
	start := int64(page-1) * int64(size)
	if start < 0 || start/int64(size) != int64(page-1) {
		start = 1<<63 - 1
	}
	for i := len(files) - 1; i >= 0; i-- {
		day, ok := fileDay(files[i])
		if !ok {
			continue
		}
		if f.HasSince && day.Before(dayStart(f.Since)) {
			continue
		}
		if f.HasUntil && day.After(dayStart(f.Until)) {
			continue
		}
		info, err := os.Stat(files[i])
		if err != nil {
			return Page{}, err
		}
		key := countKey(files[i], f)
		if n, ok := cachedCount(key, info); ok && (int64(out.Total+n) <= start || len(out.Records) == size) {
			out.Total += n
			continue
		}
		before := out.Total
		err = scanReverse(files[i], func(rec Record) {
			if _, ok := matchTime(rec, f); !ok || !matchFields(rec, f) {
				return
			}
			if int64(out.Total) >= start && len(out.Records) < size {
				out.Records = append(out.Records, rec)
			}
			out.Total++
		})
		if err != nil {
			return Page{}, err
		}
		if after, err := os.Stat(files[i]); err == nil && after.Size() == info.Size() && after.ModTime().Equal(info.ModTime()) {
			rememberCount(key, info, out.Total-before)
		}
	}
	return out, nil
}

// Count is how many records match f.
func Count(dir string, f Filter) (int, error) {
	n := 0
	err := List(dir, f, func(Record) error {
		n++
		return nil
	})
	return n, err
}

// Stat reports file count, total bytes, and valid JSONL entries.
func Stat(dir string) (Stats, error) {
	files, err := dataFiles(dir)
	if err != nil {
		return Stats{}, err
	}
	var st Stats
	st.Files = len(files)
	for _, path := range files {
		info, err := os.Stat(path)
		if err != nil {
			return Stats{}, err
		}
		st.Bytes += info.Size()
		key := countKey(path, Filter{})
		if n, ok := cachedCount(key, info); ok {
			st.Entries += n
			continue
		}
		before := st.Entries
		_, err = scanFile(path, -1, func(Record) (bool, error) {
			st.Entries++
			return false, nil
		})
		if err != nil {
			return Stats{}, err
		}
		if after, err := os.Stat(path); err == nil && after.Size() == info.Size() && after.ModTime().Equal(info.ModTime()) {
			rememberCount(key, info, st.Entries-before)
		}
	}
	return st, nil
}

// NormalizePage clamps page and size the same way QueryPage does.
func NormalizePage(page, size int) (int, int) {
	if page < 1 {
		page = 1
	}
	if size <= 0 {
		size = DefaultPageSize
	}
	if size > MaxPageSize {
		size = MaxPageSize
	}
	return page, size
}

// PageLabel is a short error when a page request is malformed.
func PageLabel(page, size int) string {
	page, size = NormalizePage(page, size)
	return fmt.Sprintf("page %d size %d", page, size)
}
