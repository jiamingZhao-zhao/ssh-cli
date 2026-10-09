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
// It streams twice and keeps only the page in memory.
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
	total := 0
	err := List(dir, f, func(Record) error {
		total++
		return nil
	})
	if err != nil {
		return Page{}, err
	}
	out := Page{Page: page, PageSize: size, Total: total, Records: []Record{}}
	start := total - page*size
	take := size
	if start < 0 {
		take += start
		start = 0
	}
	if take <= 0 {
		return out, nil
	}
	seen := 0
	var window []Record
	err = List(dir, f, func(rec Record) error {
		if seen < start {
			seen++
			return nil
		}
		if len(window) < take {
			window = append(window, rec)
		}
		return nil
	})
	if err != nil {
		return Page{}, err
	}
	for i, j := 0, len(window)-1; i < j; i, j = i+1, j-1 {
		window[i], window[j] = window[j], window[i]
	}
	if window != nil {
		out.Records = window
	}
	return out, nil
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
		_, err = scanFile(path, -1, func(Record) (bool, error) {
			st.Entries++
			return false, nil
		})
		if err != nil {
			return Stats{}, err
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
