package audit

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

// Counts only: no command text, output, or unbounded offset/record index.
type fileCount struct {
	size     int64
	modified time.Time
	count    int
}

var counts = struct {
	sync.Mutex
	items map[string]fileCount
}{items: map[string]fileCount{}}

func countKey(path string, filter Filter) string {
	b, _ := json.Marshal(filter)
	return path + "\x00" + string(b)
}
func cachedCount(key string, info os.FileInfo) (int, bool) {
	counts.Lock()
	defer counts.Unlock()
	entry, ok := counts.items[key]
	return entry.count, ok && entry.size == info.Size() && entry.modified.Equal(info.ModTime())
}
func rememberCount(key string, info os.FileInfo, count int) {
	if len(key) > 4096 {
		return
	}
	counts.Lock()
	defer counts.Unlock()
	if len(counts.items) >= 256 {
		clear(counts.items)
	}
	counts.items[key] = fileCount{info.Size(), info.ModTime(), count}
}
