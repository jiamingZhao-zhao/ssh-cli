package metrics

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestParallelBoundAndPartialSnapshot(t *testing.T) {
	var active, peak atomic.Int32
	run := func(ctx context.Context, command string) (string, int, error) {
		n := active.Add(1)
		defer active.Add(-1)
		for n > peak.Load() {
			old := peak.Load()
			if n <= old || peak.CompareAndSwap(old, n) {
				break
			}
		}
		time.Sleep(5 * time.Millisecond)
		if command == "uptime" {
			return "up 2 days", 0, nil
		}
		if strings.Contains(command, "loadavg") {
			return "0.1 0.2 0.3 1/5 6", 0, nil
		}
		if command == "df -P" {
			return "", 0, errors.New("synthetic probe timeout")
		}
		return "", 1, nil
	}
	snap, err := Parallel(context.Background(), run, nil, Options{})
	if err != nil || snap.Uptime == "" || snap.Load == "" || len(snap.Notes) == 0 {
		t.Fatalf("lost partial snapshot: %+v %v", snap, err)
	}
	if peak.Load() < 2 || peak.Load() > 3 {
		t.Fatalf("concurrency %d", peak.Load())
	}
}
