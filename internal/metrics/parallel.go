package metrics

import (
	"context"
	"strings"
	"sync"
	"time"
)

// Parallel prefetches independent probes, then uses the ordinary reducer and
// its ordered second CPU/network samples. Exec must support concurrent calls;
// gate is always called serially. Concurrency never exceeds three SSH channels.
func Parallel(ctx context.Context, exec ExecFunc, gate GateFunc, opt Options) (Snapshot, error) {
	type result struct {
		text string
		code int
		err  error
		at   time.Time
	}
	probes := Probes()
	results := make([]result, len(probes))
	sem := make(chan struct{}, 3)
	var wg sync.WaitGroup
	for i, p := range probes {
		if p.Name == "proc-aux" {
			continue
		}
		if gate != nil {
			if err := gate(p.Command); err != nil {
				continue
			}
		}
		wg.Add(1)
		go func(i int, p Probe) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				results[i].err = ctx.Err()
				return
			}
			defer func() { <-sem }()
			text, code, err := exec(ctx, p.Command)
			results[i] = result{text, code, err, time.Now()}
		}(i, p)
	}
	wg.Wait()
	cache := map[string]result{}
	var firstErr error
	succeeded := false
	for i, p := range probes {
		if p.Name == "proc-aux" {
			continue
		}
		r := results[i]
		cache[p.Command] = r
		if r.err != nil && firstErr == nil {
			firstErr = r.err
		}
		if r.err == nil && r.code == 0 && strings.TrimSpace(r.text) != "" {
			succeeded = true
		}
	}
	if !succeeded && firstErr != nil {
		return Snapshot{}, firstErr
	}
	var netStart, netEnd time.Time
	snap, err := Collect(ctx, func(ctx context.Context, command string) (string, int, error) {
		if r, ok := cache[command]; ok {
			delete(cache, command)
			if strings.Contains(command, "/net/dev") {
				netStart = r.at
			}
			if r.err != nil {
				return "", 1, nil
			} // retain successful fields
			return r.text, r.code, nil
		}
		text, code, err := exec(ctx, command)
		if strings.Contains(command, "/net/dev") {
			netEnd = time.Now()
		}
		if err != nil && succeeded {
			return "", 1, nil
		}
		return text, code, err
	}, gate, opt)
	// The first samples may precede other slow probes; use the actual interval.
	if elapsed := netEnd.Sub(netStart).Seconds(); snap.NetSampled && elapsed > 0 && !netStart.IsZero() && !netEnd.IsZero() {
		for i, p := range probes {
			if p.Name != "net" {
				continue
			}
			rx, tx := NetBytes(results[i].text)
			if snap.NetRx >= rx {
				snap.NetRxRate = uint64(float64(snap.NetRx-rx) / elapsed)
			}
			if snap.NetTx >= tx {
				snap.NetTxRate = uint64(float64(snap.NetTx-tx) / elapsed)
			}
		}
	}
	return snap, err
}
