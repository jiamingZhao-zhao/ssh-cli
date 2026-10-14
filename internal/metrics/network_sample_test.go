package metrics

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestNetworkSamplesDistinguishZeroMissingAndReset(t *testing.T) {
	for _, tc := range []struct {
		name, first, second string
		sampled             bool
		rate                uint64
	}{
		{"zero", "eth0: 0 0 0 0 0 0 0 0 0", "eth0: 0 0 0 0 0 0 0 0 0", true, 0},
		{"rate", "eth0: 10 0 0 0 0 0 0 0 4", "eth0: 12 0 0 0 0 0 0 0 5", true, 2000},
		{"malformed", "unparsed", "unparsed", false, 0},
		{"missing second", "eth0: 10 0 0 0 0 0 0 0 4", "", false, 0},
		{"reset", "eth0: 10 0 0 0 0 0 0 0 4", "eth0: 0 0 0 0 0 0 0 0 0", false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			count := 0
			snap, err := Collect(context.Background(), func(_ context.Context, cmd string) (string, int, error) {
				if strings.Contains(cmd, "/net/dev") {
					count++
					if count == 1 {
						return tc.first, 0, nil
					}
					return tc.second, 0, nil
				}
				return "", 1, nil
			}, nil, Options{Pause: time.Millisecond})
			if err != nil || snap.NetSampled != tc.sampled || snap.NetRxRate != tc.rate {
				t.Fatalf("snapshot %+v err %v", snap, err)
			}
		})
	}
}
