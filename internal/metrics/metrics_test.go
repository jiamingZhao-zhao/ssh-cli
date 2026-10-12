package metrics

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestParseSnapshotPieces(t *testing.T) {
	cpu, ok := CPUPercent(
		"cpu  100 0 50 1000 10 0 0 0\n",
		"cpu  200 0 80 1100 10 0 0 0\n",
	)
	if !ok || cpu < 50 || cpu > 90 {
		t.Fatalf("cpu %v %v", cpu, ok)
	}
	mem, swap, ok := ParseFree("              total        used        free      shared  buff/cache   available\nMem:         8000000     2000000     4000000      100000     2000000     5000000\nSwap:        1000000      250000      750000\n")
	if !ok || mem.Total != 8000000 || mem.Used != 3000000 || swap.Used != 250000 {
		t.Fatalf("mem %#v swap %#v", mem, swap)
	}
	disks := ParseDF("Filesystem 1024-blocks Used Available Capacity Mounted on\ntmpfs 1 1 1 1% /dev/shm\n/dev/sda1 100 40 60 40% /\n/dev/sdb1 10 1 9 10% /data/vol one\n")
	if len(disks) != 2 || disks[0].Mount != "/" || disks[1].Mount != "/data/vol one" || disks[1].Percent != "10%" || disks[0].UsedBytes != 40*1024 || disks[0].SizeBytes != 100*1024 {
		t.Fatalf("disks %#v", disks)
	}
	half := ParseDF("Filesystem 512-blocks Used Available Capacity Mounted on\n/dev/sda1 2 1 1 50% /\n")
	if len(half) != 1 || half[0].SizeBytes != 1024 || half[0].UsedBytes != 512 {
		t.Fatalf("512-blocks %#v", half)
	}
	procs := ParsePS("PID USER %CPU %MEM COMMAND\n1 root 0.1 0.2 systemd\n2 root 9.0 0.1 kthreadd extra\n")
	if len(procs) != 2 || procs[1].Comm != "kthreadd extra" || procs[0].CPU != "0.1" {
		t.Fatalf("procs %#v", procs)
	}
	aux := ParsePS("USER PID %CPU %MEM VSZ RSS TTY STAT START TIME COMMAND\nroot 1 0.0 0.1 1 2048 ? Ss 00:00 0:01 init\n")
	if len(aux) != 1 || aux[0].PID != "1" || aux[0].Comm != "init" || aux[0].RSS != 2048 {
		t.Fatalf("aux %#v", aux)
	}
	wide := ParsePS("PID PPID USER %CPU %MEM RSS STAT ELAPSED COMMAND\n9 1 root 1.3 0.4 762573 Ssl 01:02:03 java -jar /opt/ag.jar\n")
	if len(wide) != 1 || wide[0].PPID != "1" || wide[0].Stat != "Ssl" || wide[0].ETime != "01:02:03" || wide[0].Args != "java -jar /opt/ag.jar" || wide[0].Mem != "0.4" {
		t.Fatalf("wide %#v", wide)
	}
	if _, _, err := ProcCommands("9"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ProcCommands("abc"); err == nil {
		t.Fatal("bad pid accepted")
	}
	if got := ParseCwd("lrwxrwxrwx 1 root root 0 Oct 12 10:00 /proc/9/cwd -> /opt/app\n"); got != "/opt/app" {
		t.Fatalf("cwd %q", got)
	}
	rss := ParsePS("PID USER %CPU RSS COMMAND\n9 root 1.3 762573 java\n")
	if len(rss) != 1 || rss[0].RSS != 762573 || rss[0].CPU != "1.3" || rss[0].Comm != "java" {
		t.Fatalf("rss %#v", rss)
	}
	rx, tx := NetBytes("Inter-|   Receive |  Transmit\n face |bytes packets errs drop fifo frame compressed multicast|bytes packets\n    lo: 9 0 0 0 0 0 0 0 9 0 0 0 0 0 0 0\n  eth0: 100 1 0 0 0 0 0 0 40 1 0 0 0 0 0 0\n")
	if rx != 100 || tx != 40 {
		t.Fatalf("net %d %d", rx, tx)
	}
}

func TestTopFiveByMemory(t *testing.T) {
	var b strings.Builder
	b.WriteString("PID RSS COMMAND\n")
	for i := 0; i < 10; i++ {
		fmt.Fprintf(&b, "%d %d cmd-%d\n", i+1, (i+1)*1000, i+1)
	}
	procs := ParsePS(b.String())
	if len(procs) != 5 || procs[0].RSS != 10000 || procs[4].RSS != 6000 {
		t.Fatalf("top memory %#v", procs)
	}
	sorted := false
	for _, p := range Probes() {
		if p.Name == "proc" && strings.Contains(p.Command, "--sort=-rss") {
			sorted = true
		}
	}
	if !sorted {
		t.Fatal("proc probe is not sorted by memory")
	}
}

func TestChineseUptime(t *testing.T) {
	cases := []struct{ in, want string }{
		{"09:54:31 up 255 days, 23:49,  1 user,  load average: 0.01, 0.02, 0.05", "已运行 255 天 23 小时 49 分"},
		{"10:03:02 up 255 days, 23:58,  0 users,  load average: 0.01, 0.07, 0.07", "已运行 255 天 23 小时 58 分"},
		{"up 2 days", "已运行 2 天"},
		{"up 1 day,  2:03,  2 users,  load average: 0.00, 0.01, 0.05", "已运行 1 天 2 小时 3 分"},
		{"up 2:03,  1 user,  load average: 0.1, 0.2, 0.3", "已运行 2 小时 3 分"},
		{"up 3 min,  1 user,  load average: 0, 0, 0", "已运行 3 分"},
		{"up 23 hours, 49 minutes", "已运行 23 小时 49 分"},
	}
	for _, tc := range cases {
		if got := ChineseUptime(tc.in); got != tc.want {
			t.Errorf("ChineseUptime(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestCollectDegrades(t *testing.T) {
	calls := 0
	run := func(_ context.Context, command string) (string, int, error) {
		calls++
		switch {
		case command == "uptime":
			return "up 2 days", 0, nil
		case strings.Contains(command, "loadavg"):
			return "0.31 0.25 0.23 1/2 3\n", 0, nil
		case strings.Contains(command, "hostname"):
			return "", 1, nil
		case command == "cat /proc/stat":
			if calls < 20 {
				return "cpu  1 0 0 10 0 0 0 0\n", 0, nil
			}
		case command == "free -b":
			return "Mem: 1000 400 600\n", 0, nil
		case command == "df -P":
			return "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/sda1 100 40 60 40% /\n", 0, nil
		case strings.HasPrefix(command, "ps -eo"):
			return "", 127, nil
		case command == "ps aux":
			return "USER PID %CPU %MEM VSZ RSS TTY STAT START TIME COMMAND\nroot 1 0.2 0.3 1 1 ? Ss 00:00 0:00 init\n", 0, nil
		case strings.Contains(command, "net/dev"):
			return "  eth0: 10 0 0 0 0 0 0 0 4 0 0 0 0 0 0 0\n", 0, nil
		}
		return "", 1, nil
	}
	snap, err := Collect(context.Background(), run, func(command string) error {
		if strings.Contains(command, "hostname") {
			return errors.New("denied")
		}
		return nil
	}, Options{Pause: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(snap.Uptime, "已运行") || !strings.Contains(snap.Uptime, "2 天") || snap.Load != "0.31 0.25 0.23" || snap.Hostname != "" {
		t.Fatalf("identity %#v", snap)
	}
	if snap.Mem == nil || snap.Mem.Total != 1000 || len(snap.Disks) != 1 || len(snap.Procs) != 1 {
		t.Fatalf("body %#v", snap)
	}
	joined := strings.Join(snap.Notes, ";")
	if !strings.Contains(joined, "hostname: denied") || !strings.Contains(joined, "proc: unavailable") {
		t.Fatalf("notes %s", joined)
	}
	if _, err := Collect(context.Background(), func(context.Context, string) (string, int, error) {
		return "", 0, errors.New("dial failed")
	}, nil, Options{}); err == nil {
		t.Fatal("transport swallowed")
	}
}
