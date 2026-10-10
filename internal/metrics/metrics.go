// Package metrics collects a best-effort snapshot of a remote Linux host.
// Each probe is a fixed read-only command. A missing binary, a non-Linux
// /proc, or a policy denial omits that field and adds a note. Nothing writes.
package metrics

import (
	"context"
	"strconv"
	"strings"
	"time"
)

// Probe is one fixed read.
type Probe struct {
	Name    string
	Command string
}

// Probes are the commands a snapshot may run. stat and net are read twice
// so CPU and traffic rates can be derived. ps falls back to ps aux.
func Probes() []Probe {
	return []Probe{
		{Name: "uptime", Command: "uptime"},
		{Name: "load", Command: "cat /proc/loadavg"},
		{Name: "hostname", Command: "cat /etc/hostname"},
		{Name: "stat", Command: "cat /proc/stat"},
		{Name: "mem", Command: "free -b"},
		{Name: "disk", Command: "df -P"},
		{Name: "proc", Command: "ps -eo pid,user,pcpu,pmem,comm --sort=-pcpu"},
		{Name: "proc-aux", Command: "ps aux"},
		{Name: "net", Command: "cat /proc/net/dev"},
	}
}

// ExecFunc runs one remote command.
type ExecFunc func(ctx context.Context, command string) (stdout string, code int, err error)

// GateFunc skips a command when it returns an error.
type GateFunc func(command string) error

// Options tunes sampling. Pause is the gap between the two /proc reads.
// Zero still takes both samples immediately.
type Options struct {
	Pause time.Duration
}

// Mem is one memory class in bytes.
type Mem struct {
	Total   uint64   `json:"total"`
	Used    uint64   `json:"used"`
	Percent *float64 `json:"percent,omitempty"`
}

// Proc is one process line, capped by the collector.
type Proc struct {
	PID  string `json:"pid"`
	User string `json:"user"`
	CPU  string `json:"cpu"`
	Mem  string `json:"mem"`
	Comm string `json:"comm"`
}

// Disk is one mount from df.
type Disk struct {
	Mount   string `json:"mount"`
	Size    string `json:"size"`
	Used    string `json:"used"`
	Avail   string `json:"avail"`
	Percent string `json:"percent"`
}

// Snapshot is safe to show when individual probes fail.
type Snapshot struct {
	Connected bool     `json:"connected"`
	Hostname  string   `json:"hostname,omitempty"`
	Uptime    string   `json:"uptime,omitempty"`
	Load      string   `json:"load,omitempty"`
	CPU       *float64 `json:"cpuPercent,omitempty"`
	Mem       *Mem     `json:"mem,omitempty"`
	Swap      *Mem     `json:"swap,omitempty"`
	Procs     []Proc   `json:"procs"`
	Disks     []Disk   `json:"disks"`
	NetRx     uint64   `json:"netRx"`
	NetTx     uint64   `json:"netTx"`
	NetRxRate uint64   `json:"netRxRate"`
	NetTxRate uint64   `json:"netTxRate"`
	Notes     []string `json:"notes"`
	Commands  []string `json:"-"`
}

const (
	maxProcs = 8
	maxDisks = 8
)

// Collect runs the probes. A transport error from the first successful dial
// path is returned; per-command failures become notes.
func Collect(ctx context.Context, exec ExecFunc, gate GateFunc, opt Options) (Snapshot, error) {
	snap := Snapshot{Connected: true, Procs: []Proc{}, Disks: []Disk{}, Notes: []string{}}
	if exec == nil {
		return snap, errString("metrics exec is required")
	}
	pause := opt.Pause
	if pause < 0 {
		pause = 0
	}
	byName := map[string]Probe{}
	for _, p := range Probes() {
		byName[p.Name] = p
	}
	var transport error
	run := func(name string) (string, bool) {
		p, ok := byName[name]
		if !ok {
			return "", false
		}
		if gate != nil {
			if err := gate(p.Command); err != nil {
				snap.Notes = append(snap.Notes, name+": denied by policy")
				return "", false
			}
		}
		stdout, code, err := exec(ctx, p.Command)
		if err != nil {
			transport = err
			return "", false
		}
		snap.Commands = append(snap.Commands, p.Command)
		if code != 0 || strings.TrimSpace(stdout) == "" {
			snap.Notes = append(snap.Notes, name+": unavailable")
			return "", false
		}
		return stdout, true
	}
	if text, ok := run("uptime"); ok {
		snap.Uptime = oneLine(text)
	}
	if transport != nil {
		return Snapshot{}, transport
	}
	if text, ok := run("load"); ok {
		snap.Load = loadOf(text)
	}
	if transport != nil {
		return Snapshot{}, transport
	}
	if text, ok := run("hostname"); ok {
		snap.Hostname = oneLine(text)
	}
	if transport != nil {
		return Snapshot{}, transport
	}
	stat1, ok1 := run("stat")
	if transport != nil {
		return Snapshot{}, transport
	}
	net1, okNet1 := run("net")
	if transport != nil {
		return Snapshot{}, transport
	}
	if ok1 || okNet1 {
		if pause > 0 {
			timer := time.NewTimer(pause)
			select {
			case <-ctx.Done():
				timer.Stop()
				return Snapshot{}, ctx.Err()
			case <-timer.C:
			}
		}
	}
	stat2, ok2 := "", false
	if ok1 {
		stat2, ok2 = run("stat")
		if transport != nil {
			return Snapshot{}, transport
		}
	}
	net2, okNet2 := "", false
	if okNet1 {
		net2, okNet2 = run("net")
		if transport != nil {
			return Snapshot{}, transport
		}
	}
	if ok1 && ok2 {
		if cpu, ok := CPUPercent(stat1, stat2); ok {
			snap.CPU = &cpu
		}
	}
	if okNet1 {
		rx, tx := NetBytes(net1)
		snap.NetRx, snap.NetTx = rx, tx
		if okNet2 && pause > 0 {
			rx2, tx2 := NetBytes(net2)
			snap.NetRx, snap.NetTx = rx2, tx2
			sec := uint64(pause / time.Second)
			if sec < 1 {
				sec = 1
			}
			if rx2 >= rx {
				snap.NetRxRate = (rx2 - rx) / sec
			}
			if tx2 >= tx {
				snap.NetTxRate = (tx2 - tx) / sec
			}
		}
	}
	if text, ok := run("mem"); ok {
		mem, swap, okm := ParseFree(text)
		if okm {
			snap.Mem = &mem
			snap.Swap = &swap
		} else {
			snap.Notes = append(snap.Notes, "mem: unparsed")
		}
	}
	if transport != nil {
		return Snapshot{}, transport
	}
	if text, ok := run("disk"); ok {
		snap.Disks = ParseDF(text)
		if len(snap.Disks) == 0 {
			snap.Notes = append(snap.Notes, "disk: unparsed")
		}
	}
	if transport != nil {
		return Snapshot{}, transport
	}
	if text, ok := run("proc"); ok {
		snap.Procs = ParsePS(text)
	} else if transport == nil {
		if text, ok := run("proc-aux"); ok {
			snap.Procs = ParsePS(text)
		}
	}
	if transport != nil {
		return Snapshot{}, transport
	}
	if snap.Procs == nil {
		snap.Procs = []Proc{}
	}
	if snap.Disks == nil {
		snap.Disks = []Disk{}
	}
	return snap, nil
}

type errString string

func (e errString) Error() string { return string(e) }

func oneLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimSpace(s)
	if len(s) > 180 {
		s = s[:180]
	}
	return s
}

func loadOf(s string) string {
	f := strings.Fields(s)
	if len(f) >= 3 {
		return f[0] + " " + f[1] + " " + f[2]
	}
	return oneLine(s)
}

// CPUPercent is the non-idle share between two /proc/stat samples.
func CPUPercent(a, b string) (float64, bool) {
	idle1, total1, ok1 := cpuLine(a)
	idle2, total2, ok2 := cpuLine(b)
	if !ok1 || !ok2 || total2 <= total1 {
		return 0, false
	}
	dTotal := total2 - total1
	dIdle := idle2 - idle1
	if dIdle > dTotal {
		return 0, false
	}
	return 100 * float64(dTotal-dIdle) / float64(dTotal), true
}

func cpuLine(text string) (idle, total uint64, ok bool) {
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "cpu ") {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 5 {
			return 0, 0, false
		}
		var sum uint64
		for _, tok := range f[1:] {
			n, err := strconv.ParseUint(tok, 10, 64)
			if err != nil {
				return 0, 0, false
			}
			sum += n
		}
		idleN, err := strconv.ParseUint(f[4], 10, 64)
		if err != nil {
			return 0, 0, false
		}
		if len(f) > 5 {
			if n, err := strconv.ParseUint(f[5], 10, 64); err == nil {
				idleN += n
			}
		}
		return idleN, sum, true
	}
	return 0, 0, false
}

// ParseFree reads `free` or `free -b`. Used prefers total-available.
func ParseFree(text string) (mem, swap Mem, ok bool) {
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) < 3 {
			continue
		}
		kind := strings.TrimSuffix(strings.ToLower(f[0]), ":")
		total, err1 := strconv.ParseUint(f[1], 10, 64)
		used, err2 := strconv.ParseUint(f[2], 10, 64)
		if err1 != nil || err2 != nil || total == 0 {
			continue
		}
		item := Mem{Total: total, Used: used}
		if len(f) >= 7 {
			if avail, err := strconv.ParseUint(f[6], 10, 64); err == nil && avail <= total {
				item.Used = total - avail
			}
		}
		pct := 100 * float64(item.Used) / float64(item.Total)
		item.Percent = &pct
		switch kind {
		case "mem":
			mem = item
			ok = true
		case "swap":
			swap = item
		}
	}
	return mem, swap, ok
}

// ParseDF reads POSIX df. Virtual filesystems are skipped.
func ParseDF(text string) []Disk {
	var out []Disk
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) < 6 || f[0] == "Filesystem" {
			continue
		}
		fs := f[0]
		if fs == "tmpfs" || fs == "devtmpfs" || fs == "overlay" || fs == "none" || strings.HasPrefix(fs, "squashfs") {
			continue
		}
		disk := Disk{
			Size: f[1], Used: f[2], Avail: f[3], Percent: f[4],
			Mount: strings.Join(f[5:], " "),
		}
		out = append(out, disk)
		if len(out) == maxDisks {
			break
		}
	}
	if out == nil {
		return []Disk{}
	}
	return out
}

// ParsePS reads `ps -eo` or `ps aux` headers.
func ParsePS(text string) []Proc {
	lines := strings.Split(text, "\n")
	if len(lines) == 0 {
		return []Proc{}
	}
	header := strings.Fields(strings.ToUpper(lines[0]))
	col := map[string]int{}
	for i, h := range header {
		col[h] = i
	}
	pidI := firstCol(col, "PID")
	userI := firstCol(col, "USER")
	cpuI := firstCol(col, "%CPU", "CPU")
	memI := firstCol(col, "%MEM", "MEM")
	commI := firstCol(col, "COMMAND", "CMD", "COMM")
	if pidI < 0 || commI < 0 {
		return []Proc{}
	}
	var out []Proc
	for _, line := range lines[1:] {
		f := strings.Fields(line)
		if len(f) <= commI || len(f) <= pidI {
			continue
		}
		p := Proc{PID: f[pidI], Comm: strings.Join(f[commI:], " ")}
		if userI >= 0 && userI < len(f) {
			p.User = f[userI]
		}
		if cpuI >= 0 && cpuI < len(f) {
			p.CPU = f[cpuI]
		}
		if memI >= 0 && memI < len(f) {
			p.Mem = f[memI]
		}
		out = append(out, p)
		if len(out) == maxProcs {
			break
		}
	}
	if out == nil {
		return []Proc{}
	}
	return out
}

func firstCol(col map[string]int, names ...string) int {
	for _, n := range names {
		if i, ok := col[n]; ok {
			return i
		}
	}
	return -1
}

// NetBytes sums non-loopback receive and transmit bytes from /proc/net/dev.
func NetBytes(text string) (rx, tx uint64) {
	for _, line := range strings.Split(text, "\n") {
		if !strings.Contains(line, ":") {
			continue
		}
		name, rest, _ := strings.Cut(line, ":")
		name = strings.TrimSpace(name)
		if name == "" || name == "lo" || strings.HasPrefix(name, "Inter") || strings.HasPrefix(name, "face") {
			continue
		}
		f := strings.Fields(rest)
		if len(f) < 9 {
			continue
		}
		r, err1 := strconv.ParseUint(f[0], 10, 64)
		t, err2 := strconv.ParseUint(f[8], 10, 64)
		if err1 != nil || err2 != nil {
			continue
		}
		rx += r
		tx += t
	}
	return rx, tx
}
