package audit

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAppendScrubListShowAndMode(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SSH_CLI_ACTOR", "agent-1")
	when := time.Date(2020, 1, 2, 15, 4, 5, 0, time.Local)
	pem := "-----BEGIN OPENSSH PRIVATE KEY-----\nSECRETKEYDATA\n-----END OPENSSH PRIVATE KEY-----"
	rec, err := Append(dir, Record{
		Time:           when.Format(time.RFC3339Nano),
		Op:             OpExec,
		Host:           "main",
		Group:          "app-prod",
		Env:            "prod",
		Command:        "echo password=s3cret-leak && cat " + pem,
		Status:         StatusDenied,
		HighRisk:       true,
		DeniedByPolicy: true,
		Reason:         "builtin: rm of filesystem root",
		ResultSummary:  strings.Repeat("测", 10<<10),
		ExitCode:       intPtr(253),
		DurationMS:     4,
	})
	if err != nil {
		t.Fatal(err)
	}
	if rec.ID == "" || !strings.HasPrefix(rec.ID, "20200102T150405") {
		t.Fatalf("id %q", rec.ID)
	}
	if strings.Contains(rec.Command, "s3cret-leak") || strings.Contains(rec.Command, "SECRETKEYDATA") {
		t.Fatalf("scrub failed: %s", rec.Command)
	}
	if !strings.Contains(rec.Command, "[redacted]") || !strings.Contains(rec.Command, "[redacted-key]") {
		t.Fatalf("command %s", rec.Command)
	}
	if len(rec.ResultSummary) > SummaryLimit+len("\n[truncated]")+8 {
		t.Fatalf("summary len %d", len(rec.ResultSummary))
	}
	if !strings.Contains(rec.ResultSummary, "[truncated]") {
		t.Fatal("expected truncated summary")
	}
	path := filepath.Join(dir, DirName, "2020-01-02.jsonl")
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("file mode %o", fi.Mode().Perm())
	}
	di, err := os.Stat(filepath.Join(dir, DirName))
	if err != nil {
		t.Fatal(err)
	}
	if di.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode %o", di.Mode().Perm())
	}

	later := time.Date(2020, 1, 3, 1, 0, 0, 0, time.Local)
	if _, err := Append(dir, Record{
		Time:    later.Format(time.RFC3339Nano),
		Op:      OpUpload,
		Host:    "other",
		Group:   "sandbox",
		Env:     "dev",
		Src:     "./dist",
		Dst:     "/tmp/dist",
		Status:  StatusOK,
		Command: "curl https://user:s3cret-leak@192.0.2.10/x",
	}); err != nil {
		t.Fatal(err)
	}

	var denied []Record
	err = List(dir, Filter{Hosts: []string{"main"}, Status: StatusDenied}, func(r Record) error {
		denied = append(denied, r)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(denied) != 1 || denied[0].ID != rec.ID || denied[0].Actor != "agent-1" {
		t.Fatalf("denied %+v", denied)
	}
	raw := mustReadAudit(t, dir)
	if strings.Contains(raw, "s3cret-leak") || strings.Contains(raw, "SECRETKEYDATA") {
		t.Fatalf("plaintext secret in audit log:\n%s", raw)
	}

	var until []Record
	err = List(dir, Filter{Until: time.Date(2020, 1, 3, 0, 0, 0, 0, time.Local), HasUntil: true}, func(r Record) error {
		until = append(until, r)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(until) != 1 || until[0].Host != "main" {
		t.Fatalf("until scan %+v", until)
	}

	got, err := Show(dir, rec.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Host != "main" || !got.HighRisk || !got.DeniedByPolicy || got.ExitCode == nil || *got.ExitCode != 253 {
		t.Fatalf("show %+v", got)
	}
	if _, err := Show(dir, "missing"); err == nil {
		t.Fatal("expected missing id")
	}

	newest, err := ListNewest(dir, Filter{}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(newest) != 1 || newest[0].Host != "other" {
		t.Fatalf("newest %+v", newest)
	}
}

func TestTailAndFollow(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SSH_CLI_ACTOR", "")
	first, err := Append(dir, Record{Op: OpExec, Host: "main", Command: "echo one", Status: StatusOK})
	if err != nil {
		t.Fatal(err)
	}
	if first.Actor != "cli" {
		t.Fatalf("actor %q", first.Actor)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	seen := make(chan string, 4)
	errCh := make(chan error, 1)
	go func() {
		errCh <- Tail(ctx, dir, 1, true, func(rec Record) error {
			seen <- rec.Command
			return nil
		})
	}()
	waitFor(t, seen, "echo one")
	if _, err := Append(dir, Record{Op: OpExec, Host: "main", Command: "echo two", Status: StatusError, ExitCode: intPtr(3)}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, seen, "echo two")
	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("tail did not return after cancel")
	}

	var got []Record
	if err := Tail(context.Background(), dir, 1, false, func(rec Record) error {
		got = append(got, rec)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Command != "echo two" || got[0].ExitCode == nil || *got[0].ExitCode != 3 {
		t.Fatalf("tail %+v", got)
	}
}

func waitFor(t *testing.T, ch <-chan string, want string) {
	t.Helper()
	deadline := time.After(3 * time.Second)
	for {
		select {
		case got := <-ch:
			if got == want {
				return
			}
		case <-deadline:
			t.Fatalf("timed out waiting for %q", want)
		}
	}
}

func TestParseBound(t *testing.T) {
	now := time.Now()
	since, err := ParseBound("1h", false)
	if err != nil {
		t.Fatal(err)
	}
	if since.Before(now.Add(-2*time.Hour)) || since.After(now.Add(-30*time.Minute)) {
		t.Fatalf("since %s", since)
	}
	day, err := ParseBound("2020-01-02", false)
	if err != nil {
		t.Fatal(err)
	}
	if day.Hour() != 0 || day.Day() != 2 {
		t.Fatalf("day %s", day)
	}
	end, err := ParseBound("2020-01-02", true)
	if err != nil {
		t.Fatal(err)
	}
	if !end.Equal(day.AddDate(0, 0, 1)) {
		t.Fatalf("until day %s", end)
	}
	if _, err := ParseBound("not-a-time", false); err == nil {
		t.Fatal("expected error")
	}
}

func mustReadAudit(t *testing.T, dir string) string {
	t.Helper()
	var b strings.Builder
	entries, err := os.ReadDir(filepath.Join(dir, DirName))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".jsonl") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, DirName, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		b.Write(data)
	}
	return b.String()
}

func intPtr(n int) *int { return &n }
