package audit

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestQueryPageNewestFirst(t *testing.T) {
	dir := t.TempDir()
	day := time.Date(2026, 4, 1, 12, 0, 0, 0, time.Local)
	for i := 0; i < 5; i++ {
		rec := Record{Op: OpExec, Host: "box", Status: StatusOK, Command: string(rune('a' + i)), Time: day.Add(time.Duration(i) * time.Minute).Format(time.RFC3339Nano)}
		if _, err := Append(dir, rec); err != nil {
			t.Fatal(err)
		}
	}
	pg, err := QueryPage(dir, Filter{Op: OpExec}, 1, 2)
	if err != nil {
		t.Fatal(err)
	}
	if pg.Total != 5 || len(pg.Records) != 2 {
		t.Fatalf("page %+v", pg)
	}
	if pg.Records[0].Command != "e" || pg.Records[1].Command != "d" {
		t.Fatalf("order %q %q", pg.Records[0].Command, pg.Records[1].Command)
	}
	st, err := Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if st.Entries != 5 || st.Files != 1 || st.Bytes <= 0 {
		t.Fatalf("stats %+v", st)
	}
}

func TestCleanupRefusesNewerThan30Days(t *testing.T) {
	dir := t.TempDir()
	_, err := Cleanup(dir, 24*time.Hour, time.Now())
	if err == nil || err.Error() != "refusing to delete audit entries newer than 30 days" {
		t.Fatalf("err %v", err)
	}
}

func TestCleanupDropsOldDaysOnly(t *testing.T) {
	dir := t.TempDir()
	old := time.Now().Add(-40 * 24 * time.Hour)
	recent := time.Now().Add(-time.Hour)
	if _, err := Append(dir, Record{Op: OpExec, Host: "old", Status: StatusOK, Time: old.Format(time.RFC3339Nano), Command: "old"}); err != nil {
		t.Fatal(err)
	}
	if _, err := Append(dir, Record{Op: OpExec, Host: "new", Status: StatusOK, Time: recent.Format(time.RFC3339Nano), Command: "new"}); err != nil {
		t.Fatal(err)
	}
	res, err := Cleanup(dir, MinAge, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if res.Removed == 0 {
		t.Fatalf("removed nothing: %+v", res)
	}
	var kept []Record
	if err := List(dir, Filter{}, func(rec Record) error {
		kept = append(kept, rec)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(kept) != 1 || kept[0].Command != "new" {
		t.Fatalf("kept %+v", kept)
	}
	matches, _ := filepath.Glob(filepath.Join(dir, DirName, old.Format("2006-01-02")+".jsonl"))
	if len(matches) != 0 {
		if _, err := os.Stat(matches[0]); err == nil {
			t.Fatal("old file remains")
		}
	}
}
