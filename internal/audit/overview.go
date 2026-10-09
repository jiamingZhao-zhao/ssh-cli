package audit

import (
	"sort"
	"time"
)

// DayStat is one local calendar day of audit counts.
type DayStat struct {
	Date   string `json:"date"`
	OK     int    `json:"ok"`
	Denied int    `json:"denied"`
	Other  int    `json:"other"`
}

// OpStat is how many records used one operation name.
type OpStat struct {
	Op    string `json:"op"`
	Count int    `json:"count"`
}

// Overview is the dashboard aggregate. Recent records are newest first.
type Overview struct {
	Days   []DayStat `json:"days"`
	Ops    []OpStat  `json:"ops"`
	Recent []Record  `json:"recent"`
}

// LoadOverview summarizes the last days of audit data, including today.
// days is clamped to 1..31. A missing audit directory is an empty overview.
func LoadOverview(dir string, days int, now time.Time) (Overview, error) {
	if days < 1 {
		days = 14
	}
	if days > 31 {
		days = 31
	}
	if now.IsZero() {
		now = time.Now()
	}
	loc := now.Location()
	end := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, loc)
	start := end.AddDate(0, 0, -(days - 1))
	out := Overview{Days: make([]DayStat, days), Recent: []Record{}}
	index := map[string]int{}
	for i := 0; i < days; i++ {
		key := start.AddDate(0, 0, i).Format("2006-01-02")
		out.Days[i].Date = key
		index[key] = i
	}
	ops := map[string]int{}
	err := List(dir, Filter{Since: start, HasSince: true}, func(rec Record) error {
		when, err := ParseStamp(rec.Time)
		if err != nil {
			return nil
		}
		i, ok := index[when.In(loc).Format("2006-01-02")]
		if !ok {
			return nil
		}
		switch rec.Status {
		case StatusOK:
			out.Days[i].OK++
		case StatusDenied:
			out.Days[i].Denied++
		default:
			out.Days[i].Other++
		}
		if rec.Op != "" {
			ops[rec.Op]++
		}
		return nil
	})
	if err != nil {
		return Overview{}, err
	}
	names := make([]string, 0, len(ops))
	for name := range ops {
		names = append(names, name)
	}
	sort.Strings(names)
	out.Ops = make([]OpStat, 0, len(names))
	for _, name := range names {
		out.Ops = append(out.Ops, OpStat{Op: name, Count: ops[name]})
	}
	recent, err := ListNewest(dir, Filter{}, 8)
	if err != nil {
		return Overview{}, err
	}
	if recent != nil {
		out.Recent = recent
	}
	return out, nil
}
