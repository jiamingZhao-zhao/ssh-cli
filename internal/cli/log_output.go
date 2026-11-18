package cli

import (
	"bytes"
	"fmt"
	"io"
	"regexp"
	"strings"
	"sync"
	"time"
)

var (
	logControl        = regexp.MustCompile(`\x1b\[[0-?]*[ -/]*[@-~]|[\x00-\x08\x0b-\x1f\x7f]`)
	secretHeader      = regexp.MustCompile(`(?i)\b(?:proxy-authorization|authorization|blade-auth|set-cookie|cookie|x-api-key|x-auth-token|access-token)(?:\\?["'])?[ \t]*[:=][ \t]*`)
	quotedHeaderValue = regexp.MustCompile(`^"(?:[^"\\\r\n]|\\.)*"`)
	logTimestamp      = regexp.MustCompile(`(?:^|\[)(\d{4}-\d\d-\d\d[ T]\d\d:\d\d:\d\d(?:[.,]\d+)?(?:Z|[+-]\d\d:\d\d)?)`)
)

func maskLogHeaders(line string) (string, bool) {
	line = logControl.ReplaceAllString(line, "")
	var out strings.Builder
	matched := false
	for {
		loc := secretHeader.FindStringIndex(line)
		if loc == nil {
			if !matched {
				return line, false
			}
			out.WriteString(line)
			return out.String(), true
		}
		matched = true
		key := strings.TrimSpace(line[loc[0]:loc[1]])
		jsonKey := loc[0] > 0 && line[loc[0]-1] == '"' && strings.HasSuffix(strings.TrimSpace(strings.TrimSuffix(key, ":")), `"`) && strings.HasSuffix(key, ":")
		out.WriteString(line[:loc[1]])
		line = line[loc[1]:]
		value := quotedHeaderValue.FindString(line)
		rest := strings.TrimSpace(line[len(value):])
		if jsonKey && value != "" && (strings.HasPrefix(rest, "}") || strings.HasPrefix(rest, ",")) {
			out.WriteString(`"[REDACTED]"`)
			line = line[len(value):]
			continue
		}
		out.WriteString("[REDACTED]")
		return out.String(), true
	}
}

type logOutputOptions struct {
	redact       bool
	filter       *regexp.Regexp
	since, until time.Time
	zone         *time.Location
}

type logOutput struct {
	mu                                                sync.Mutex
	closed                                            bool
	dst                                               io.Writer
	opts                                              logOutputOptions
	line                                              []byte
	overflow, cut, redacted, inWindow, previousHeader bool
	unstamped                                         int
}

func (w *logOutput) Write(data []byte) (int, error) {
	const maxLogLine = 64 << 10
	length := len(data)
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return length, nil
	}
	for len(data) != 0 {
		segment, rest, complete := bytes.Cut(data, []byte{'\n'})
		if !w.overflow && len(segment)+len(w.line) <= maxLogLine {
			w.line = append(w.line, segment...)
		} else {
			w.overflow = true
		}
		if complete {
			w.flush("\n")
		}
		data = rest
	}
	return length, nil
}

func (w *logOutput) finish(complete bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.closed = true
	if complete {
		w.flush("")
	}
}

func (w *logOutput) flush(newline string) {
	if w.overflow {
		w.cut, w.overflow, w.inWindow = true, false, false
		w.line = w.line[:0]
		return
	}
	if len(w.line) == 0 && newline == "" {
		return
	}
	line := strings.TrimSuffix(string(w.line), "\r")
	w.line = w.line[:0]
	if w.opts.redact {
		if w.previousHeader && strings.TrimLeft(line, " \t") != line {
			line = "[REDACTED]"
		} else {
			line, w.previousHeader = maskLogHeaders(line)
		}
		w.redacted = w.redacted || w.previousHeader
	}
	if !w.opts.since.IsZero() || !w.opts.until.IsZero() {
		if stamp := logTimestamp.FindStringSubmatch(line); len(stamp) > 0 {
			value := strings.Replace(stamp[1], " ", "T", 1)
			when, err := time.Parse(time.RFC3339Nano, value)
			if err != nil {
				when, err = time.ParseInLocation("2006-01-02T15:04:05", value, w.opts.zone)
			}
			w.inWindow = err == nil && (w.opts.since.IsZero() || !when.Before(w.opts.since)) && (w.opts.until.IsZero() || !when.After(w.opts.until))
			if err != nil {
				w.unstamped++
			}
		} else if !w.inWindow {
			w.unstamped++
		}
		if !w.inWindow {
			return
		}
	}
	if w.opts.filter == nil || w.opts.filter.MatchString(line) {
		_, _ = io.WriteString(w.dst, line+newline)
	}
}

func logBoundary(raw string, now time.Time) (time.Time, error) {
	if raw == "" {
		return time.Time{}, nil
	}
	if duration, err := time.ParseDuration(raw); err == nil && duration > 0 && duration <= 30*24*time.Hour {
		return now.Add(-duration), nil
	}
	if timestamp, err := time.Parse(time.RFC3339Nano, raw); err == nil && !timestamp.After(now) {
		return timestamp, nil
	}
	return time.Time{}, fmt.Errorf("expected a past RFC3339 timestamp or duration such as 15m (max 720h)")
}
