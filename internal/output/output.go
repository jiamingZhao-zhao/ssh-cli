// Package output prints human tables and JSON in UTF-8.
package output

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode/utf8"

	"golang.org/x/term"
)

// Printer writes command results.
type Printer struct {
	JSON bool
	Out  io.Writer
	Err  io.Writer
}

// New returns a printer. Nil writers fall back to stdout and stderr.
func New(jsonOut bool, out, errw io.Writer) Printer {
	if out == nil {
		out = os.Stdout
	}
	if errw == nil {
		errw = os.Stderr
	}
	return Printer{JSON: jsonOut, Out: out, Err: errw}
}

// Emit writes v as indented JSON when JSON mode is on.
func (p Printer) Emit(v any) error {
	enc := json.NewEncoder(p.Out)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// Errorf prints a non-JSON error line.
func (p Printer) Errorf(format string, args ...any) {
	fmt.Fprintf(p.Err, "error: "+format+"\n", args...)
}

// Warningf prints a warning to stderr. Warnings stay off stdout so pipes stay clean.
func (p Printer) Warningf(format string, args ...any) {
	fmt.Fprintf(p.Err, "warning: "+format+"\n", args...)
}

// Table writes an aligned text table.
func (p Printer) Table(headers []string, rows [][]string) {
	widths := make([]int, len(headers))
	for i, h := range headers {
		widths[i] = displayWidth(h)
	}
	for _, row := range rows {
		for i := range headers {
			cell := ""
			if i < len(row) {
				cell = row[i]
			}
			if w := displayWidth(cell); w > widths[i] {
				widths[i] = w
			}
		}
	}
	writeRow := func(row []string) {
		var b strings.Builder
		for i := range headers {
			cell := ""
			if i < len(row) {
				cell = row[i]
			}
			if i > 0 {
				b.WriteString("  ")
			}
			b.WriteString(cell)
			if i < len(headers)-1 {
				pad := widths[i] - displayWidth(cell)
				if pad > 0 {
					b.WriteString(strings.Repeat(" ", pad))
				}
			}
		}
		fmt.Fprintln(p.Out, b.String())
	}
	writeRow(headers)
	writeRow(sep(widths))
	for _, row := range rows {
		writeRow(row)
	}
}

func sep(widths []int) []string {
	out := make([]string, len(widths))
	for i, w := range widths {
		if w < 1 {
			w = 1
		}
		out[i] = strings.Repeat("-", w)
	}
	return out
}

func displayWidth(s string) int { return utf8.RuneCountInString(s) }

// IsTerminal reports whether w is an interactive console.
func IsTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	return term.IsTerminal(int(f.Fd()))
}

// Paint wraps s in an ANSI color when enabled. color is red, orange, yellow, or green.
func Paint(enabled bool, color, s string) string {
	if !enabled || s == "" {
		return s
	}
	code := ""
	switch strings.ToLower(color) {
	case "red":
		code = "31"
	case "orange":
		code = "38;5;208"
	case "yellow":
		code = "33"
	case "green":
		code = "32"
	default:
		return s
	}
	return "\033[" + code + "m" + s + "\033[0m"
}
