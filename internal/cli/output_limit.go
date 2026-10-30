package cli

import "io"

// Consume all bytes so output limits never close the SSH channel early.
// Limits are independent for stdout/stderr and count retained bytes, including LF.
type outputLimiter struct {
	dst               io.Writer
	maxLine, maxTotal int
	line, total       int
	cut               bool
	skipUTF8          int
}

func (w *outputLimiter) Write(p []byte) (int, error) {
	if w.maxLine == 0 && w.maxTotal == 0 {
		return w.dst.Write(p)
	}
	b := make([]byte, 0, len(p))
	for _, c := range p {
		keep := (w.maxTotal == 0 || w.total < w.maxTotal) && (c == '\n' || w.maxLine == 0 || w.line < w.maxLine)
		if w.skipUTF8 > 0 {
			if c&0xc0 == 0x80 {
				keep = false
				w.skipUTF8--
			} else {
				w.skipUTF8 = 0
			}
		}
		width := 1
		if c >= 0xc2 && c <= 0xdf {
			width = 2
		}
		if c >= 0xe0 && c <= 0xef {
			width = 3
		}
		if c >= 0xf0 && c <= 0xf4 {
			width = 4
		}
		if width > 1 && ((w.maxTotal > 0 && w.total+width > w.maxTotal) || (w.maxLine > 0 && w.line+width > w.maxLine)) {
			keep = false
			w.skipUTF8 = width - 1
		}
		if keep {
			b = append(b, c)
			w.total++
		} else {
			w.cut = true
		}
		if c == '\n' {
			w.line = 0
		} else {
			w.line++
		}
	}
	if len(b) > 0 {
		if _, err := w.dst.Write(b); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}
