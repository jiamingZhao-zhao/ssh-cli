package audit

import (
	"bytes"
	"fmt"
	"os"
)

// scanReverse bounds memory by the largest accepted JSONL line, not file size
// or requested page. It also accepts a final record without a trailing newline.
func scanReverse(path string, fn func(Record)) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	offset := info.Size()
	var carry []byte
	block := make([]byte, 64<<10)
	for offset > 0 {
		n := int64(len(block))
		if n > offset {
			n = offset
		}
		offset -= n
		if _, err := f.ReadAt(block[:n], offset); err != nil {
			return err
		}
		buf := append(append([]byte(nil), block[:n]...), carry...)
		end := len(buf)
		for {
			i := bytes.LastIndexByte(buf[:end], '\n')
			if i < 0 {
				break
			}
			if rec, ok := decodeLine(string(buf[i+1 : end])); ok {
				fn(rec)
			}
			end = i
		}
		carry = append(carry[:0], buf[:end]...)
		if len(carry) > 512<<10 {
			return fmt.Errorf("audit line too long")
		}
	}
	if rec, ok := decodeLine(string(carry)); ok {
		fn(rec)
	}
	return nil
}
