package cli

import "encoding/json"

// limitRecords bounds serialized output without corrupting names, timestamps,
// key fingerprints or UTF-8. Each JSON record is indivisible; the caller must
// expose truncated. maxTotal counts records, not the surrounding JSON envelope.
func limitRecords[T any](records []T, maxLine, maxTotal int) ([]T, bool) {
	if maxLine == 0 && maxTotal == 0 {
		return records, false
	}
	result := make([]T, 0, len(records))
	total, truncated := 0, false
	for _, record := range records {
		data, err := json.Marshal(record)
		if err != nil {
			truncated = true
			continue
		}
		if maxLine > 0 && len(data) > maxLine {
			truncated = true
			continue
		}
		if maxTotal > 0 && total+len(data) > maxTotal {
			truncated = true
			break
		}
		result = append(result, record)
		total += len(data)
	}
	return result, truncated
}
