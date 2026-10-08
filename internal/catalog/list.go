package catalog

import "strings"

func cleanList(items []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, t := range items {
		for _, p := range strings.Split(t, ",") {
			p = strings.TrimSpace(p)
			if p == "" || seen[p] {
				continue
			}
			seen[p] = true
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
