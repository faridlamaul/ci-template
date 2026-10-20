package finding

import (
	"strings"

	"github.com/bmatcuk/doublestar/v4"
)

// FilterPaths drops findings whose File matches any exclude pattern. A pattern
// ending in "/" matches any file with that prefix; others are doublestar globs.
func FilterPaths(fs []Finding, exclude []string) []Finding {
	out := make([]Finding, 0, len(fs))
	for _, f := range fs {
		if !excluded(f.File, exclude) {
			out = append(out, f)
		}
	}
	return out
}

func excluded(file string, patterns []string) bool {
	for _, p := range patterns {
		if strings.HasSuffix(p, "/") {
			if strings.HasPrefix(file, p) {
				return true
			}
			continue
		}
		if ok, err := doublestar.Match(p, file); err == nil && ok {
			return true
		}
	}
	return false
}
