// Package detect picks the language of a project directory.
package detect

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/faridlamaul/shipguard/internal/ci"
	"github.com/faridlamaul/shipguard/internal/policy"
)

// Detect selects the language for dir (markers are checked in dir only) and
// its toolchain version. cfg.Language selects directly; cfg.Version overrides
// the detected version.
func Detect(dir string, cfg policy.CIConfig, langs []ci.Language, defaults map[string]string) (ci.Language, ci.Detection, error) {
	var l ci.Language
	if cfg.Language != "" {
		name := cfg.Language
		if name == "golang" {
			name = "go"
		}
		for _, c := range langs {
			if c.Name() == name {
				l = c
				break
			}
		}
		if l == nil {
			return nil, ci.Detection{}, fmt.Errorf("unknown ci.language %q", cfg.Language)
		}
		if len(present(dir, l)) == 0 {
			return nil, ci.Detection{}, fmt.Errorf("ci.language %q: none of %s found in %s",
				cfg.Language, strings.Join(l.Markers(), ", "), dir)
		}
	} else {
		var found []string
		for _, c := range langs {
			if m := present(dir, c); len(m) > 0 {
				found = append(found, m...)
				l = c
			}
		}
		matched := 0
		for _, c := range langs {
			if len(present(dir, c)) > 0 {
				matched++
			}
		}
		switch {
		case matched == 0:
			var all []string
			for _, c := range langs {
				all = append(all, c.Markers()...)
			}
			sort.Strings(all)
			return nil, ci.Detection{}, fmt.Errorf("no language detected in %s: looked for %s; set ci.language",
				dir, strings.Join(all, ", "))
		case matched > 1:
			return nil, ci.Detection{}, fmt.Errorf("ambiguous language in %s: found %s; set ci.language",
				dir, strings.Join(found, ", "))
		}
	}
	if cfg.Version != "" {
		return l, ci.Detection{Language: l.Name(), Version: cfg.Version, Source: "config"}, nil
	}
	det, err := l.Detect(dir, defaults)
	if err != nil {
		return nil, ci.Detection{}, fmt.Errorf("detect %s version: %w", l.Name(), err)
	}
	return l, det, nil
}

// present returns the markers of l that exist in dir.
func present(dir string, l ci.Language) []string {
	var out []string
	for _, m := range l.Markers() {
		if _, err := os.Stat(filepath.Join(dir, m)); err == nil {
			out = append(out, m)
		}
	}
	return out
}
