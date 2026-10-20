package finding

import "strings"

// LicenseKey normalizes an SPDX license id for deny matching: lowercased, with
// one trailing "-only", "-or-later" or "+" removed, so a deny entry matches the
// whole family (GPL-3.0 covers GPL-3.0-only, GPL-3.0-or-later and GPL-3.0+).
func LicenseKey(spdx string) string {
	s := strings.ToLower(strings.TrimSpace(spdx))
	for _, suf := range []string{"-or-later", "-only", "+"} {
		if strings.HasSuffix(s, suf) {
			return strings.TrimSuffix(s, suf)
		}
	}
	return s
}
