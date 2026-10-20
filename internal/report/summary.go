package report

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/faridlamaul/shipguard/internal/finding"
	"github.com/faridlamaul/shipguard/internal/policy"
)

// Summary renders the gate decision as Markdown. maxBytes <= 0 means no limit;
// otherwise the blocking-findings table is cut from the end so the result is
// at most maxBytes bytes. Only id, category, severity, location and message of
// a finding are rendered.
func Summary(r finding.Result, d policy.Decision, maxBytes int) string {
	var head strings.Builder
	fmt.Fprintf(&head, "## shipguard: %s\n\n", strings.ToUpper(d.Result))
	fmt.Fprintf(&head, "%d blocking, %d new, %d total findings.\n\n", len(d.Blocking), d.New, d.Total)
	if r.PolicyDefaults {
		head.WriteString("No shipguard config file found: built-in defaults applied.\n\n")
	}
	if r.PolicyChanged {
		head.WriteString("### ⚠ Policy changed in this PR\n\n")
		head.WriteString("The policy was modified by this change. Review it before merging.\n\n")
		if r.PolicyDiff != "" {
			diff, cut := strings.TrimRight(r.PolicyDiff, "\n"), false
			if len(diff) > maxDiffBytes {
				diff, cut = cutUTF8(diff, maxDiffBytes), true
			}
			fence := strings.Repeat("`", max(3, longestRun(diff, '`')+1))
			head.WriteString(fence + "diff\n" + diff + "\n" + fence + "\n")
			if cut {
				head.WriteString("(diff truncated)\n")
			}
			head.WriteString("\n")
		}
	}
	if len(d.ScannerErrors) > 0 {
		head.WriteString("### Scanner errors\n\n")
		for _, s := range d.ScannerErrors {
			fmt.Fprintf(&head, "- %s: %s\n", cell(s.Name), cell(s.Error))
		}
		head.WriteString("\n")
	}

	var table string
	var rows []string
	if len(d.Blocking) > 0 {
		table = "### Blocking findings\n\n| Severity | Category | ID | Location | Message |\n|---|---|---|---|---|\n"
		for _, f := range d.Blocking {
			rows = append(rows, fmt.Sprintf("| %s | %s | %s | %s | %s |\n",
				f.Severity, cell(string(f.Category)), cell(f.ID), cell(location(f)), cell(f.Message)))
		}
	}

	var tail strings.Builder
	if len(d.Expired) > 0 {
		tail.WriteString("\n### Expired exceptions\n\n")
		for _, e := range d.Expired {
			fmt.Fprintf(&tail, "- %s", cell(e.ID))
			if e.Path != "" {
				fmt.Fprintf(&tail, " (%s)", cell(e.Path))
			}
			fmt.Fprintf(&tail, " expired %s\n", e.Expires.Format("2006-01-02"))
		}
	}
	fmt.Fprintf(&tail, "\n%s\n", counts(r, d))

	build := func(k int) string {
		var b strings.Builder
		b.WriteString(head.String())
		if table != "" {
			b.WriteString(table)
			for _, row := range rows[:k] {
				b.WriteString(row)
			}
			if k < len(rows) {
				b.WriteString(moreLine(len(rows) - k))
			}
		}
		b.WriteString(tail.String())
		return b.String()
	}

	full := build(len(rows))
	if maxBytes <= 0 || len(full) <= maxBytes {
		return full
	}
	// Largest k whose output fits: base size with no rows, plus the first k
	// rows, plus the "more" line for the remaining ones.
	base := len(build(0)) - len(moreLine(len(rows)))
	fit, sum := -1, 0
	for k := 0; k < len(rows); k++ {
		if base+sum+len(moreLine(len(rows)-k)) > maxBytes {
			break
		}
		fit = k
		sum += len(rows[k])
	}
	if fit >= 0 {
		return build(fit)
	}
	return cutUTF8(build(0), maxBytes)
}

const maxDiffBytes = 4000

// longestRun returns the length of the longest run of c in s.
func longestRun(s string, c byte) int {
	best, cur := 0, 0
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			cur++
			best = max(best, cur)
		} else {
			cur = 0
		}
	}
	return best
}

func moreLine(n int) string {
	return fmt.Sprintf("\n…and %d more findings in .shipguard/findings.json\n", n)
}

func location(f finding.Finding) string {
	if f.Line > 0 {
		return fmt.Sprintf("%s:%d", f.File, f.Line)
	}
	return f.File
}

func counts(r finding.Result, d policy.Decision) string {
	existing := 0
	for _, f := range r.Findings {
		if f.Status == finding.StatusExisting {
			existing++
		}
	}
	for _, f := range d.Suppressed {
		if f.Status == finding.StatusExisting {
			existing--
		}
	}
	for _, f := range d.Blocking {
		if f.Status == finding.StatusExisting {
			existing--
		}
	}
	if existing < 0 {
		existing = 0
	}
	below := d.Total - len(d.Blocking) - len(d.Suppressed) - existing
	if below < 0 {
		below = 0
	}
	return fmt.Sprintf("Existing: %d · Suppressed: %d · Below threshold: %d", existing, len(d.Suppressed), below)
}

// cell makes s safe for a Markdown table cell.
func cell(s string) string {
	s = strings.NewReplacer("\r\n", " ", "\n", " ", "\r", " ", "|", `\|`).Replace(s)
	return s
}

// cutUTF8 shortens s to at most n bytes without splitting a rune.
func cutUTF8(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}
