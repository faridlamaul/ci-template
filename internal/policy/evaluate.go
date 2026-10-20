package policy

import (
	"strings"
	"time"

	"github.com/bmatcuk/doublestar/v4"

	"github.com/faridlamaul/shipguard/internal/finding"
)

const licensePrefix = "license:"

// Decision is the outcome of evaluating a Result against a Config.
type Decision struct {
	Result        string            // "pass" | "fail" | "audit"
	Blocking      []finding.Finding // above threshold, not suppressed, and (not PR or Status=="new")
	Suppressed    []finding.Finding
	Expired       []Exception // matched a finding but past expiry
	New, Total    int
	ScannerErrors []finding.ScannerRun
	audit         bool
}

// Evaluate applies thresholds and exceptions to r. On a PR only findings with
// Status "new" can block. An exception is active until Expires + 24h.
func Evaluate(r finding.Result, cfg Config, pr bool, now time.Time) Decision {
	d := Decision{Total: len(r.Findings), audit: cfg.Mode == "audit"}
	for _, s := range r.Scanners {
		if s.Status == "error" {
			d.ScannerErrors = append(d.ScannerErrors, s)
		}
	}
	expired := map[int]bool{}
	for _, f := range r.Findings {
		if f.Status == finding.StatusNew {
			d.New++
		}
		active := false
		for i, e := range cfg.Exceptions {
			if !matches(e, f) {
				continue
			}
			if now.Before(e.Expires.Add(24 * time.Hour)) {
				active = true
			} else {
				expired[i] = true
			}
		}
		if active {
			d.Suppressed = append(d.Suppressed, f)
			continue
		}
		if pr && f.Status != finding.StatusNew {
			continue
		}
		if blocks(f, cfg) {
			d.Blocking = append(d.Blocking, f)
		}
	}
	for i, e := range cfg.Exceptions {
		if expired[i] {
			d.Expired = append(d.Expired, e)
		}
	}
	switch {
	case len(d.ScannerErrors) > 0:
		d.Result = "fail"
	case d.audit:
		d.Result = "audit"
	case len(d.Blocking) > 0:
		d.Result = "fail"
	default:
		d.Result = "pass"
	}
	return d
}

// ExitCode maps the decision to a process exit code: any scanner error 2,
// blocking findings in enforce mode 1, otherwise 0.
func (d Decision) ExitCode() int {
	switch {
	case len(d.ScannerErrors) > 0:
		return 2
	case len(d.Blocking) > 0 && !d.audit:
		return 1
	}
	return 0
}

func matches(e Exception, f finding.Finding) bool {
	if e.ID != f.ID && e.ID != f.Fingerprint && !contains(f.Aliases, e.ID) {
		return false
	}
	if e.Path == "" || e.Path == f.File {
		return true
	}
	ok, err := doublestar.Match(e.Path, f.File)
	return err == nil && ok
}

func contains(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}

func blocks(f finding.Finding, cfg Config) bool {
	t, ok := cfg.Policy.FailOn[f.Category]
	if !ok {
		return false
	}
	if strings.HasPrefix(f.ID, licensePrefix) && !licenseDenied(strings.TrimPrefix(f.ID, licensePrefix), cfg) {
		return false
	}
	switch {
	case t.Any:
		return true
	case f.Severity < t.Severity:
		return false
	case t.FixAvailableOnly:
		return f.FixAvailable
	}
	return true
}

func licenseDenied(spdx string, cfg Config) bool {
	for _, d := range cfg.Scanners.SCA.Licenses.Deny {
		if finding.LicenseKey(d) == finding.LicenseKey(spdx) {
			return true
		}
	}
	return false
}
