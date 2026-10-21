package scanner

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/faridlamaul/shipguard/internal/finding"
)

// osvSleep is the backoff sleep used between osv-scanner attempts; tests
// replace it.
var osvSleep = time.Sleep

type osv struct{ run Runner }

// NewOSV returns the SCA scanner backed by the osv-scanner binary. When
// SHIPGUARD_OSV_OFFLINE_DB is set it scans against that local database.
func NewOSV(run Runner) Scanner { return &osv{run: run} }

func (o *osv) Name() string               { return "osv-scanner" }
func (o *osv) Category() finding.Category { return finding.CategorySCA }

type osvReport struct {
	Results []struct {
		Source struct {
			Path string `json:"path"`
		} `json:"source"`
		Packages []struct {
			Package struct {
				Name      string `json:"name"`
				Version   string `json:"version"`
				Ecosystem string `json:"ecosystem"`
			} `json:"package"`
			Vulnerabilities []osvVuln `json:"vulnerabilities"`
			Groups          []struct {
				IDs         []string `json:"ids"`
				MaxSeverity string   `json:"max_severity"`
			} `json:"groups"`
		} `json:"packages"`
	} `json:"results"`
}

// osvSeverity maps a CVSS score to a severity; a missing or unparsable score
// is medium.
func osvSeverity(maxSeverity string) finding.Severity {
	score, err := strconv.ParseFloat(maxSeverity, 64)
	switch {
	case err != nil || score <= 0:
		return finding.Medium
	case score >= 9.0:
		return finding.Critical
	case score >= 7.0:
		return finding.High
	case score >= 4.0:
		return finding.Medium
	}
	return finding.Low
}

// ParseOSV converts an osv-scanner JSON report into findings: one per file,
// package version and vulnerability (see parseOSV).
func ParseOSV(raw []byte) ([]finding.Finding, error) { return parseOSV(raw, "") }

type osvVuln struct {
	ID       string   `json:"id"`
	Aliases  []string `json:"aliases"`
	Affected []struct {
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
		Ranges []struct {
			Type   string `json:"type"`
			Events []struct {
				Introduced   string `json:"introduced"`
				Fixed        string `json:"fixed"`
				LastAffected string `json:"last_affected"`
			} `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
}

// parseOSV converts the report into findings without duplicates:
//   - advisories osv-scanner groups as one vulnerability (e.g. a PYSEC and a
//     GHSA id sharing aliases) become one finding, keeping the group's first
//     id and the union of the other ids and aliases;
//   - the same file, package, version and id reported twice (osv-scanner
//     2.7.0 reports requirements.txt once as "lockfile" with version 5.3 and
//     once as "unknown" with 5.3.0) is kept once; numeric versions that
//     differ only by trailing ".0" components are the same version.
func parseOSV(raw []byte, dir string) ([]finding.Finding, error) {
	var rep osvReport
	if err := json.Unmarshal(raw, &rep); err != nil {
		return nil, fmt.Errorf("parse osv-scanner report: %w", err)
	}
	out := []finding.Finding{}
	seen := map[string]int{} // dedupe key -> index in out
	for _, res := range rep.Results {
		file := relFile(res.Source.Path, dir)
		for _, p := range res.Packages {
			byID := make(map[string]osvVuln, len(p.Vulnerabilities))
			for _, v := range p.Vulnerabilities {
				byID[v.ID] = v
			}
			sev := map[string]string{}
			group := map[string][]string{} // id -> ids of its group present in the report
			for _, g := range p.Groups {
				var ids []string
				for _, id := range g.IDs {
					if _, ok := byID[id]; ok {
						ids = append(ids, id)
					}
				}
				for _, id := range g.IDs {
					sev[id] = g.MaxSeverity
					if _, done := group[id]; !done && len(ids) > 0 {
						group[id] = ids
					}
				}
			}
			emitted := map[string]bool{}
			for _, v := range p.Vulnerabilities {
				if emitted[v.ID] {
					continue
				}
				ids := group[v.ID]
				if len(ids) == 0 {
					ids = []string{v.ID}
				}
				keep := ids[0]
				var aliases []string
				fixed := ""
				for _, id := range ids {
					emitted[id] = true
					m := byID[id]
					if id != keep {
						aliases = append(aliases, id)
					}
					aliases = append(aliases, m.Aliases...)
					if fixed == "" {
						fixed = osvFixed(m, p.Package.Name, p.Package.Version, p.Package.Ecosystem)
					}
				}
				f := finding.Finding{
					ID:           keep,
					Aliases:      mergeAliases(nil, aliases, keep),
					Scanner:      "osv-scanner",
					Category:     finding.CategorySCA,
					Severity:     osvSeverity(sev[keep]),
					File:         file,
					Message:      fmt.Sprintf("%s@%s is affected by %s", p.Package.Name, p.Package.Version, keep),
					Package:      p.Package.Name,
					Version:      p.Package.Version,
					FixedVersion: fixed,
					FixAvailable: fixed != "",
					Fingerprint:  finding.Fingerprint(keep, file, p.Package.Name+"@"+p.Package.Version),
				}
				key := strings.Join([]string{file, p.Package.Ecosystem, p.Package.Name, normVersion(p.Package.Version), keep}, "\x00")
				if i, ok := seen[key]; ok {
					out[i].Aliases = mergeAliases(out[i].Aliases, f.Aliases, keep)
					continue
				}
				seen[key] = len(out)
				out = append(out, f)
			}
		}
	}
	return out, nil
}

// osvFixed returns the fixed version for the installed version of the
// package, ignoring GIT ranges, whose "fixed" holds a commit hash: the
// "fixed" closing the [introduced, fixed) interval that contains version.
// When version cannot be placed in any interval (unparsable, or outside every
// one) it returns the first fixed version, so a fix is reported whenever one
// exists (fix_available_only fails closed).
func osvFixed(v osvVuln, name, version, ecosystem string) string {
	first := ""
	for _, a := range v.Affected {
		if a.Package.Ecosystem != ecosystem || osvName(a.Package.Name, ecosystem) != osvName(name, ecosystem) {
			continue
		}
		for _, r := range a.Ranges {
			if r.Type == "GIT" {
				continue
			}
			introduced := "0"
			for _, e := range r.Events {
				switch {
				case e.Introduced != "":
					introduced = e.Introduced
				case e.Fixed != "":
					if first == "" {
						first = e.Fixed
					}
					if versionIn(version, introduced, e.Fixed) {
						return e.Fixed
					}
					introduced = "0"
				}
			}
		}
	}
	return first
}

var pypiSeparators = regexp.MustCompile(`[-_.]+`)

// osvName normalizes a package name the way OSV compares it: PyPI names per
// PEP 503 (lowercase, runs of "-", "_" and "." become "-"); other ecosystems
// are compared exactly.
func osvName(name, ecosystem string) string {
	if ecosystem == "PyPI" {
		return pypiSeparators.ReplaceAllString(strings.ToLower(name), "-")
	}
	return name
}

// versionIn reports whether version lies in [introduced, fixed); introduced
// "0" means from the beginning. Unparsable versions are in no interval.
func versionIn(version, introduced, fixed string) bool {
	if introduced != "0" {
		if c, ok := compareVersions(version, introduced); !ok || c < 0 {
			return false
		}
	}
	c, ok := compareVersions(version, fixed)
	return ok && c < 0
}

// compareVersions is a small ecosystem-agnostic comparator. Versions are
// split into release, pre-release (after the first "-") and build metadata
// (after "+", ignored); parts split on "." and "-"; numeric segments compare
// numerically, others lexically, and a missing release segment is 0. A
// version with a pre-release sorts before the same release. A leading "v" is
// dropped. ok is false when either version is unparsable: empty, an empty
// segment, or a release that does not start with a number.
func compareVersions(a, b string) (int, bool) {
	ar, ap, ok := splitVersion(a)
	if !ok {
		return 0, false
	}
	br, bp, ok := splitVersion(b)
	if !ok {
		return 0, false
	}
	if c := compareSegments(ar, br, "0"); c != 0 {
		return c, true
	}
	switch {
	case ap == nil && bp == nil:
		return 0, true
	case ap == nil:
		return 1, true
	case bp == nil:
		return -1, true
	}
	return compareSegments(ap, bp, ""), true
}

func splitVersion(v string) (release, pre []string, ok bool) {
	v = strings.TrimPrefix(v, "v")
	v, _, _ = strings.Cut(v, "+")
	r, p, hasPre := strings.Cut(v, "-")
	release = strings.Split(r, ".")
	if _, err := strconv.ParseUint(release[0], 10, 64); err != nil {
		return nil, nil, false
	}
	if hasPre {
		pre = strings.FieldsFunc(p, func(c rune) bool { return c == '.' || c == '-' })
		if len(pre) == 0 {
			return nil, nil, false
		}
	}
	for _, s := range append(slices.Clone(release), pre...) {
		if s == "" {
			return nil, nil, false
		}
	}
	return release, pre, true
}

// compareSegments compares segment lists; a missing segment is pad.
func compareSegments(a, b []string, pad string) int {
	for i := range max(len(a), len(b)) {
		x, y := pad, pad
		if i < len(a) {
			x = a[i]
		}
		if i < len(b) {
			y = b[i]
		}
		xn, xerr := strconv.ParseUint(x, 10, 64)
		yn, yerr := strconv.ParseUint(y, 10, 64)
		switch {
		case xerr == nil && yerr == nil:
			if c := cmp.Compare(xn, yn); c != 0 {
				return c
			}
		default:
			if c := strings.Compare(x, y); c != 0 {
				return c
			}
		}
	}
	return 0
}

// mergeAliases returns the sorted union of a and b without self.
func mergeAliases(a, b []string, self string) []string {
	var out []string
	for _, x := range append(slices.Clone(a), b...) {
		if x != self && !slices.Contains(out, x) {
			out = append(out, x)
		}
	}
	sort.Strings(out)
	return out
}

var numericVersion = regexp.MustCompile(`^[0-9]+(\.[0-9]+)*$`)

// normVersion drops trailing ".0" components of a numeric version, so 5.3
// and 5.3.0 compare equal; other versions are returned unchanged.
func normVersion(v string) string {
	if !numericVersion.MatchString(v) {
		return v
	}
	for strings.HasSuffix(v, ".0") {
		v = strings.TrimSuffix(v, ".0")
	}
	return v
}

// osvConfig is an empty osv-scanner config. Passed with --config it replaces
// any osv-scanner.toml in the repository.
const osvConfig = ""

// osvExcludes returns the --x-exclude values for the directory-shaped
// excludes (osv-scanner 2.7.0): "dir/" becomes the plain value "dir" (a path
// relative to the scan root, matched exactly) and "**/X/**" becomes "g:**/X"
// ("g:" globs are matched against the path from the filesystem root, so rooted
// globs cannot be written). Every other form (file names, "web/*", rooted
// globs) only filters the findings after the scan: osv-scanner still reads
// those files, and an unreadable lockfile there fails the scan.
func osvExcludes(exclude []string) []string {
	var out []string
	for _, e := range exclude {
		var v string
		switch {
		case strings.HasSuffix(e, "/**"):
			if d := strings.TrimSuffix(e, "/**"); strings.HasPrefix(d, "**/") && !strings.ContainsAny(d[3:], "*?[{\\") {
				v = "g:" + d
			}
		case strings.HasSuffix(e, "/"):
			if d := strings.TrimSuffix(e, "/"); d != "" && !strings.ContainsAny(d, "*?[{\\") {
				v = d
			}
		}
		if v != "" && !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	return out
}

func (o *osv) args(output, config string, exclude []string) []string {
	// --output-file replaces the deprecated --output (osv-scanner v2.7.0).
	// Policy lives only in .shipguard.yaml: --config overrides every
	// osv-scanner.toml, and --no-ignore stops .gitignore from hiding
	// lockfiles; directory excludes keep osv-scanner out of those trees and
	// all excludes are applied to the findings.
	a := []string{"scan", "source", "-r", "--format", "json", "--output-file", output, "--config", config, "--no-ignore"}
	if db := os.Getenv("SHIPGUARD_OSV_OFFLINE_DB"); db != "" {
		a = append(a, "--offline-vulnerabilities", "--local-db-path", db)
	}
	for _, e := range osvExcludes(exclude) {
		a = append(a, "--x-exclude", e)
	}
	return append(a, ".")
}

// osvExtractionFailed reports whether osv-scanner could not parse a manifest
// or lockfile. It says so only on stderr and still exits 0, 1 or 128. Any such
// error fails the scan: the stderr path text comes from the repository (raw,
// with newlines allowed), so it is never used to decide that an error is
// harmless. Excluded directories are not walked at all (--x-exclude), so an
// error cannot legitimately come from them.
func osvExtractionFailed(stderr []byte) bool {
	return bytes.Contains(stderr, []byte("Error during extraction")) || bytes.Contains(stderr, []byte("could not extract"))
}

func (o *osv) Scan(ctx context.Context, t Target) ([]finding.Finding, error) {
	ctx, cancel := withTimeout(ctx, t)
	defer cancel()

	output, err := tempReport(t, "osv")
	if err != nil {
		return nil, err
	}
	defer os.Remove(output)
	work, err := tempDir(t, "osv")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(work)
	config := filepath.Join(work, "osv-scanner.toml")
	if err := os.WriteFile(config, []byte(osvConfig), 0o600); err != nil {
		return nil, fmt.Errorf("write osv-scanner config: %w", err)
	}

	// Exit 128 means no packages were found: zero findings, not an error.
	noPackages, extractFailed, exitCode := false, false, 0
	err = Retry(ctx, 3, osvSleep, func() error {
		// Stderr is only inspected, never surfaced: it can echo paths and
		// package names.
		_, stderr, code, err := o.run(ctx, t.Dir, "osv-scanner", o.args(output, config, t.Exclude)...)
		if err != nil {
			return fmt.Errorf("osv-scanner: %w", err)
		}
		switch code {
		case 0, 1, 128:
			// Deterministic, so not retried.
			extractFailed = osvExtractionFailed(stderr)
			noPackages = code == 128
			exitCode = code
			return nil
		}
		return fmt.Errorf("osv-scanner exited with code %d", code)
	})
	if err != nil {
		return nil, err
	}
	if extractFailed {
		return nil, errors.New("osv-scanner could not extract one or more lockfiles; fix them, or exclude their directory in paths.exclude (directory entries ending in / or **/name/**)")
	}

	fs := []finding.Finding{}
	if !noPackages {
		raw, err := os.ReadFile(output)
		if err != nil {
			return nil, fmt.Errorf("read osv-scanner output: %w", err)
		}
		if err := checkReport("osv-scanner", raw, exitCode); err != nil {
			return nil, err
		}
		if fs, err = parseOSV(raw, t.Dir); err != nil {
			return nil, err
		}
		// Exit 1 means vulnerabilities were found; a report without any is
		// not trustworthy.
		if exitCode == 1 && len(fs) == 0 {
			return nil, errors.New("osv-scanner exited with code 1 but its report has no vulnerabilities")
		}
	}
	if t.RawDir != "" {
		if err := writeRaw(t.RawDir, "osv", fs); err != nil {
			return nil, err
		}
	}
	return fs, nil
}
