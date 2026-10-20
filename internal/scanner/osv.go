package scanner

import (
	"bytes"
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
				Fixed string `json:"fixed"`
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
						fixed = osvFixed(m, p.Package.Name, p.Package.Ecosystem)
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

// osvFixed returns the first fixed version for the package, ignoring GIT
// ranges, whose "fixed" holds a commit hash.
func osvFixed(v osvVuln, name, ecosystem string) string {
	for _, a := range v.Affected {
		if a.Package.Name != name || a.Package.Ecosystem != ecosystem {
			continue
		}
		for _, r := range a.Ranges {
			if r.Type == "GIT" {
				continue
			}
			for _, e := range r.Events {
				if e.Fixed != "" {
					return e.Fixed
				}
			}
		}
	}
	return ""
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
// any osv-scanner.toml in the repository (R-C2).
const osvConfig = ""

func (o *osv) args(output, config string) []string {
	// --output-file replaces the deprecated --output (osv-scanner v2.7.0).
	// Policy lives only in .shipguard.yaml (R-C2): --config overrides every
	// osv-scanner.toml, and --no-ignore stops .gitignore from hiding
	// lockfiles; shipguard's excludes are applied to the findings.
	a := []string{"scan", "source", "-r", "--format", "json", "--output-file", output, "--config", config, "--no-ignore"}
	if db := os.Getenv("SHIPGUARD_OSV_OFFLINE_DB"); db != "" {
		a = append(a, "--offline-vulnerabilities", "--local-db-path", db)
	}
	return append(a, ".")
}

// osvExtractionFailed reports whether osv-scanner could not parse a manifest
// or lockfile. It says so only on stderr and still exits 0, 1 or 128.
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
	noPackages, extractFailed := false, false
	err = Retry(ctx, 3, osvSleep, func() error {
		// Stderr is only inspected, never surfaced: it can echo paths and
		// package names.
		_, stderr, code, err := o.run(ctx, t.Dir, "osv-scanner", o.args(output, config)...)
		if err != nil {
			return fmt.Errorf("osv-scanner: %w", err)
		}
		switch code {
		case 0, 1, 128:
			// Deterministic, so not retried.
			extractFailed = osvExtractionFailed(stderr)
			noPackages = code == 128
			return nil
		}
		return fmt.Errorf("osv-scanner exited with code %d", code)
	})
	if err != nil {
		return nil, err
	}
	if extractFailed {
		return nil, errors.New("osv-scanner could not extract one or more manifests or lockfiles; fix or exclude them")
	}

	fs := []finding.Finding{}
	if !noPackages {
		raw, err := os.ReadFile(output)
		if err != nil {
			return nil, fmt.Errorf("read osv-scanner output: %w", err)
		}
		if fs, err = parseOSV(raw, t.Dir); err != nil {
			return nil, err
		}
	}
	if t.RawDir != "" {
		if err := writeRaw(t.RawDir, "osv", fs); err != nil {
			return nil, err
		}
	}
	return fs, nil
}
