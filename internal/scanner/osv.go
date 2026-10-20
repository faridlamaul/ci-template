package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
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
			Vulnerabilities []struct {
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
			} `json:"vulnerabilities"`
			Groups []struct {
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

// ParseOSV converts an osv-scanner JSON report into findings, one per
// package and vulnerability.
func ParseOSV(raw []byte) ([]finding.Finding, error) { return parseOSV(raw, "") }

func parseOSV(raw []byte, dir string) ([]finding.Finding, error) {
	var rep osvReport
	if err := json.Unmarshal(raw, &rep); err != nil {
		return nil, fmt.Errorf("parse osv-scanner report: %w", err)
	}
	out := []finding.Finding{}
	for _, res := range rep.Results {
		file := relFile(res.Source.Path, dir)
		for _, p := range res.Packages {
			sev := map[string]string{}
			for _, g := range p.Groups {
				for _, id := range g.IDs {
					sev[id] = g.MaxSeverity
				}
			}
			for _, v := range p.Vulnerabilities {
				fixed := ""
			find:
				for _, a := range v.Affected {
					if a.Package.Name != p.Package.Name || a.Package.Ecosystem != p.Package.Ecosystem {
						continue
					}
					for _, r := range a.Ranges {
						if r.Type == "GIT" { // fixed holds a commit hash, not a version
							continue
						}
						for _, e := range r.Events {
							if e.Fixed != "" {
								fixed = e.Fixed
								break find
							}
						}
					}
				}
				out = append(out, finding.Finding{
					ID:           v.ID,
					Aliases:      v.Aliases,
					Scanner:      "osv-scanner",
					Category:     finding.CategorySCA,
					Severity:     osvSeverity(sev[v.ID]),
					File:         file,
					Message:      fmt.Sprintf("%s@%s is affected by %s", p.Package.Name, p.Package.Version, v.ID),
					Package:      p.Package.Name,
					Version:      p.Package.Version,
					FixedVersion: fixed,
					FixAvailable: fixed != "",
					Fingerprint:  finding.Fingerprint(v.ID, file, p.Package.Name+"@"+p.Package.Version),
				})
			}
		}
	}
	return out, nil
}

func (o *osv) args(output string) []string {
	// --output-file replaces the deprecated --output (osv-scanner v2.7.0).
	a := []string{"scan", "source", "-r", "--format", "json", "--output-file", output}
	if db := os.Getenv("SHIPGUARD_OSV_OFFLINE_DB"); db != "" {
		a = append(a, "--offline-vulnerabilities", "--local-db-path", db)
	}
	return append(a, ".")
}

func (o *osv) Scan(ctx context.Context, t Target) ([]finding.Finding, error) {
	ctx, cancel := withTimeout(ctx, t)
	defer cancel()

	output, err := tempReport(t, "osv")
	if err != nil {
		return nil, err
	}
	defer os.Remove(output)

	// Exit 128 means no packages were found: zero findings, not an error.
	noPackages := false
	err = Retry(ctx, 3, osvSleep, func() error {
		// Stderr is dropped: it can echo paths and package names.
		_, _, code, err := o.run(ctx, t.Dir, "osv-scanner", o.args(output)...)
		if err != nil {
			return fmt.Errorf("osv-scanner: %w", err)
		}
		switch code {
		case 0, 1:
			noPackages = false
			return nil
		case 128:
			noPackages = true
			return nil
		}
		return fmt.Errorf("osv-scanner exited with code %d", code)
	})
	if err != nil {
		return nil, err
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
