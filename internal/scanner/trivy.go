package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/faridlamaul/shipguard/internal/finding"
)

// trivySleep is the backoff sleep used between `trivy config` attempts; tests
// replace it.
var trivySleep = time.Sleep

// trivyCache returns the trivy cache directory under the target cache dir.
func trivyCache(t Target) string { return filepath.Join(t.CacheDir, "trivy") }

// trivySkipDirs maps the directory-shaped Exclude entries (ending in "/") to
// --skip-dirs flags; glob patterns are applied centrally on the findings.
func trivySkipDirs(t Target) []string {
	var a []string
	for _, e := range t.Exclude {
		if d := strings.TrimRight(e, "/"); strings.HasSuffix(e, "/") && d != "" {
			a = append(a, "--skip-dirs", d)
		}
	}
	return a
}

type trivyReport struct {
	Results []struct {
		Target            string `json:"Target"`
		Misconfigurations []struct {
			ID            string `json:"ID"`
			AVDID         string `json:"AVDID"`
			Title         string `json:"Title"`
			Message       string `json:"Message"`
			Severity      string `json:"Severity"`
			Status        string `json:"Status"`
			CauseMetadata struct {
				Resource  string `json:"Resource"`
				StartLine int    `json:"StartLine"`
			} `json:"CauseMetadata"`
		} `json:"Misconfigurations"`
		Licenses []struct {
			PkgName  string `json:"PkgName"`
			FilePath string `json:"FilePath"`
			Name     string `json:"Name"`
			Severity string `json:"Severity"`
		} `json:"Licenses"`
	} `json:"Results"`
}

func decodeTrivy(raw []byte) (trivyReport, error) {
	var rep trivyReport
	if err := json.Unmarshal(raw, &rep); err != nil {
		return rep, fmt.Errorf("parse trivy report: %w", err)
	}
	return rep, nil
}

// ParseTrivyConfig converts a `trivy config` JSON report into findings; only
// misconfigurations with Status FAIL are reported.
func ParseTrivyConfig(raw []byte) ([]finding.Finding, error) {
	rep, err := decodeTrivy(raw)
	if err != nil {
		return nil, err
	}
	out := []finding.Finding{}
	for _, res := range rep.Results {
		for _, m := range res.Misconfigurations {
			if m.Status != "FAIL" {
				continue
			}
			id := m.AVDID
			if id == "" {
				id = m.ID
			}
			sev, err := finding.ParseSeverity(strings.ToLower(m.Severity))
			if err != nil {
				sev = finding.Medium
			}
			key := m.CauseMetadata.Resource
			if key == "" {
				key = finding.NormalizeSnippet(m.Title)
			}
			msg := m.Message
			if msg == "" {
				msg = m.Title
			}
			out = append(out, finding.Finding{
				ID:          id,
				Scanner:     "trivy-config",
				Category:    finding.CategoryIaC,
				Severity:    sev,
				File:        filepath.ToSlash(res.Target),
				Line:        m.CauseMetadata.StartLine,
				Message:     msg,
				Fingerprint: finding.Fingerprint(id, filepath.ToSlash(res.Target), key),
			})
		}
	}
	return out, nil
}

// ParseTrivyLicense converts a `trivy fs --scanners license` JSON report into
// findings: high for a license in deny, info otherwise.
func ParseTrivyLicense(raw []byte, deny []string) ([]finding.Finding, error) {
	rep, err := decodeTrivy(raw)
	if err != nil {
		return nil, err
	}
	denied := map[string]bool{}
	for _, d := range deny {
		denied[finding.LicenseKey(d)] = true
	}
	out := []finding.Finding{}
	for _, res := range rep.Results {
		for _, l := range res.Licenses {
			file := filepath.ToSlash(l.FilePath)
			if file == "" {
				file = filepath.ToSlash(res.Target)
			}
			id := "license:" + l.Name
			sev := finding.Info
			if denied[finding.LicenseKey(l.Name)] {
				sev = finding.High
			}
			out = append(out, finding.Finding{
				ID:          id,
				Scanner:     "trivy-license",
				Category:    finding.CategorySCA,
				Severity:    sev,
				File:        file,
				Message:     fmt.Sprintf("%s uses license %s", l.PkgName, l.Name),
				Package:     l.PkgName,
				Fingerprint: finding.Fingerprint(id, file, l.PkgName),
			})
		}
	}
	return out, nil
}

type trivy struct {
	run      Runner
	name     string
	category finding.Category
	rawName  string
	retry    bool
	args     func(t Target, output string) []string
	parse    func(raw []byte, t Target) ([]finding.Finding, error)
}

// NewTrivyConfig returns the IaC scanner backed by `trivy config`.
func NewTrivyConfig(run Runner) Scanner {
	return &trivy{
		run: run, name: "trivy-config", category: finding.CategoryIaC, rawName: "trivy-config", retry: true,
		// `trivy config` has no --skip-db-update flag (it does not use the
		// vulnerability DB); the checks bundle is fetched into the cache dir.
		args: func(t Target, output string) []string {
			a := []string{"config", "--format", "json", "--output", output, "--cache-dir", trivyCache(t)}
			if repo := os.Getenv("SHIPGUARD_TRIVY_CHECKS_BUNDLE_REPOSITORY"); repo != "" {
				a = append(a, "--checks-bundle-repository", repo)
			}
			a = append(a, trivySkipDirs(t)...)
			return append(a, "--exit-code", "0", ".")
		},
		parse: func(raw []byte, _ Target) ([]finding.Finding, error) { return ParseTrivyConfig(raw) },
	}
}

// NewTrivyLicense returns the license scanner backed by `trivy fs --scanners license`.
func NewTrivyLicense(run Runner) Scanner {
	return &trivy{
		run: run, name: "trivy-license", category: finding.CategorySCA, rawName: "trivy-license",
		args: func(t Target, output string) []string {
			a := []string{"fs", "--scanners", "license", "--format", "json", "--output", output,
				"--cache-dir", trivyCache(t), "--skip-db-update"}
			a = append(a, trivySkipDirs(t)...)
			return append(a, "--exit-code", "0", ".")
		},
		parse: func(raw []byte, t Target) ([]finding.Finding, error) { return ParseTrivyLicense(raw, t.DenyLicenses) },
	}
}

func (s *trivy) Name() string               { return s.name }
func (s *trivy) Category() finding.Category { return s.category }

func (s *trivy) Scan(ctx context.Context, t Target) ([]finding.Finding, error) {
	ctx, cancel := withTimeout(ctx, t)
	defer cancel()

	output, err := tempReport(t, s.rawName)
	if err != nil {
		return nil, err
	}
	defer os.Remove(output)

	attempts := 1
	if s.retry { // config fetches the checks bundle over the network
		attempts = 3
	}
	err = Retry(ctx, attempts, trivySleep, func() error {
		// Stderr is dropped: it can echo paths and file contents.
		_, _, code, err := s.run(ctx, t.Dir, "trivy", s.args(t, output)...)
		if err != nil {
			return fmt.Errorf("%s: %w", s.name, err)
		}
		if code != 0 {
			return fmt.Errorf("%s exited with code %d", s.name, code)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(output)
	if err != nil {
		return nil, fmt.Errorf("read %s output: %w", s.name, err)
	}
	fs, err := s.parse(raw, t)
	if err != nil {
		return nil, err
	}
	if t.RawDir != "" {
		if err := writeRaw(t.RawDir, s.rawName, fs); err != nil {
			return nil, err
		}
	}
	return fs, nil
}
