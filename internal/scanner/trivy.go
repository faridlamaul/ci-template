package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/faridlamaul/shipguard/internal/finding"
)

// trivySleep is the backoff sleep used between DB download attempts; tests
// replace it.
var trivySleep = time.Sleep

// trivyDBReady records the cache dirs whose DB download already succeeded in
// this process, so the two trivy scanners download it once. Failures are not
// recorded, so a later scan retries.
var (
	trivyDBMu    sync.Mutex
	trivyDBReady = map[string]bool{}
)

func resetTrivyDB() {
	trivyDBMu.Lock()
	defer trivyDBMu.Unlock()
	trivyDBReady = map[string]bool{}
}

// trivyCache returns the trivy cache directory under the target cache dir.
func trivyCache(t Target) string { return filepath.Join(t.CacheDir, "trivy") }

// ensureTrivyDB downloads the trivy DB into the cache once per process
// (Retry(3) on failure). It is cheap after the first success. Concurrent
// callers serialize on the lock, so only one downloads.
func ensureTrivyDB(ctx context.Context, run Runner, t Target) error {
	cache := trivyCache(t)
	trivyDBMu.Lock()
	defer trivyDBMu.Unlock()
	if trivyDBReady[cache] {
		return nil
	}
	args := []string{"fs", "--download-db-only", "--cache-dir", cache}
	if repo := os.Getenv("SHIPGUARD_TRIVY_DB_REPOSITORY"); repo != "" {
		args = append(args, "--db-repository", repo)
	}
	err := Retry(ctx, 3, trivySleep, func() error {
		// Stderr is dropped: it can echo registry URLs and credentials hints.
		_, _, code, err := run(ctx, t.Dir, "trivy", args...)
		if err != nil {
			return fmt.Errorf("trivy db download: %w", err)
		}
		if code != 0 {
			return fmt.Errorf("trivy db download exited with code %d", code)
		}
		return nil
	})
	if err != nil {
		return err
	}
	trivyDBReady[cache] = true
	return nil
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

// licenseKey normalizes an SPDX id for deny matching: case-insensitive, and
// trivy's "-only" suffix (AGPL-3.0-only) is equal to the bare id (AGPL-3.0).
func licenseKey(s string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), "-only")
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
		denied[licenseKey(d)] = true
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
			if denied[licenseKey(l.Name)] {
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
	args     func(t Target, output string) []string
	parse    func(raw []byte, t Target) ([]finding.Finding, error)
}

// NewTrivyConfig returns the IaC scanner backed by `trivy config`.
func NewTrivyConfig(run Runner) Scanner {
	return &trivy{
		run: run, name: "trivy-config", category: finding.CategoryIaC, rawName: "trivy-config",
		// `trivy config` has no --skip-db-update flag (it does not use the
		// vulnerability DB); the checks bundle is fetched into the cache dir.
		args: func(t Target, output string) []string {
			a := []string{"config", "--format", "json", "--output", output, "--cache-dir", trivyCache(t)}
			for _, e := range t.Exclude {
				if d := strings.TrimRight(e, "/"); strings.HasSuffix(e, "/") && d != "" {
					a = append(a, "--skip-dirs", d)
				}
			}
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
			return []string{"fs", "--scanners", "license", "--format", "json", "--output", output,
				"--cache-dir", trivyCache(t), "--skip-db-update", "--exit-code", "0", "."}
		},
		parse: func(raw []byte, t Target) ([]finding.Finding, error) { return ParseTrivyLicense(raw, t.DenyLicenses) },
	}
}

func (s *trivy) Name() string               { return s.name }
func (s *trivy) Category() finding.Category { return s.category }

func (s *trivy) Scan(ctx context.Context, t Target) ([]finding.Finding, error) {
	ctx, cancel := withTimeout(ctx, t)
	defer cancel()

	if err := ensureTrivyDB(ctx, s.run, t); err != nil {
		return nil, err
	}
	output, err := tempReport(t, s.rawName)
	if err != nil {
		return nil, err
	}
	defer os.Remove(output)

	// Stderr is dropped: it can echo paths and file contents.
	_, _, code, err := s.run(ctx, t.Dir, "trivy", s.args(t, output)...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", s.name, err)
	}
	if code != 0 {
		return nil, fmt.Errorf("%s exited with code %d", s.name, code)
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
