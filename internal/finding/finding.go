// Package finding defines the unified finding model shared by all scanners.
package finding

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Severity ranks a finding; higher is more severe.
type Severity int

const (
	Info     Severity = 0
	Low      Severity = 1
	Medium   Severity = 2
	High     Severity = 3
	Critical Severity = 4
)

var severityNames = map[Severity]string{
	Info: "info", Low: "low", Medium: "medium", High: "high", Critical: "critical",
}

// String returns the lowercase name of the severity.
func (s Severity) String() string {
	if n, ok := severityNames[s]; ok {
		return n
	}
	return fmt.Sprintf("severity(%d)", int(s))
}

// ParseSeverity parses a lowercase severity name.
func ParseSeverity(s string) (Severity, error) {
	for sev, name := range severityNames {
		if name == s {
			return sev, nil
		}
	}
	return Info, fmt.Errorf("invalid severity %q (want critical|high|medium|low|info)", s)
}

// MarshalText implements encoding.TextMarshaler.
func (s Severity) MarshalText() ([]byte, error) {
	n, ok := severityNames[s]
	if !ok {
		return nil, fmt.Errorf("invalid severity %d", int(s))
	}
	return []byte(n), nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (s *Severity) UnmarshalText(b []byte) error {
	v, err := ParseSeverity(string(b))
	if err != nil {
		return err
	}
	*s = v
	return nil
}

// Category is the kind of scan that produced a finding.
type Category string

const (
	CategorySecrets Category = "secrets"
	CategorySAST    Category = "sast"
	CategorySCA     Category = "sca"
	CategoryIaC     Category = "iac"
)

// Status marks a finding relative to the base ref ("" when not diffed).
type Status string

const (
	StatusNone     Status = ""
	StatusNew      Status = "new"
	StatusExisting Status = "existing"
)

// Finding is one normalized scanner result. Secret values never appear here.
type Finding struct {
	ID           string   `json:"id"`
	Aliases      []string `json:"aliases,omitempty"`
	Scanner      string   `json:"scanner"`
	Category     Category `json:"category"`
	Severity     Severity `json:"severity"`
	File         string   `json:"file"`
	Line         int      `json:"line,omitempty"`
	Message      string   `json:"message"`
	Package      string   `json:"package,omitempty"`
	Version      string   `json:"version,omitempty"`
	FixedVersion string   `json:"fixed_version,omitempty"`
	FixAvailable bool     `json:"fix_available,omitempty"`
	Fingerprint  string   `json:"fingerprint"`
	Status       Status   `json:"status,omitempty"`
}

// UnmarshalJSON decodes a Finding and rejects one without a severity, which
// would otherwise decode as info and could slip past the gate.
func (f *Finding) UnmarshalJSON(b []byte) error {
	type plain Finding
	aux := struct {
		*plain
		Severity *Severity `json:"severity"`
	}{plain: (*plain)(f)}
	if err := json.Unmarshal(b, &aux); err != nil {
		return err
	}
	if aux.Severity == nil {
		return fmt.Errorf("finding %q: missing severity", f.ID)
	}
	f.Severity = *aux.Severity
	return nil
}

// ScannerRun records the outcome of one scanner (Status: ok|error|skipped).
type ScannerRun struct {
	Name       string   `json:"name"`
	Category   Category `json:"category"`
	Status     string   `json:"status"`
	Error      string   `json:"error,omitempty"`
	DurationMS int64    `json:"duration_ms"`
}

// Result is the content of findings.json.
type Result struct {
	SchemaVersion    int             `json:"schema_version"`
	ShipguardVersion string          `json:"shipguard_version"`
	Context          json.RawMessage `json:"context,omitempty"`
	Scanners         []ScannerRun    `json:"scanners"`
	Findings         []Finding       `json:"findings"`
	PolicyChanged    bool            `json:"policy_changed,omitempty"`
	PolicyDiff       string          `json:"policy_diff,omitempty"`
	PolicyDefaults   bool            `json:"policy_defaults,omitempty"` // no config file: built-in defaults
}

// MarshalJSON encodes nil Scanners and Findings as empty arrays, as the
// findings schema requires.
func (r Result) MarshalJSON() ([]byte, error) {
	type plain Result
	if r.Scanners == nil {
		r.Scanners = []ScannerRun{}
	}
	if r.Findings == nil {
		r.Findings = []Finding{}
	}
	return json.Marshal(plain(r))
}

// ReadResult loads a Result from a JSON file.
func ReadResult(path string) (Result, error) {
	var r Result
	b, err := os.ReadFile(path)
	if err != nil {
		return r, fmt.Errorf("read result: %w", err)
	}
	if err := json.Unmarshal(b, &r); err != nil {
		return r, fmt.Errorf("parse result %s: %w", path, err)
	}
	return r, nil
}

// WriteResult writes a Result as indented JSON, creating the parent
// directory. It writes a temp file in the same directory and renames it into
// place, so readers never see a partial file.
func WriteResult(path string, r Result) (err error) {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return fmt.Errorf("encode result: %w", err)
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("write result: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".findings-*.tmp")
	if err != nil {
		return fmt.Errorf("write result: %w", err)
	}
	defer func() {
		if err != nil {
			_ = os.Remove(tmp.Name())
		}
	}()
	_, werr := tmp.Write(append(b, '\n'))
	cerr := tmp.Close()
	if err := errors.Join(werr, cerr); err != nil {
		return fmt.Errorf("write result: %w", err)
	}
	if err := os.Chmod(tmp.Name(), 0o644); err != nil {
		return fmt.Errorf("write result: %w", err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("write result: %w", err)
	}
	return nil
}

// ScannerRun.Status values.
const (
	RunStatusOK      = "ok"      // the scanner completed
	RunStatusError   = "error"   // the scanner failed
	RunStatusSkipped = "skipped" // the scanner is disabled by the config
)
