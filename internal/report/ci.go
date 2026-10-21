package report

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/faridlamaul/shipguard/internal/ci/run"
)

const (
	ciSummaryMax    = 64 << 10
	ciMaxFailures   = 20
	ciMaxAnnotation = 50
	ciResultPath    = ".shipguard/ci/result.json"
	ciMaxFile       = 64 << 20
	ciMaxMessage    = 4 << 10
)

// CIResult is the outcome of one `shipguard ci` run.
type CIResult struct {
	Language string           `json:"language"`
	Version  string           `json:"version"`
	Source   string           `json:"source"`
	Steps    []run.StepResult `json:"steps"`

	// Dir is the project dir that relative JUnit and Coverage paths resolve
	// against; empty means the working directory.
	Dir string `json:"-"`
}

// TestFailure is one failed or errored JUnit test case.
type TestFailure struct {
	Suite, Name, File string
	Line              int
	Message           string
}

type junitSuite struct {
	Name   string       `xml:"name,attr"`
	Suites []junitSuite `xml:"testsuite"`
	Cases  []junitCase  `xml:"testcase"`
}

type junitCase struct {
	Name     string      `xml:"name,attr"`
	File     string      `xml:"file,attr"`
	Line     string      `xml:"line,attr"`
	Failures []junitFail `xml:"failure"`
	Errors   []junitFail `xml:"error"`
}

type junitFail struct {
	Message string `xml:"message,attr"`
	Text    string `xml:",chardata"`
}

// MergeJUnit writes one <testsuites> document holding every testsuite of
// files (roots may be testsuites or testsuite) and returns the failures.
func MergeJUnit(files []string, w io.Writer) ([]TestFailure, error) {
	var failures []TestFailure
	var body bytes.Buffer
	for _, f := range files {
		raws, fs, err := readJUnit(f)
		if err != nil {
			return nil, err
		}
		for _, raw := range raws {
			body.Write(raw)
			body.WriteByte('\n')
		}
		failures = append(failures, fs...)
	}
	out := "<testsuites/>\n"
	if body.Len() > 0 {
		out = "<testsuites>\n" + body.String() + "</testsuites>\n"
	}
	if _, err := io.WriteString(w, out); err != nil {
		return nil, fmt.Errorf("write junit: %w", err)
	}
	return failures, nil
}

// readCapped reads path, failing when it exceeds ciMaxFile bytes.
func readCapped(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, ciMaxFile+1))
	if err != nil {
		return nil, err
	}
	if len(data) > ciMaxFile {
		return nil, fmt.Errorf("file exceeds %d MiB", ciMaxFile>>20)
	}
	return data, nil
}

func readJUnit(path string) ([][]byte, []TestFailure, error) {
	data, err := readCapped(path)
	if err != nil {
		return nil, nil, fmt.Errorf("read junit %s: %w", path, err)
	}
	raws, fs, err := parseJUnit(filepath.Base(path), data)
	if err != nil {
		return nil, nil, fmt.Errorf("parse junit %s: %w", path, err)
	}
	return raws, fs, nil
}

func parseJUnit(base string, data []byte) ([][]byte, []TestFailure, error) {
	dec := xml.NewDecoder(bytes.NewReader(data))
	dec.CharsetReader = func(_ string, in io.Reader) (io.Reader, error) { return in, nil }
	var raws [][]byte
	var fails []TestFailure
	sawRoot := false
	var strayRaw []byte
	var strayCases []junitCase
	for {
		start := dec.InputOffset()
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, nil, err
		}
		se, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		switch se.Name.Local {
		case "testsuites":
			sawRoot = true
		case "testsuite":
			sawRoot = true
			var s junitSuite
			if err := dec.DecodeElement(&s, &se); err != nil {
				return nil, nil, err
			}
			raws = append(raws, data[start:dec.InputOffset()])
			fails = append(fails, suiteFailures(s)...)
		case "testcase":
			// Bare testcases under <testsuites> (e.g. Node's reporter).
			sawRoot = true
			var c junitCase
			if err := dec.DecodeElement(&c, &se); err != nil {
				return nil, nil, err
			}
			strayRaw = append(strayRaw, data[start:dec.InputOffset()]...)
			strayRaw = append(strayRaw, '\n')
			strayCases = append(strayCases, c)
		default:
			if !sawRoot {
				return nil, nil, fmt.Errorf("unexpected root element <%s>", se.Name.Local)
			}
			if err := dec.Skip(); err != nil {
				return nil, nil, err
			}
		}
	}
	if !sawRoot {
		return nil, nil, errors.New("no testsuite element")
	}
	if len(strayCases) > 0 {
		var name bytes.Buffer
		if err := xml.EscapeText(&name, []byte(base)); err != nil {
			return nil, nil, err
		}
		raws = append(raws, []byte(`<testsuite name="`+name.String()+`">`+"\n"+string(strayRaw)+"</testsuite>"))
		fails = append(fails, suiteFailures(junitSuite{Name: base, Cases: strayCases})...)
	}
	return raws, fails, nil
}

func suiteFailures(s junitSuite) []TestFailure {
	var out []TestFailure
	for _, c := range s.Cases {
		for _, f := range append(append([]junitFail{}, c.Failures...), c.Errors...) {
			line, _ := strconv.Atoi(strings.TrimSpace(c.Line))
			msg := strings.TrimSpace(f.Message)
			if msg == "" {
				msg, _, _ = strings.Cut(strings.TrimSpace(f.Text), "\n")
				msg = strings.TrimSpace(msg)
			}
			out = append(out, TestFailure{Suite: s.Name, Name: c.Name, File: c.File, Line: line, Message: cutUTF8(msg, ciMaxMessage)})
		}
	}
	for _, sub := range s.Suites {
		out = append(out, suiteFailures(sub)...)
	}
	return out
}

// CISummary renders the run as Markdown, at most maxBytes (<= 0: no limit).
// Relative coverage paths resolve against r.Dir.
func CISummary(r CIResult, failures []TestFailure, maxBytes int) string {
	var head strings.Builder
	fmt.Fprintf(&head, "## shipguard ci: %s %s\n\n", cell(r.Language), cell(r.Version))
	head.WriteString("| Step | Status | Duration | Notes |\n|---|---|---|---|\n")
	for _, s := range r.Steps {
		var notes []string
		if s.Reason != "" {
			notes = append(notes, s.Reason)
		}
		notes = append(notes, s.Warnings...)
		fmt.Fprintf(&head, "| %s | %s | %s | %s |\n", cell(string(s.Name)), cell(s.Status),
			s.Duration.Round(10e6), cell(strings.Join(notes, "; ")))
	}
	if pct, ok := coveragePercent(r); ok {
		fmt.Fprintf(&head, "\nCoverage: %.1f%%\n", pct)
	}

	lines := make([]string, len(failures))
	for i, f := range failures {
		loc := ""
		if f.File != "" {
			loc = " (" + f.File
			if f.Line > 0 {
				loc += ":" + strconv.Itoa(f.Line)
			}
			loc += ")"
		}
		lines[i] = fmt.Sprintf("- %s › %s%s: %s\n", cell(f.Suite), cell(f.Name), loc, cell(f.Message))
	}
	n := min(len(lines), ciMaxFailures)
	for {
		var b strings.Builder
		b.WriteString(head.String())
		if n > 0 {
			b.WriteString("\n### Failures\n\n")
			for _, l := range lines[:n] {
				b.WriteString(l)
			}
		}
		if n < len(lines) {
			fmt.Fprintf(&b, "\n%d more in %s\n", len(lines)-n, ciResultPath)
		}
		if maxBytes <= 0 || b.Len() <= maxBytes {
			return b.String()
		}
		if n == 0 {
			return cutUTF8(b.String(), maxBytes)
		}
		n--
	}
}

// coveragePercent reads line-rate from the first step's Cobertura file.
func coveragePercent(r CIResult) (float64, bool) {
	p := firstCoverage(r)
	if p == "" {
		return 0, false
	}
	data, err := readCapped(resolve(r.Dir, p))
	if err != nil {
		return 0, false
	}
	dec := xml.NewDecoder(bytes.NewReader(data))
	dec.CharsetReader = func(_ string, in io.Reader) (io.Reader, error) { return in, nil }
	for {
		tok, err := dec.Token()
		if err != nil {
			return 0, false
		}
		if se, ok := tok.(xml.StartElement); ok {
			for _, a := range se.Attr {
				if a.Name.Local == "line-rate" {
					v, err := strconv.ParseFloat(strings.TrimSpace(a.Value), 64)
					return v * 100, err == nil
				}
			}
			return 0, false
		}
	}
}

func firstCoverage(r CIResult) string {
	for _, s := range r.Steps {
		if s.Coverage != "" {
			return s.Coverage
		}
	}
	return ""
}

func resolve(dir, p string) string {
	if filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(dir, p)
}

// WriteCI writes .shipguard/ci/{result.json,summary.md,test-results/junit.xml,
// coverage.xml} under dir. Bitbucket finds the JUnit there itself, so no
// clone-root copy is written (it would be counted twice).
func WriteCI(dir string, r CIResult) error {
	base := filepath.Join(dir, outDir, "ci")
	if err := os.MkdirAll(filepath.Join(base, "test-results"), 0o755); err != nil {
		return fmt.Errorf("create ci output dir: %w", err)
	}
	r.Dir = dir
	r.Steps = append([]run.StepResult(nil), r.Steps...)
	var raws [][]byte
	var failures []TestFailure
	seen := map[string]bool{}
	for i := range r.Steps {
		s := &r.Steps[i]
		s.Warnings = append([]string(nil), s.Warnings...)
		for _, j := range s.JUnit {
			p := resolve(dir, j)
			if seen[p] {
				continue
			}
			seen[p] = true
			rs, fs, err := readJUnit(p)
			if err != nil {
				s.Warnings = append(s.Warnings, fmt.Sprintf("unreadable JUnit %s: %v", j, err))
				continue
			}
			raws = append(raws, rs...)
			failures = append(failures, fs...)
		}
	}
	var junit bytes.Buffer
	if len(raws) == 0 {
		junit.WriteString("<testsuites/>\n")
	} else {
		junit.WriteString("<testsuites>\n")
		for _, raw := range raws {
			junit.Write(raw)
			junit.WriteByte('\n')
		}
		junit.WriteString("</testsuites>\n")
	}
	var covData []byte
	if p := firstCoverage(r); p != "" {
		var err error
		if covData, err = readCapped(resolve(dir, p)); err != nil {
			for i := range r.Steps {
				if r.Steps[i].Coverage == p {
					r.Steps[i].Warnings = append(r.Steps[i].Warnings, fmt.Sprintf("unreadable coverage %s: %v", p, err))
					break
				}
			}
			covData = nil
		}
	}
	js, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return fmt.Errorf("encode result.json: %w", err)
	}
	writes := []struct {
		name string
		data []byte
	}{
		{"result.json", append(js, '\n')},
		{"summary.md", []byte(CISummary(r, failures, ciSummaryMax))},
		{filepath.Join("test-results", "junit.xml"), junit.Bytes()},
	}
	for _, w := range writes {
		if err := os.WriteFile(filepath.Join(base, w.name), w.data, 0o644); err != nil {
			return fmt.Errorf("write %s: %w", w.name, err)
		}
	}
	covOut := filepath.Join(base, "coverage.xml")
	if covData != nil {
		if err := os.WriteFile(covOut, covData, 0o644); err != nil {
			return fmt.Errorf("write coverage.xml: %w", err)
		}
	} else if err := os.Remove(covOut); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove stale coverage.xml: %w", err)
	}
	return nil
}

// CIGitHub appends the summary to $GITHUB_STEP_SUMMARY and prints one ::error
// workflow command per failure (at most 50) to stdout.
func CIGitHub(r CIResult, failures []TestFailure, getenv func(string) string, stdout io.Writer) error {
	if p := getenv("GITHUB_STEP_SUMMARY"); p != "" {
		if err := appendFile(p, CISummary(r, failures, ciSummaryMax)); err != nil {
			return err
		}
	}
	data := strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A")
	prop := strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A", ":", "%3A", ",", "%2C")
	for i, f := range failures {
		if i >= ciMaxAnnotation {
			break
		}
		var props []string
		if f.File != "" {
			props = append(props, "file="+prop.Replace(f.File))
			if f.Line > 0 {
				props = append(props, "line="+strconv.Itoa(f.Line))
			}
		}
		props = append(props, "title="+prop.Replace(f.Suite+" › "+f.Name))
		if _, err := fmt.Fprintf(stdout, "::error %s::%s\n", strings.Join(props, ","), data.Replace(f.Message)); err != nil {
			return fmt.Errorf("write annotation: %w", err)
		}
	}
	return nil
}
