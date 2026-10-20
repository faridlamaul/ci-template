package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/faridlamaul/shipguard/internal/finding"
)

type gitleaks struct{ run Runner }

// NewGitleaks returns the secrets scanner backed by the gitleaks binary.
func NewGitleaks(run Runner) Scanner { return &gitleaks{run: run} }

func (g *gitleaks) Name() string               { return "gitleaks" }
func (g *gitleaks) Category() finding.Category { return finding.CategorySecrets }

// gitleaksLeak is the subset of a gitleaks report entry that shipguard reads.
// Match and the source line are intentionally not decoded.
type gitleaksLeak struct {
	RuleID      string
	Description string
	StartLine   int
	File        string
	Secret      string
}

// ParseGitleaks converts a gitleaks JSON report into findings. The secret is
// only hashed into the fingerprint and never stored.
func ParseGitleaks(raw []byte) ([]finding.Finding, error) {
	return parseGitleaks(raw)
}

// parseGitleaks makes reported paths relative to the first of dirs that
// contains them.
func parseGitleaks(raw []byte, dirs ...string) ([]finding.Finding, error) {
	var leaks []gitleaksLeak
	if err := json.Unmarshal(raw, &leaks); err != nil {
		return nil, fmt.Errorf("parse gitleaks report: %w", err)
	}
	out := make([]finding.Finding, 0, len(leaks))
	for _, l := range leaks {
		file := l.File
		for _, d := range dirs {
			file = relFile(file, d)
		}
		out = append(out, finding.Finding{
			ID:          l.RuleID,
			Scanner:     "gitleaks",
			Category:    finding.CategorySecrets,
			Severity:    finding.High,
			File:        file,
			Line:        l.StartLine,
			Message:     l.Description,
			Fingerprint: finding.Fingerprint(l.RuleID, file, finding.SecretKey(l.Secret)),
		})
	}
	return out, nil
}

// relFile returns a slash-separated path relative to dir, stripping the
// absolute prefix gitleaks may emit.
func relFile(file, dir string) string {
	f := filepath.FromSlash(strings.ReplaceAll(file, "\\", "/"))
	if dir != "" && filepath.IsAbs(f) {
		if rel, err := filepath.Rel(dir, f); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			f = rel
		}
	}
	return filepath.ToSlash(f)
}

// gitleaksDefaultConfig selects gitleaks' built-in rules and nothing else.
// Passed with --config, it also stops gitleaks from loading a .gitleaks.toml
// from the repository or the GITLEAKS_CONFIG* variables.
const gitleaksDefaultConfig = "[extend]\nuseDefault = true\n"

// args builds the gitleaks command line. source is the git dir (git modes) or
// the work-tree link (dir mode); cfg and ignore are shipguard's own files.
func (g *gitleaks) args(t Target, source, report, cfg, ignore string) []string {
	var a []string
	switch {
	case t.LogOpts != "":
		a = []string{"git", "--log-opts=" + t.LogOpts, source}
	case t.FullHistory:
		a = []string{"git", source}
	default:
		a = []string{"dir", source}
	}
	// No --redact: the secret is needed to compute the fingerprint.
	return append(a, "--report-format", "json", "--report-path", report, "--exit-code", "0", "--no-banner",
		"--config", cfg, "--gitleaks-ignore-path", ignore, "--ignore-gitleaks-allow")
}

// source returns the path gitleaks scans and the prefix to strip from the
// file paths it reports. Policy lives only in .shipguard.yaml, so the
// repository's .gitleaksignore must not apply. gitleaks always loads
// <source>/.gitleaksignore, whatever --gitleaks-ignore-path says, so:
//   - git modes scan the git dir, which holds no committed files;
//   - dir mode scans the work tree through a symlink in a fresh temp dir
//     (with a trailing separator so the walk follows it). Reported paths then
//     carry that random prefix, which no committed fingerprint can match.
func (g *gitleaks) source(ctx context.Context, t Target, work string) (string, string, error) {
	if t.LogOpts != "" || t.FullHistory {
		out, _, code, err := g.run(ctx, t.Dir, "git", "rev-parse", "--absolute-git-dir")
		if err != nil {
			return "", "", fmt.Errorf("gitleaks: locate git dir: %w", err)
		}
		gitDir := strings.TrimSpace(string(out))
		if code != 0 || gitDir == "" {
			return "", "", fmt.Errorf("gitleaks: locate git dir: git rev-parse exited with code %d", code)
		}
		return gitDir, t.Dir, nil
	}
	abs, err := filepath.Abs(t.Dir)
	if err != nil {
		return "", "", fmt.Errorf("gitleaks: %w", err)
	}
	link := filepath.Join(work, "repo")
	if err := os.Symlink(abs, link); err != nil {
		// No symlinks (e.g. Windows without developer mode): scanning the
		// tree directly is only safe when there is no ignore file to obey.
		if fi, serr := os.Stat(filepath.Join(t.Dir, ".gitleaksignore")); serr == nil && !fi.IsDir() {
			return "", "", fmt.Errorf("gitleaks: cannot neutralize .gitleaksignore (symlink: %w); use .shipguard.yaml exceptions instead", err)
		}
		return ".", t.Dir, nil
	}
	return link + string(filepath.Separator), link, nil
}

func (g *gitleaks) Scan(ctx context.Context, t Target) ([]finding.Finding, error) {
	ctx, cancel := withTimeout(ctx, t)
	defer cancel()

	report, err := tempReport(t, "gitleaks")
	if err != nil {
		return nil, err
	}
	defer os.Remove(report)
	work, err := tempDir(t, "gitleaks")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(work)
	cfg := filepath.Join(work, "gitleaks.toml")
	if err := os.WriteFile(cfg, []byte(gitleaksDefaultConfig), 0o600); err != nil {
		return nil, fmt.Errorf("write gitleaks config: %w", err)
	}
	ignore := filepath.Join(work, "ignore") // empty: no .gitleaksignore
	if err := os.Mkdir(ignore, 0o700); err != nil {
		return nil, fmt.Errorf("create gitleaks ignore dir: %w", err)
	}
	source, prefix, err := g.source(ctx, t, work)
	if err != nil {
		return nil, err
	}

	_, _, code, err := g.run(ctx, t.Dir, "gitleaks", g.args(t, source, report, cfg, ignore)...)
	if err != nil {
		return nil, fmt.Errorf("gitleaks: %w", err)
	}
	if code != 0 {
		return nil, fmt.Errorf("gitleaks exited with code %d", code)
	}
	raw, err := os.ReadFile(report)
	if err != nil {
		return nil, fmt.Errorf("read gitleaks report: %w", err)
	}
	fs, err := parseGitleaks(raw, prefix, t.Dir)
	if err != nil {
		return nil, err
	}
	if t.RawDir != "" {
		if err := writeRaw(t.RawDir, "gitleaks", fs); err != nil {
			return nil, err
		}
	}
	return fs, nil
}

// tempDir creates an empty private directory outside Dir and RawDir.
func tempDir(t Target, tool string) (string, error) {
	d, err := os.MkdirTemp("", "shipguard-"+tool+"-*")
	if err != nil {
		return "", fmt.Errorf("create %s temp dir: %w", tool, err)
	}
	for _, x := range []string{t.Dir, t.RawDir} {
		if x != "" && within(x, d) {
			os.RemoveAll(d)
			return "", fmt.Errorf("temp dir %s is inside %s; set TMPDIR elsewhere", filepath.Dir(d), x)
		}
	}
	return d, nil
}

// tempReport creates an empty report file outside Dir and RawDir so the
// unredacted report is never left in a scanned or published location.
func tempReport(t Target, tool string) (string, error) {
	f, err := os.CreateTemp("", "shipguard-"+tool+"-*.json")
	if err != nil {
		return "", fmt.Errorf("create %s report: %w", tool, err)
	}
	name := f.Name()
	f.Close()
	for _, d := range []string{t.Dir, t.RawDir} {
		if d != "" && within(d, name) {
			os.Remove(name)
			return "", fmt.Errorf("temp dir %s is inside %s; set TMPDIR elsewhere", filepath.Dir(name), d)
		}
	}
	return name, nil
}

func within(dir, path string) bool {
	a, err1 := filepath.Abs(dir)
	b, err2 := filepath.Abs(path)
	if err1 != nil || err2 != nil {
		return false
	}
	if r, err := filepath.EvalSymlinks(a); err == nil {
		a = r
	}
	if r, err := filepath.EvalSymlinks(filepath.Dir(b)); err == nil {
		b = filepath.Join(r, filepath.Base(b))
	}
	rel, err := filepath.Rel(a, b)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func writeRaw(rawDir, tool string, fs []finding.Finding) error {
	if err := os.MkdirAll(rawDir, 0o755); err != nil {
		return fmt.Errorf("create raw dir: %w", err)
	}
	b, err := json.MarshalIndent(fs, "", "  ")
	if err != nil {
		return fmt.Errorf("encode %s findings: %w", tool, err)
	}
	if err := os.WriteFile(filepath.Join(rawDir, tool+".json"), b, 0o644); err != nil {
		return fmt.Errorf("write %s raw: %w", tool, err)
	}
	return nil
}
