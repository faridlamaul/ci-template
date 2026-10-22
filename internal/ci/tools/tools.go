// Package tools downloads, verifies and caches the pinned third-party tools
// used by `shipguard ci` (linters, test runners, package managers).
//
// The pins live in ci-tools.env, embedded in the binary and validated by Load,
// so a malformed bump cannot ship silently.
package tools

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/faridlamaul/shipguard/internal/scanner"
)

//go:embed ci-tools.env
var embedded string

// toolKeys lists the env-file prefixes of the pinned tools.
var toolKeys = []string{"GOLANGCI_LINT", "GOTESTSUM", "RUFF", "UV", "CARGO_NEXTEST", "BUN", "SHIPTAG", "GORELEASER", "CRANE", "COSIGN", "TRIVY"}

// defaultKeys lists the language defaults every pin file must carry.
var defaultKeys = []string{"NODE_DEFAULT", "PYTHON_DEFAULTS", "RUBY_DEFAULT", "RUST_DEFAULT", "PYTEST_VERSION", "COVERAGE_VERSION", "POETRY_VERSION", "COREPACK_VERSION"}

var arches = []string{"amd64", "arm64"}

var sha256Re = regexp.MustCompile(`^[0-9a-f]{64}$`)

const (
	downloadAttempts = 3
	maxFileSize      = 1 << 30 // per extracted file, guards against decompression bombs
)

// Tool describes one pinned download.
type Tool struct {
	Name, Version string
	URL           map[string]string // arch ("amd64"|"arm64") -> https URL; {version} is substituted
	SHA256        map[string]string // arch -> hex
	Archive       string            // "tar.gz" | "zip" | "raw"
	// Bin is the path of the executable inside the archive. {version} and
	// {arch} (amd64|arm64) are substituted; a leading "*/" matches any single
	// top-level directory. For "raw" downloads only its basename is used.
	Bin string
}

// Load parses the embedded pin file and returns the tools keyed by name
// (e.g. "golangci-lint") and the remaining KEY=VALUE language defaults.
func Load() (map[string]Tool, map[string]string, error) {
	return parse(embedded, toolKeys)
}

func parse(text string, prefixes []string) (map[string]Tool, map[string]string, error) {
	kv := map[string]string{}
	for i, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok || strings.TrimSpace(k) == "" {
			return nil, nil, fmt.Errorf("ci-tools.env line %d: want KEY=VALUE", i+1)
		}
		kv[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	used := map[string]bool{}
	get := func(key string) (string, error) {
		used[key] = true
		v := kv[key]
		if v == "" {
			return "", fmt.Errorf("ci-tools.env: missing %s", key)
		}
		return v, nil
	}
	out := map[string]Tool{}
	for _, p := range prefixes {
		t := Tool{
			Name:   strings.ToLower(strings.ReplaceAll(p, "_", "-")),
			URL:    map[string]string{},
			SHA256: map[string]string{},
		}
		var err error
		if t.Version, err = get(p + "_VERSION"); err != nil {
			return nil, nil, err
		}
		for _, a := range arches {
			suffix := strings.ToUpper(a)
			u, err := get(p + "_URL_" + suffix)
			if err != nil {
				return nil, nil, err
			}
			if !strings.HasPrefix(u, "https://") {
				return nil, nil, fmt.Errorf("ci-tools.env: %s_URL_%s must be https", p, suffix)
			}
			s, err := get(p + "_SHA256_" + suffix)
			if err != nil {
				return nil, nil, err
			}
			if !sha256Re.MatchString(s) {
				return nil, nil, fmt.Errorf("ci-tools.env: %s_SHA256_%s must be 64 lowercase hex characters", p, suffix)
			}
			t.URL[a], t.SHA256[a] = u, s
		}
		if t.Archive, err = get(p + "_ARCHIVE"); err != nil {
			return nil, nil, err
		}
		switch t.Archive {
		case "tar.gz", "zip", "raw":
		default:
			return nil, nil, fmt.Errorf("ci-tools.env: %s_ARCHIVE must be tar.gz, zip or raw, got %q", p, t.Archive)
		}
		if t.Bin, err = get(p + "_BIN"); err != nil {
			return nil, nil, err
		}
		out[t.Name] = t
	}
	defs := map[string]string{}
	for k, v := range kv {
		if !used[k] {
			defs[k] = v
		}
	}
	if len(prefixes) == len(toolKeys) { // the real file: require every default
		for _, k := range defaultKeys {
			if defs[k] == "" {
				return nil, nil, fmt.Errorf("ci-tools.env: missing %s", k)
			}
		}
	}
	return out, defs, nil
}

// Cache stores verified tools under Dir/<name>-<version>/. A single Cache is
// not safe for concurrent Ensure calls on the same tool; callers serialise.
type Cache struct {
	Dir    string       // <repo>/.shipguard-cache/tools
	Arch   string       // runtime.GOARCH
	Client *http.Client // nil = default with 2m timeout
	Sleep  func(time.Duration)
}

// Ensure returns the absolute path of the tool's executable, downloading and
// verifying it first when the cache has no valid entry. An entry is valid when
// its .ok marker names the pinned archive SHA-256 and the executable still
// hashes to the SHA-256 recorded in the marker at install time. A partially
// written entry is never trusted: it is built in a staging directory and
// renamed into place only after verification.
func (c *Cache) Ensure(ctx context.Context, t Tool) (string, error) {
	want, ok := t.SHA256[c.Arch]
	url := strings.ReplaceAll(t.URL[c.Arch], "{version}", t.Version)
	if !ok || url == "" {
		return "", fmt.Errorf("tool %s: no pin for architecture %q", t.Name, c.Arch)
	}
	if !strings.HasPrefix(url, "https://") {
		return "", fmt.Errorf("tool %s: download URL must be https: %s", t.Name, url)
	}
	if !sha256Re.MatchString(want) {
		return "", fmt.Errorf("tool %s: pinned sha256 for %s is not 64 hex characters", t.Name, c.Arch)
	}
	dir, err := filepath.Abs(filepath.Join(c.Dir, t.Name+"-"+t.Version))
	if err != nil {
		return "", fmt.Errorf("tool %s: %w", t.Name, err)
	}
	bin := filepath.Join(dir, path.Base(t.expandBin(c.Arch)))
	if cached(dir, bin, want) {
		return bin, nil
	}

	if err := os.MkdirAll(c.Dir, 0o755); err != nil {
		return "", fmt.Errorf("tool %s: %w", t.Name, err)
	}
	dl, err := os.CreateTemp(c.Dir, ".download-*")
	if err != nil {
		return "", fmt.Errorf("tool %s: %w", t.Name, err)
	}
	defer func() { _ = os.Remove(dl.Name()) }()
	defer func() { _ = dl.Close() }()

	var got string
	sleep := c.Sleep
	if sleep == nil {
		sleep = time.Sleep
	}
	err = scanner.Retry(ctx, downloadAttempts, sleep, func() error {
		var err error
		got, err = c.fetch(ctx, url, dl)
		return err
	})
	if err != nil {
		return "", fmt.Errorf("tool %s: download %s: %w", t.Name, url, err)
	}
	if got != want {
		return "", fmt.Errorf("tool %s: checksum mismatch for %s: got %s, want %s", t.Name, url, got, want)
	}

	stage, err := os.MkdirTemp(c.Dir, ".stage-*")
	if err != nil {
		return "", fmt.Errorf("tool %s: %w", t.Name, err)
	}
	defer func() { _ = os.RemoveAll(stage) }()
	if err := t.install(dl, stage, c.Arch); err != nil {
		return "", fmt.Errorf("tool %s: %w", t.Name, err)
	}
	binSum, err := fileSHA256(filepath.Join(stage, filepath.Base(bin)))
	if err != nil {
		return "", fmt.Errorf("tool %s: %w", t.Name, err)
	}
	if err := os.WriteFile(filepath.Join(stage, ".ok"), []byte(want+"\n"+binSum+"\n"), 0o644); err != nil {
		return "", fmt.Errorf("tool %s: %w", t.Name, err)
	}
	if err := os.RemoveAll(dir); err != nil {
		return "", fmt.Errorf("tool %s: %w", t.Name, err)
	}
	if err := os.Rename(stage, dir); err != nil {
		return "", fmt.Errorf("tool %s: %w", t.Name, err)
	}
	return bin, nil
}

// cached reports whether dir holds a verified install: the .ok marker is
// "<archive sha256>\n<executable sha256>\n", the archive hash is the pinned
// one and the executable still hashes to the recorded value.
func cached(dir, bin, want string) bool {
	mark, err := os.ReadFile(filepath.Join(dir, ".ok"))
	if err != nil {
		return false
	}
	lines := strings.Fields(string(mark))
	if len(lines) != 2 || lines[0] != want || !sha256Re.MatchString(lines[1]) {
		return false
	}
	if st, err := os.Lstat(bin); err != nil || !st.Mode().IsRegular() {
		return false
	}
	got, err := fileSHA256(bin)
	return err == nil && got == lines[1]
}

func fileSHA256(name string) (string, error) {
	f, err := os.Open(name)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// fetch downloads url into f (truncating it first) and returns the SHA-256 of
// the bytes written.
func (c *Cache) fetch(ctx context.Context, url string, f *os.File) (string, error) {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	if err := f.Truncate(0); err != nil {
		return "", err
	}
	client := c.Client
	if client == nil {
		client = &http.Client{
			Timeout: 2 * time.Minute,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if req.URL.Scheme != "https" {
					return errors.New("redirect to non-https URL refused")
				}
				if len(via) >= 10 {
					return errors.New("too many redirects")
				}
				return nil
			},
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status %s", resp.Status)
	}
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(f, h), resp.Body); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (t Tool) expandBin(arch string) string {
	r := strings.NewReplacer("{version}", t.Version, "{arch}", arch)
	return r.Replace(t.Bin)
}

// install turns the verified download f into stage/<basename(Bin)>.
func (t Tool) install(f *os.File, stage, arch string) error {
	bin := t.expandBin(arch)
	final := filepath.Join(stage, path.Base(bin))
	if t.Archive == "raw" {
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			return err
		}
		return writeFile(final, f, 0o755)
	}
	root, err := os.MkdirTemp(stage, "x-")
	if err != nil {
		return err
	}
	switch t.Archive {
	case "tar.gz":
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			return err
		}
		err = extractTarGz(f, root)
	case "zip":
		err = extractZip(f, root)
	default:
		err = fmt.Errorf("unsupported archive type %q", t.Archive)
	}
	if err != nil {
		return err
	}
	src, err := locate(root, bin)
	if err != nil {
		return err
	}
	if err := os.Rename(src, final); err != nil {
		return err
	}
	if err := os.Chmod(final, 0o755); err != nil {
		return err
	}
	return os.RemoveAll(root)
}

// locate resolves the Bin path inside the extracted tree.
func locate(root, bin string) (string, error) {
	rel, err := safeRel(bin)
	if err != nil {
		return "", fmt.Errorf("bin %q: %w", bin, err)
	}
	if strings.HasPrefix(rel, "*/") {
		ents, err := os.ReadDir(root)
		if err != nil {
			return "", err
		}
		for _, e := range ents {
			if e.IsDir() {
				p := filepath.Join(root, e.Name(), filepath.FromSlash(rel[2:]))
				if st, err := os.Lstat(p); err == nil && st.Mode().IsRegular() {
					return p, nil
				}
			}
		}
		return "", fmt.Errorf("executable %q not found in archive", bin)
	}
	p := filepath.Join(root, filepath.FromSlash(rel))
	if st, err := os.Lstat(p); err != nil || !st.Mode().IsRegular() {
		return "", fmt.Errorf("executable %q not found in archive", bin)
	}
	return p, nil
}

// safeRel validates an archive-internal path: relative, no ".." component.
// A leading "*/" wildcard is allowed (and kept) for Bin lookups.
func safeRel(name string) (string, error) {
	n := strings.ReplaceAll(name, "\\", "/")
	if n == "" || strings.HasPrefix(n, "/") || filepath.IsAbs(n) {
		return "", fmt.Errorf("unsafe path %q", name)
	}
	for _, part := range strings.Split(n, "/") {
		if part == ".." {
			return "", fmt.Errorf("unsafe path %q", name)
		}
	}
	return path.Clean(n), nil
}

// checkLink rejects a symlink or hardlink whose target would leave root.
// Links are validated but never materialised: the pinned tools do not need
// them, and skipping them rules out link-chaining escapes.
func checkLink(entry, target string) error {
	t := strings.ReplaceAll(target, "\\", "/")
	if strings.HasPrefix(t, "/") || filepath.IsAbs(t) {
		return fmt.Errorf("link %q points outside the archive: %q", entry, target)
	}
	joined := path.Clean(path.Join(path.Dir(entry), t))
	if joined == ".." || strings.HasPrefix(joined, "../") {
		return fmt.Errorf("link %q points outside the archive: %q", entry, target)
	}
	return nil
}

func writeFile(dst string, r io.Reader, mode os.FileMode) error {
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	n, err := io.Copy(out, io.LimitReader(r, maxFileSize+1))
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err == nil && n > maxFileSize {
		err = fmt.Errorf("file %s exceeds %d bytes", dst, int64(maxFileSize))
	}
	return err
}

func extractTarGz(r io.Reader, root string) error {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return fmt.Errorf("gzip: %w", err)
	}
	defer func() { _ = gz.Close() }()
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("tar: %w", err)
		}
		rel, err := safeRel(h.Name)
		if err != nil {
			return fmt.Errorf("tar entry: %w", err)
		}
		dst := filepath.Join(root, filepath.FromSlash(rel))
		switch h.Typeflag {
		case tar.TypeDir:
			err = os.MkdirAll(dst, 0o755)
		case tar.TypeReg:
			if err = os.MkdirAll(filepath.Dir(dst), 0o755); err == nil {
				err = writeFile(dst, tr, 0o644)
			}
		case tar.TypeSymlink, tar.TypeLink:
			err = checkLink(rel, h.Linkname)
		}
		if err != nil {
			return fmt.Errorf("tar entry %q: %w", h.Name, err)
		}
	}
}

func extractZip(f *os.File, root string) error {
	st, err := f.Stat()
	if err != nil {
		return err
	}
	zr, err := zip.NewReader(f, st.Size())
	if err != nil {
		return fmt.Errorf("zip: %w", err)
	}
	for _, zf := range zr.File {
		rel, err := safeRel(zf.Name)
		if err != nil {
			return fmt.Errorf("zip entry: %w", err)
		}
		dst := filepath.Join(root, filepath.FromSlash(rel))
		switch {
		case zf.Mode()&os.ModeSymlink != 0:
			err = zipLink(zf, rel)
		case zf.FileInfo().IsDir():
			err = os.MkdirAll(dst, 0o755)
		default:
			err = zipFile(zf, dst)
		}
		if err != nil {
			return fmt.Errorf("zip entry %q: %w", zf.Name, err)
		}
	}
	return nil
}

func zipLink(zf *zip.File, rel string) error {
	rc, err := zf.Open()
	if err != nil {
		return err
	}
	defer func() { _ = rc.Close() }()
	b, err := io.ReadAll(io.LimitReader(rc, 4096))
	if err != nil {
		return err
	}
	return checkLink(rel, string(b))
}

func zipFile(zf *zip.File, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	rc, err := zf.Open()
	if err != nil {
		return err
	}
	defer func() { _ = rc.Close() }()
	return writeFile(dst, rc, 0o644)
}
