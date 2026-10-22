package tools

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

func TestLoadReleaseTools(t *testing.T) {
	tl, _, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"shiptag", "goreleaser", "crane", "cosign", "trivy"} {
		tool, ok := tl[n]
		if !ok {
			t.Fatalf("missing tool %s", n)
		}
		for _, a := range []string{"amd64", "arm64"} {
			if !hex64.MatchString(tool.SHA256[a]) {
				t.Errorf("%s/%s: bad sha %q", n, a, tool.SHA256[a])
			}
			if !strings.HasPrefix(tool.URL[a], "https://") {
				t.Errorf("%s/%s: bad url %q", n, a, tool.URL[a])
			}
		}
	}
}

func TestLoadEmbedded(t *testing.T) {
	tl, defs, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"golangci-lint", "gotestsum", "ruff", "uv", "cargo-nextest", "bun"} {
		tool, ok := tl[n]
		if !ok {
			t.Fatalf("missing tool %s", n)
		}
		if tool.Name != n || tool.Version == "" || tool.Bin == "" {
			t.Errorf("%s: incomplete %+v", n, tool)
		}
		for _, a := range []string{"amd64", "arm64"} {
			if !hex64.MatchString(tool.SHA256[a]) {
				t.Errorf("%s/%s: bad sha %q", n, a, tool.SHA256[a])
			}
			if !strings.HasPrefix(tool.URL[a], "https://") {
				t.Errorf("%s/%s: bad url %q", n, a, tool.URL[a])
			}
		}
	}
	for _, k := range []string{"NODE_DEFAULT", "PYTHON_DEFAULTS", "RUBY_DEFAULT", "RUST_DEFAULT", "PYTEST_VERSION", "COVERAGE_VERSION", "POETRY_VERSION", "COREPACK_VERSION"} {
		if defs[k] == "" {
			t.Errorf("missing default %s", k)
		}
	}
}

func TestParseRejectsBad(t *testing.T) {
	good := func() string {
		return "X_VERSION=1\nX_URL_AMD64=https://a/{version}\nX_URL_ARM64=https://a\nX_SHA256_AMD64=" +
			strings.Repeat("a", 64) + "\nX_SHA256_ARM64=" + strings.Repeat("b", 64) + "\nX_ARCHIVE=raw\nX_BIN=x\n"
	}
	if _, _, err := parse(good(), []string{"X"}); err != nil {
		t.Fatalf("good rejected: %v", err)
	}
	cases := map[string]string{
		"X_ARCHIVE":      strings.Replace(good(), "X_ARCHIVE=raw\n", "", 1),
		"X_SHA256_ARM64": strings.Replace(good(), strings.Repeat("b", 64), "zz", 1),
		"X_URL_AMD64":    strings.Replace(good(), "https://a/{version}", "http://a", 1),
	}
	for key, in := range cases {
		_, _, err := parse(in, []string{"X"})
		if err == nil || !strings.Contains(err.Error(), key) {
			t.Errorf("%s: err = %v", key, err)
		}
	}
}

type entry struct {
	name, body string
	link       string
	hard       bool
}

func tgz(t *testing.T, es ...entry) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range es {
		h := &tar.Header{Name: e.name, Mode: 0o644, Size: int64(len(e.body))}
		if e.link != "" {
			h.Typeflag, h.Linkname, h.Size = tar.TypeSymlink, e.link, 0
			if e.hard {
				h.Typeflag = tar.TypeLink
			}
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if e.link == "" {
			if _, err := tw.Write([]byte(e.body)); err != nil {
				t.Fatal(err)
			}
		}
	}
	_ = tw.Close()
	_ = gz.Close()
	return buf.Bytes()
}

func sum(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

func setup(t *testing.T, payload []byte, handler http.HandlerFunc) (*Cache, Tool, *int32) {
	t.Helper()
	var hits int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		if handler != nil {
			handler(w, r)
			return
		}
		_, _ = w.Write(payload)
	}))
	t.Cleanup(srv.Close)
	c := &Cache{Dir: filepath.Join(t.TempDir(), "tools"), Arch: "amd64", Client: srv.Client(), Sleep: func(time.Duration) {}}
	tool := Tool{
		Name: "demo", Version: "1.2.3", Archive: "tar.gz", Bin: "demo-{version}/demo",
		URL:    map[string]string{"amd64": srv.URL + "/demo-{version}.tar.gz"},
		SHA256: map[string]string{"amd64": sum(payload)},
	}
	return c, tool, &hits
}

func TestEnsureDownloadsVerifiesCaches(t *testing.T) {
	c, tool, hits := setup(t, tgz(t, entry{name: "demo-1.2.3/demo", body: "#!/bin/sh\n"}), nil)
	p, err := c.Ensure(context.Background(), tool)
	if err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(p) || filepath.Base(p) != "demo" {
		t.Errorf("path = %s", p)
	}
	if st, err := os.Stat(p); err != nil || st.Mode().Perm() != 0o755 {
		t.Errorf("stat = %v, %v", st, err)
	}
	p2, err := c.Ensure(context.Background(), tool)
	if err != nil || p2 != p {
		t.Fatalf("second = %s, %v", p2, err)
	}
	if *hits != 1 {
		t.Errorf("hits = %d, want 1", *hits)
	}
}

func TestEnsureZipAndRawAndGlob(t *testing.T) {
	var zb bytes.Buffer
	zw := zip.NewWriter(&zb)
	w, _ := zw.Create("bun-linux-x64/bun")
	_, _ = w.Write([]byte("bin"))
	_ = zw.Close()
	c, tool, _ := setup(t, zb.Bytes(), nil)
	tool.Archive = "zip"
	tool.Bin = "*/bun"
	p, err := c.Ensure(context.Background(), tool)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(p); string(b) != "bin" {
		t.Errorf("zip content %q", b)
	}

	raw := []byte("raw-exe")
	c2, rt, _ := setup(t, raw, nil)
	rt.Archive, rt.Bin = "raw", "demo"
	p, err = c2.Ensure(context.Background(), rt)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(p); string(b) != "raw-exe" {
		t.Errorf("raw content %q", b)
	}
}

func TestEnsureChecksumMismatch(t *testing.T) {
	c, tool, _ := setup(t, tgz(t, entry{name: "demo-1.2.3/demo", body: "x"}), nil)
	tool.SHA256["amd64"] = strings.Repeat("0", 64)
	if _, err := c.Ensure(context.Background(), tool); err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("err = %v", err)
	}
	assertEmpty(t, c.Dir)
}

func assertEmpty(t *testing.T, dir string) {
	t.Helper()
	var left []string
	_ = filepath.Walk(dir, func(p string, i os.FileInfo, err error) error {
		if err == nil && p != dir {
			left = append(left, p)
		}
		return nil
	})
	if len(left) != 0 {
		t.Errorf("cache not empty: %v", left)
	}
}

func TestEnsureRejectsHTTP(t *testing.T) {
	c, tool, hits := setup(t, []byte("x"), nil)
	tool.URL["amd64"] = strings.Replace(tool.URL["amd64"], "https://", "http://", 1)
	if _, err := c.Ensure(context.Background(), tool); err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatalf("err = %v", err)
	}
	if *hits != 0 {
		t.Errorf("hits = %d", *hits)
	}
}

func TestEnsureRetries(t *testing.T) {
	payload := tgz(t, entry{name: "demo-1.2.3/demo", body: "x"})
	var n int32
	c, tool, _ := setup(t, payload, func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&n, 1) <= 2 {
			http.Error(w, "boom", 500)
			return
		}
		_, _ = w.Write(payload)
	})
	var sleeps int
	c.Sleep = func(time.Duration) { sleeps++ }
	if _, err := c.Ensure(context.Background(), tool); err != nil {
		t.Fatal(err)
	}
	if sleeps != 2 {
		t.Errorf("sleeps = %d", sleeps)
	}
}

func TestEnsureArchivePathTraversal(t *testing.T) {
	good := entry{name: "demo-1.2.3/demo", body: "x"}
	for name, tc := range map[string]struct {
		es   []entry
		want string
	}{
		"dotdot":   {[]entry{{name: "../x", body: "x"}, good}, "unsafe path"},
		"abs":      {[]entry{{name: "/etc/x", body: "x"}, good}, "unsafe path"},
		"symlink":  {[]entry{{name: "demo-1.2.3/l", link: "../../outside"}, good}, "points outside"},
		"abslink":  {[]entry{{name: "demo-1.2.3/l", link: "/etc/passwd"}, good}, "points outside"},
		"hardlink": {[]entry{{name: "demo-1.2.3/h", link: "../../outside", hard: true}, good}, "points outside"},
	} {
		t.Run(name, func(t *testing.T) {
			c, tool, _ := setup(t, tgz(t, tc.es...), nil)
			_, err := c.Ensure(context.Background(), tool)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want containing %q", err, tc.want)
			}
			assertEmpty(t, c.Dir)
		})
	}
}

func TestEnsureZipPathTraversal(t *testing.T) {
	var zb bytes.Buffer
	zw := zip.NewWriter(&zb)
	for _, n := range []string{"../x", "demo-1.2.3/demo"} {
		w, _ := zw.Create(n)
		_, _ = w.Write([]byte("x"))
	}
	_ = zw.Close()
	c, tool, _ := setup(t, zb.Bytes(), nil)
	tool.Archive = "zip"
	_, err := c.Ensure(context.Background(), tool)
	if err == nil || !strings.Contains(err.Error(), "unsafe path") {
		t.Fatalf("err = %v", err)
	}
	assertEmpty(t, c.Dir)
}

func TestEnsureIgnoresStaleOK(t *testing.T) {
	c, tool, hits := setup(t, tgz(t, entry{name: "demo-1.2.3/demo", body: "x"}), nil)
	dir := filepath.Join(c.Dir, "demo-1.2.3")
	_ = os.MkdirAll(dir, 0o755)
	_ = os.WriteFile(filepath.Join(dir, "demo"), []byte("tampered"), 0o755)
	_ = os.WriteFile(filepath.Join(dir, ".ok"), []byte("wrong"), 0o644)
	if _, err := c.Ensure(context.Background(), tool); err != nil {
		t.Fatal(err)
	}
	if *hits != 1 {
		t.Errorf("hits = %d", *hits)
	}
}

func TestEnsureRehashesCachedBinary(t *testing.T) {
	c, tool, hits := setup(t, tgz(t, entry{name: "demo-1.2.3/demo", body: "good"}), nil)
	p, err := c.Ensure(context.Background(), tool)
	if err != nil {
		t.Fatal(err)
	}
	// A matching .ok marker is not enough: the cached executable is re-hashed.
	if err := os.WriteFile(p, []byte("tampered"), 0o755); err != nil {
		t.Fatal(err)
	}
	p2, err := c.Ensure(context.Background(), tool)
	if err != nil || p2 != p {
		t.Fatalf("second = %s, %v", p2, err)
	}
	if b, _ := os.ReadFile(p); string(b) != "good" {
		t.Errorf("content = %q, want the re-downloaded executable", b)
	}
	if *hits != 2 {
		t.Errorf("hits = %d, want 2 (re-download after the hash mismatch)", *hits)
	}
	if _, err := c.Ensure(context.Background(), tool); err != nil || *hits != 2 {
		t.Errorf("third: err = %v, hits = %d, want a cache hit", err, *hits)
	}
}

func TestEnsureUnsupportedArch(t *testing.T) {
	c, tool, _ := setup(t, []byte("x"), nil)
	c.Arch = "riscv64"
	if _, err := c.Ensure(context.Background(), tool); err == nil {
		t.Fatal("want error")
	}
}
