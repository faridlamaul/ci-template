//go:build e2e

// Package e2e runs the shipguard container image against vulnerable fixtures.
// It needs Docker, the image named by SHIPGUARD_IMAGE and network access (the
// osv-scanner and trivy checks bundle queries).
package e2e

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/faridlamaul/shipguard/internal/testutil/gitfixture"
)

const fixturesDir = "../testdata/fixtures"

// secretFile is the file the tests write the fake secret to.
const secretFile = "settings.ini"

// fakeSecret assembles a high-entropy value at runtime so that no secret
// string exists in the repository. It is not a provider token format.
func fakeSecret() string {
	return "f9b00f23" + "faf0ba12" + "7c3d8e45" + "a1b2c3d4"
}

type finding struct {
	Category string `json:"category"`
	ID       string `json:"id"`
	Status   string `json:"status"`
}

type pair struct {
	Category string `json:"category"`
	ID       string `json:"id"`
}

func image(t *testing.T) string {
	t.Helper()
	img := os.Getenv("SHIPGUARD_IMAGE")
	if img == "" {
		t.Skip("SHIPGUARD_IMAGE is not set")
	}
	return img
}

// docker runs docker and returns combined output and the exit code.
func docker(t *testing.T, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command("docker", args...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	var ee *exec.ExitError
	switch {
	case err == nil:
		return out.String(), 0
	case errors.As(err, &ee):
		return out.String(), ee.ExitCode()
	default:
		t.Fatalf("docker %s: %v", strings.Join(args, " "), err)
		return "", -1
	}
}

// shipguard runs `shipguard run --dir /src` on dir. Only the variables in env
// reach the container, so host CI variables never leak in.
func shipguard(t *testing.T, img, dir string, env ...string) (string, int) {
	t.Helper()
	args := []string{"run", "--rm", "-v", dir + ":/src", "-w", "/src"}
	for _, e := range env {
		args = append(args, "-e", e)
	}
	args = append(args, img, "run", "--dir", "/src")
	out, code := docker(t, args...)
	// The container runs as root; make its output removable by the host user.
	if o, c := docker(t, "run", "--rm", "-v", dir+":/src", "--entrypoint", "sh", img, "-c", "chmod -R a+rwX /src"); c != 0 {
		t.Logf("chmod after run failed (%d): %s", c, o)
	}
	return out, code
}

func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-c", "commit.gpgsign=false"}, args...)...)
	cmd.Dir = dir
	cmd.Env = gitfixture.Env()
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

func copyDir(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		if rel == "expected.json" {
			return nil
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
}

// newRepo returns a temp dir holding a fixture copy in a fresh git repo on
// main. Cleanup makes root-owned scanner output removable before TempDir's.
func newRepo(t *testing.T, img, lang string) string {
	t.Helper()
	dir := t.TempDir()
	t.Cleanup(func() {
		docker(t, "run", "--rm", "-v", dir+":/src", "--entrypoint", "sh", img, "-c", "chmod -R a+rwX /src")
	})
	copyDir(t, filepath.Join(fixturesDir, lang), dir)
	git(t, dir, "init", "-q", "-b", "main")
	return dir
}

func commitAll(t *testing.T, dir, msg string) string {
	t.Helper()
	git(t, dir, "add", "-A")
	git(t, dir, "commit", "-q", "-m", msg)
	return git(t, dir, "rev-parse", "HEAD")
}

func readFindings(t *testing.T, dir string) []finding {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, ".shipguard", "findings.json"))
	if err != nil {
		t.Fatal(err)
	}
	var res struct {
		Findings []finding `json:"findings"`
	}
	if err := json.Unmarshal(data, &res); err != nil {
		t.Fatal(err)
	}
	return res.Findings
}

func TestFixtureFindings(t *testing.T) {
	img := image(t)
	for _, lang := range []string{"go", "node", "python", "ruby", "rust"} {
		t.Run(lang, func(t *testing.T) {
			t.Parallel()
			dir := newRepo(t, img, lang)
			secret := fakeSecret()
			if err := os.WriteFile(filepath.Join(dir, secretFile), []byte("api_key = \""+secret+"\"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			commitAll(t, dir, "fixture")

			out, code := shipguard(t, img, dir)
			if code != 1 {
				t.Fatalf("exit = %d, want 1\n%s", code, out)
			}
			got := readFindings(t, dir)

			raw, err := os.ReadFile(filepath.Join(fixturesDir, lang, "expected.json"))
			if err != nil {
				t.Fatal(err)
			}
			var want []pair
			if err := json.Unmarshal(raw, &want); err != nil {
				t.Fatal(err)
			}
			want = append(want, pair{Category: "secrets"}) // any secrets finding
			for _, w := range want {
				found := false
				for _, f := range got {
					if f.Category == w.Category && (w.ID == "" || f.ID == w.ID) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("missing finding {%s %s}", w.Category, w.ID)
				}
			}

			err = filepath.WalkDir(filepath.Join(dir, ".shipguard"), func(p string, d fs.DirEntry, err error) error {
				if err != nil || d.IsDir() {
					return err
				}
				data, rerr := os.ReadFile(p)
				if rerr != nil {
					return rerr
				}
				if bytes.Contains(data, []byte(secret)) {
					t.Errorf("secret value leaked into %s", p)
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestPRDiffAware(t *testing.T) {
	img := image(t)
	dir := newRepo(t, img, "python")
	commitAll(t, dir, "base")
	git(t, dir, "checkout", "-q", "-b", "feature")
	hit := "import os\n\n\ndef clean(path):\n    os.system(\"rm -rf %s\" % path)\n"
	if err := os.WriteFile(filepath.Join(dir, "extra.py"), []byte(hit), 0o644); err != nil {
		t.Fatal(err)
	}
	head := commitAll(t, dir, "feature")

	out, code := shipguard(t, img, dir,
		"GITHUB_ACTIONS=true", "GITHUB_EVENT_NAME=pull_request", "GITHUB_BASE_REF=main", "GITHUB_SHA="+head)
	if code != 1 {
		t.Fatalf("exit = %d, want 1\n%s", code, out)
	}
	var added, existing int
	for _, f := range readFindings(t, dir) {
		switch f.Status {
		case "new":
			added++
			if f.Category != "sast" || f.ID != "shipguard.python.command-injection" {
				t.Errorf("unexpected new finding {%s %s}", f.Category, f.ID)
			}
		case "existing":
			existing++
		}
	}
	if added != 1 {
		t.Errorf("new findings = %d, want exactly 1\n%s", added, out)
	}
	if existing == 0 {
		t.Error("expected the fixture's findings to be existing")
	}
}

func TestNoLockfileRepoPasses(t *testing.T) {
	img := image(t)
	dir := t.TempDir()
	t.Cleanup(func() {
		docker(t, "run", "--rm", "-v", dir+":/src", "--entrypoint", "sh", img, "-c", "chmod -R a+rwX /src")
	})
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("# nothing to scan\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	git(t, dir, "init", "-q", "-b", "main")
	commitAll(t, dir, "readme")
	if out, code := shipguard(t, img, dir); code != 0 {
		t.Fatalf("exit = %d, want 0\n%s", code, out)
	}
}
