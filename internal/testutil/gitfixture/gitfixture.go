// Package gitfixture builds throwaway git repositories for tests, isolated
// from the host's git configuration (including commit signing).
package gitfixture

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// Repo is a temporary git repository.
type Repo struct {
	T   *testing.T
	Dir string

	n int
}

// Env returns the process environment with git configuration isolated and
// author/committer identity fixed.
func Env() []string {
	return append(os.Environ(),
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_AUTHOR_NAME=Test",
		"GIT_AUTHOR_EMAIL=test@example.com",
		"GIT_COMMITTER_NAME=Test",
		"GIT_COMMITTER_EMAIL=test@example.com",
		"LC_ALL=C",
	)
}

// New initialises an empty repository on branch main in a temp dir.
func New(t *testing.T) *Repo {
	t.Helper()
	r := &Repo{T: t, Dir: t.TempDir()}
	r.Git("init", "-q", "-b", "main")
	return r
}

// Git runs git in the repository and returns trimmed stdout.
func (r *Repo) Git(args ...string) string {
	r.T.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = r.Dir
	cmd.Env = Env()
	out, err := cmd.Output()
	if err != nil {
		stderr := ""
		if ee, ok := err.(*exec.ExitError); ok {
			stderr = string(ee.Stderr)
		}
		r.T.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, stderr)
	}
	return strings.TrimSpace(string(out))
}

// Commit writes unique content to each file (creating parent dirs), commits,
// and returns the full SHA. With no files it creates an empty commit.
func (r *Repo) Commit(msg string, files ...string) string {
	r.T.Helper()
	args := []string{"-c", "commit.gpgsign=false", "commit", "-q", "-m", msg}
	if len(files) == 0 {
		args = append(args, "--allow-empty")
	}
	for _, f := range files {
		r.n++
		p := filepath.Join(r.Dir, f)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			r.T.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(msg+"\n"+strconv.Itoa(r.n)+"\n"), 0o644); err != nil {
			r.T.Fatal(err)
		}
		r.Git("add", "--", f)
	}
	r.Git(args...)
	return r.Git("rev-parse", "HEAD")
}

// CommitAs makes an empty commit with the given author identity.
func (r *Repo) CommitAs(name, email, msg string) string {
	r.T.Helper()
	cmd := exec.Command("git", "-c", "commit.gpgsign=false", "commit", "-q", "--allow-empty", "-m", msg)
	cmd.Dir = r.Dir
	cmd.Env = append(Env(), "GIT_AUTHOR_NAME="+name, "GIT_AUTHOR_EMAIL="+email)
	if out, err := cmd.CombinedOutput(); err != nil {
		r.T.Fatalf("commit: %v\n%s", err, out)
	}
	return r.Git("rev-parse", "HEAD")
}

// Tag tags HEAD, annotated or lightweight.
func (r *Repo) Tag(name string, annotated bool) {
	r.T.Helper()
	if annotated {
		r.Git("-c", "tag.gpgsign=false", "tag", "-a", name, "-m", name)
		return
	}
	r.Git("-c", "tag.gpgsign=false", "tag", name)
}

// Merge merges branch into the current branch with a merge commit (--no-ff)
// and the given message, and returns the merge commit's SHA.
func (r *Repo) Merge(branch, msg string) string {
	r.T.Helper()
	r.Git("-c", "commit.gpgsign=false", "merge", "-q", "--no-ff", "-m", msg, branch)
	return r.Git("rev-parse", "HEAD")
}
