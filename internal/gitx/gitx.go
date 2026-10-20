// Package gitx runs the git operations shipguard needs for diff-aware scans:
// resolving the base ref, reading files at a revision, and checking out the
// base in a temporary worktree.
package gitx

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// gitError is a failed git invocation with its trimmed stderr.
type gitError struct {
	args   []string
	err    error
	stderr string
}

func (e *gitError) Error() string {
	return fmt.Sprintf("git %s: %v: %s", strings.Join(e.args, " "), e.err, e.stderr)
}

func (e *gitError) Unwrap() error { return e.err }

// git runs git in dir without ever prompting for credentials. HTTP transfers
// slower than 1000 B/s for 60s are aborted so a stalled fetch cannot hang.
func git(dir string, args ...string) ([]byte, error) {
	full := append([]string{"-c", "color.ui=false", "-c", "log.showSignature=false"}, args...)
	cmd := exec.Command("git", full...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "LC_ALL=C",
		"GIT_HTTP_LOW_SPEED_LIMIT=1000", "GIT_HTTP_LOW_SPEED_TIME=60")
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return nil, &gitError{args: args, err: err, stderr: strings.TrimSpace(stderr.String())}
	}
	return stdout.Bytes(), nil
}

// checkRev rejects revisions git could parse as an option.
func checkRev(rev string) error {
	if rev == "" {
		return errors.New("empty revision")
	}
	if strings.HasPrefix(rev, "-") {
		return fmt.Errorf("invalid revision %q", rev)
	}
	return nil
}

// commit resolves rev to a full commit SHA.
func commit(dir, rev string) (string, error) {
	out, err := git(dir, "rev-parse", "--verify", "--quiet", rev+"^{commit}")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// shaRe matches an abbreviated or full commit SHA (SHA-1 or SHA-256).
var shaRe = regexp.MustCompile(`^[0-9a-f]{7,64}$`)

// fetchRef fetches ref from origin. A branch name is fetched with an explicit
// refspec so origin/<ref> is updated even in a single-branch clone, whose
// default refspec covers only the cloned branch. A SHA is fetched as is and
// resolved via FETCH_HEAD; if that fails it is retried as a branch name.
func fetchRef(dir, ref string) (string, error) {
	if shaRe.MatchString(ref) {
		if _, err := git(dir, "fetch", "--quiet", "--no-tags", "origin", ref); err == nil {
			return commit(dir, "FETCH_HEAD")
		}
		// Not fetchable as a SHA: it may be a hex-looking branch name.
	}
	if _, err := git(dir, "check-ref-format", "refs/heads/"+ref); err != nil {
		return "", fmt.Errorf("invalid branch name: %w", err)
	}
	spec := "+refs/heads/" + ref + ":refs/remotes/origin/" + ref
	if _, err := git(dir, "fetch", "--quiet", "--no-tags", "origin", spec); err != nil {
		return "", err
	}
	return commit(dir, "refs/remotes/origin/"+ref)
}

// ResolveRef resolves ref to a commit SHA. It tries origin/<ref>, then <ref>,
// then fetches <ref> from origin (see fetchRef). The error names ref.
func ResolveRef(dir, ref string) (string, error) {
	if ref == "" {
		return "", errors.New("resolve base ref: empty ref")
	}
	if err := checkRev(ref); err != nil {
		return "", fmt.Errorf("resolve base ref %q: %w", ref, err)
	}
	try := func() (string, bool) {
		for _, r := range []string{"origin/" + ref, ref} {
			if sha, err := commit(dir, r); err == nil {
				return sha, true
			}
		}
		return "", false
	}
	if sha, ok := try(); ok {
		return sha, nil
	}
	sha, err := fetchRef(dir, ref)
	if err != nil {
		return "", fmt.Errorf("resolve base ref %q: not found locally and fetch from origin failed: %w", ref, err)
	}
	return sha, nil
}

// IsShallow reports whether the repository is a shallow clone.
func IsShallow(dir string) (bool, error) {
	out, err := git(dir, "rev-parse", "--is-shallow-repository")
	if err != nil {
		return false, fmt.Errorf("check shallow clone: %w", err)
	}
	return strings.TrimSpace(string(out)) == "true", nil
}

// Unshallow fetches the full history of a shallow clone from origin, with
// every branch, so it also works in single-branch clones.
func Unshallow(dir string) error {
	if _, err := git(dir, "fetch", "--quiet", "--unshallow", "--no-tags", "origin", "+refs/heads/*:refs/remotes/origin/*"); err != nil {
		return fmt.Errorf("unshallow clone: %w", err)
	}
	return nil
}

// Worktree checks out sha as a detached worktree in a new temp dir. cleanup
// removes the worktree and the temp dir; it is safe to call more than once.
func Worktree(dir, sha string) (string, func(), error) {
	if err := checkRev(sha); err != nil {
		return "", nil, fmt.Errorf("create worktree: %w", err)
	}
	tmp, err := os.MkdirTemp("", "shipguard-base-*")
	if err != nil {
		return "", nil, fmt.Errorf("create worktree: %w", err)
	}
	// Resolve symlinks (macOS /var → /private/var) so scanner paths made
	// relative to the worktree match the ones git reports.
	if r, err := filepath.EvalSymlinks(tmp); err == nil {
		tmp = r
	}
	path := filepath.Join(tmp, "base")
	if _, err := git(dir, "worktree", "add", "--quiet", "--detach", path, sha); err != nil {
		os.RemoveAll(tmp)
		return "", nil, fmt.Errorf("create worktree at %s: %w", sha, err)
	}
	done := false
	cleanup := func() {
		if done {
			return
		}
		done = true
		_, _ = git(dir, "worktree", "remove", "--force", path)
		os.RemoveAll(tmp)
		_, _ = git(dir, "worktree", "prune")
	}
	return path, cleanup, nil
}

// Show returns the content of path (slash-separated, relative to the
// repository root) at revision sha. ok is false when the file is absent there.
func Show(dir, sha, path string) ([]byte, bool, error) {
	if err := checkRev(sha); err != nil {
		return nil, false, fmt.Errorf("show %s: %w", path, err)
	}
	if _, err := commit(dir, sha); err != nil {
		return nil, false, fmt.Errorf("show %s at %s: unknown revision: %w", path, sha, err)
	}
	obj := sha + ":" + path
	if _, err := git(dir, "cat-file", "-e", obj); err != nil {
		return nil, false, nil
	}
	b, err := git(dir, "cat-file", "blob", obj)
	if err != nil {
		return nil, false, fmt.Errorf("show %s at %s: %w", path, sha, err)
	}
	return b, true, nil
}

// Diff returns the unified diff of path between revisions base and head.
func Diff(dir, base, head, path string) (string, error) {
	for _, r := range []string{base, head} {
		if err := checkRev(r); err != nil {
			return "", fmt.Errorf("diff %s: %w", path, err)
		}
	}
	out, err := git(dir, "diff", "--no-ext-diff", "--no-textconv", base, head, "--", path)
	if err != nil {
		return "", fmt.Errorf("diff %s: %w", path, err)
	}
	return string(out), nil
}
