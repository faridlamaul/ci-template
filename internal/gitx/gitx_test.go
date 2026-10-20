package gitx

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/faridlamaul/shipguard/internal/testutil/gitfixture"
)

// isolate keeps the host git configuration out of gitx's own git calls.
func isolate(t *testing.T) {
	t.Helper()
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
}

// clone clones src into a new temp dir and returns it as a fixture repo.
func clone(t *testing.T, src *gitfixture.Repo, extra ...string) *gitfixture.Repo {
	t.Helper()
	dst := filepath.Join(t.TempDir(), "clone")
	src.Git(append(append([]string{"clone", "-q"}, extra...), "file://"+src.Dir, dst)...)
	return &gitfixture.Repo{T: t, Dir: dst}
}

func TestResolveRefOriginPrefix(t *testing.T) {
	isolate(t)
	origin := gitfixture.New(t)
	origin.Commit("base", "a.txt")
	origin.Git("checkout", "-q", "-b", "feature")
	want := origin.Commit("feature", "b.txt")
	origin.Git("checkout", "-q", "main")

	c := clone(t, origin)
	// "feature" exists only as origin/feature in the clone.
	got, err := ResolveRef(c.Dir, "feature")
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("ResolveRef(feature) = %s, want %s", got, want)
	}
}

func TestResolveRefLocalAndSHA(t *testing.T) {
	isolate(t)
	r := gitfixture.New(t)
	sha := r.Commit("base", "a.txt")
	for _, ref := range []string{"main", sha, sha[:12]} {
		got, err := ResolveRef(r.Dir, ref)
		if err != nil || got != sha {
			t.Errorf("ResolveRef(%s) = %q, %v; want %s", ref, got, err, sha)
		}
	}
}

func TestResolveRefFetchesMissingRef(t *testing.T) {
	isolate(t)
	origin := gitfixture.New(t)
	origin.Commit("base", "a.txt")
	c := clone(t, origin)
	origin.Git("checkout", "-q", "-b", "late")
	want := origin.Commit("late", "b.txt")

	got, err := ResolveRef(c.Dir, "late")
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("ResolveRef(late) = %s, want %s", got, want)
	}
}

func TestResolveRefErrors(t *testing.T) {
	isolate(t)
	r := gitfixture.New(t)
	r.Commit("base", "a.txt")
	for _, ref := range []string{"", "nope", "-x"} {
		_, err := ResolveRef(r.Dir, ref)
		if err == nil {
			t.Errorf("ResolveRef(%q): want error", ref)
			continue
		}
		if ref != "" && !strings.Contains(err.Error(), ref) {
			t.Errorf("ResolveRef(%q): error %q does not name the ref", ref, err)
		}
	}
}

func TestShowAndDiff(t *testing.T) {
	isolate(t)
	r := gitfixture.New(t)
	base := r.Commit("base", "a.txt")
	head := r.Commit("head", "a.txt", "b.txt")

	b, ok, err := Show(r.Dir, base, "a.txt")
	if err != nil || !ok || string(b) != "base\n1\n" {
		t.Fatalf("Show(base, a.txt) = %q, %v, %v", b, ok, err)
	}
	if _, ok, err := Show(r.Dir, base, "b.txt"); err != nil || ok {
		t.Fatalf("Show(base, b.txt) ok=%v err=%v; want absent", ok, err)
	}
	if _, _, err := Show(r.Dir, "0000000000000000000000000000000000000000", "a.txt"); err == nil {
		t.Fatal("Show with unknown revision: want error")
	}

	d, err := Diff(r.Dir, base, head, "a.txt")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(d, "-base") || !strings.Contains(d, "+head") || strings.Contains(d, "b.txt") {
		t.Fatalf("Diff = %q", d)
	}
}

func TestWorktree(t *testing.T) {
	isolate(t)
	r := gitfixture.New(t)
	base := r.Commit("base", "a.txt")
	r.Commit("head", "b.txt")

	path, cleanup, err := Worktree(r.Dir, base)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(path, "a.txt")); err != nil {
		t.Errorf("a.txt missing in worktree: %v", err)
	}
	if _, err := os.Stat(filepath.Join(path, "b.txt")); !os.IsNotExist(err) {
		t.Errorf("b.txt must not exist at base: %v", err)
	}
	cleanup()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("worktree dir still present after cleanup: %v", err)
	}
	if out := r.Git("worktree", "list"); strings.Count(out, "\n") != 0 {
		t.Errorf("worktree still registered:\n%s", out)
	}

	if _, _, err := Worktree(r.Dir, "nope"); err == nil {
		t.Error("Worktree(nope): want error")
	}
}

func TestShallowUnshallow(t *testing.T) {
	isolate(t)
	origin := gitfixture.New(t)
	origin.Commit("one", "a.txt")
	origin.Commit("two", "a.txt")
	c := clone(t, origin, "--depth", "1")

	sh, err := IsShallow(c.Dir)
	if err != nil || !sh {
		t.Fatalf("IsShallow = %v, %v; want true", sh, err)
	}
	if err := Unshallow(c.Dir); err != nil {
		t.Fatal(err)
	}
	if sh, err := IsShallow(c.Dir); err != nil || sh {
		t.Fatalf("after Unshallow IsShallow = %v, %v; want false", sh, err)
	}
}

// singleBranch returns origin (main + feature) and a shallow single-branch
// clone of feature, as Bitbucket Pipelines clones by default.
func singleBranch(t *testing.T) (origin, c *gitfixture.Repo, mainSHA string) {
	t.Helper()
	origin = gitfixture.New(t)
	origin.Commit("one", "a.txt")
	mainSHA = origin.Commit("two", "a.txt")
	origin.Git("checkout", "-q", "-b", "feature")
	origin.Commit("feat", "b.txt")
	origin.Git("checkout", "-q", "main")
	c = clone(t, origin, "--single-branch", "--branch", "feature", "--depth", "1")
	return origin, c, mainSHA
}

func TestResolveRefSingleBranchClone(t *testing.T) {
	isolate(t)
	_, c, mainSHA := singleBranch(t)
	got, err := ResolveRef(c.Dir, "main")
	if err != nil {
		t.Fatal(err)
	}
	if got != mainSHA {
		t.Fatalf("ResolveRef(main) = %s, want %s", got, mainSHA)
	}
	if out := c.Git("rev-parse", "origin/main"); out != mainSHA {
		t.Errorf("origin/main = %s, want it updated to %s", out, mainSHA)
	}
}

func TestResolveRefFetchesSHA(t *testing.T) {
	isolate(t)
	origin, c, _ := singleBranch(t)
	origin.Git("checkout", "-q", "-b", "other")
	want := origin.Commit("other", "c.txt")
	origin.Git("config", "uploadpack.allowAnySHA1InWant", "true")
	got, err := ResolveRef(c.Dir, want)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("ResolveRef(sha) = %s, want %s", got, want)
	}
}

func TestUnshallowSingleBranchClone(t *testing.T) {
	isolate(t)
	_, c, mainSHA := singleBranch(t)
	if err := Unshallow(c.Dir); err != nil {
		t.Fatal(err)
	}
	if sh, err := IsShallow(c.Dir); err != nil || sh {
		t.Fatalf("IsShallow = %v, %v; want false", sh, err)
	}
	if out := c.Git("rev-parse", "origin/main"); out != mainSHA {
		t.Errorf("origin/main = %s, want %s after Unshallow", out, mainSHA)
	}
}

func TestIsAncestor(t *testing.T) {
	isolate(t)
	r := gitfixture.New(t)
	one := r.Commit("one", "a.txt")
	two := r.Commit("two", "a.txt")
	r.Git("checkout", "-q", "-b", "side", one)
	side := r.Commit("side", "b.txt")
	cases := []struct {
		a, b string
		want bool
	}{
		{one, two, true}, {two, two, true}, {two, one, false}, {side, two, false}, {two, side, false},
	}
	for _, c := range cases {
		got, err := IsAncestor(r.Dir, c.a, c.b)
		if err != nil || got != c.want {
			t.Errorf("IsAncestor(%.7s, %.7s) = %v, %v; want %v", c.a, c.b, got, err, c.want)
		}
	}
	if _, err := IsAncestor(r.Dir, "nope", two); err == nil {
		t.Error("unknown revision: want error")
	}
	if _, err := IsAncestor(r.Dir, "--all", two); err == nil {
		t.Error("option-like revision: want error")
	}
}
