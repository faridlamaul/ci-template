package release

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/faridlamaul/shipguard/internal/testutil/gitfixture"
)

// With the real git binary: shipguard's untracked directories make the tree
// dirty (GoReleaser refuses to release) until the exclude helper has run.
func TestExcludeShipguardCleansRealGitTree(t *testing.T) {
	repo := gitfixture.New(t)
	repo.Commit("init", "README.md")
	for _, p := range []string{".shipguard-cache/x", ".shipguard/y", ".shipguard-action/z"} {
		full := filepath.Join(repo.Dir, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if repo.Git("status", "--porcelain") == "" {
		t.Fatal("precondition: the tree should be dirty")
	}
	o := Options{Dir: repo.Dir, Exec: OSExec{}, Out: io.Discard}
	for i := 0; i < 2; i++ {
		if err := excludeShipguard(context.Background(), o); err != nil {
			t.Fatal(err)
		}
	}
	if out := repo.Git("status", "--porcelain"); out != "" {
		t.Fatalf("status --porcelain = %q, want empty", out)
	}
}
