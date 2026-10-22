package release

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// shipguardPaths are the untracked directories shipguard creates in the
// checkout. GoReleaser refuses to release from a dirty tree, so they are kept
// out of `git status` through .git/info/exclude (local, never committed).
var shipguardPaths = []string{".shipguard/", ".shipguard-cache/", ".shipguard-action/"}

// excludeShipguard appends the missing shipguardPaths to the repository's
// info/exclude file.
func excludeShipguard(ctx context.Context, o Options) error {
	out, err := o.Exec.Run(ctx, o.Dir, nil, io.Discard, "git", "rev-parse", "--git-path", "info/exclude")
	path := strings.TrimSpace(string(out))
	if err != nil || path == "" {
		if err == nil {
			err = fmt.Errorf("git printed no path")
		}
		return fmt.Errorf("locate .git/info/exclude: %w", err)
	}
	if !filepath.IsAbs(path) {
		path = filepath.Join(o.Dir, path)
	}
	data, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read %s: %w", path, err)
	}
	have := map[string]bool{}
	for _, l := range strings.Split(string(data), "\n") {
		have[strings.TrimSpace(l)] = true
	}
	add := ""
	for _, p := range shipguardPaths {
		if !have[p] {
			add += p + "\n"
		}
	}
	if add == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create %s: %w", filepath.Dir(path), err)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	if len(data) > 0 && !bytes.HasSuffix(data, []byte("\n")) {
		add = "\n" + add
	}
	_, werr := f.WriteString(add)
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		return fmt.Errorf("write %s: %w", path, werr)
	}
	return nil
}

func binaries(ctx context.Context, o Options, r *Result) StepResult {
	found := false
	for _, n := range []string{".goreleaser.yaml", ".goreleaser.yml"} {
		if _, err := os.Stat(filepath.Join(o.Dir, n)); err == nil {
			found = true
		}
	}
	if !found {
		return StepResult{Status: "skipped", Reason: "no .goreleaser.yaml"}
	}
	gr, err := o.Tool(ctx, "goreleaser")
	if err != nil {
		return StepResult{Status: "failed", Reason: err.Error()}
	}
	cosign, err := o.Tool(ctx, "cosign")
	if err != nil {
		return StepResult{Status: "failed", Reason: err.Error()}
	}
	tag := r.Tag
	if tag == "" {
		tag = "v" + r.Version
	}
	if err := excludeShipguard(ctx, o); err != nil {
		return StepResult{Status: "failed", Reason: err.Error()}
	}
	args := []string{"release", "--clean"}
	if o.DryRun {
		args = []string{"release", "--snapshot", "--clean", "--skip=publish"}
	}
	path := filepath.Dir(cosign)
	if p := o.Getenv("PATH"); p != "" {
		path += string(os.PathListSeparator) + p
	}
	env := []string{"GORELEASER_CURRENT_TAG=" + tag, "PATH=" + path}
	if _, err := o.Exec.Run(ctx, o.Dir, env, o.Out, gr, args...); err != nil {
		return StepResult{Status: "failed", Reason: "goreleaser: " + err.Error()}
	}
	return StepResult{Status: "passed"}
}
