package release

import (
	"context"
	"os"
	"path/filepath"
)

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
