package scanner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"time"
)

// Runner executes an external command. A non-zero exit is reported through
// exitCode with a nil err; err is set only when the command could not run to
// completion (failed to start, context cancelled or timed out).
type Runner func(ctx context.Context, dir string, name string, args ...string) (stdout, stderr []byte, exitCode int, err error)

// ExecRunner returns a Runner backed by os/exec. The context carries the timeout.
func ExecRunner() Runner {
	return func(ctx context.Context, dir string, name string, args ...string) ([]byte, []byte, int, error) {
		cmd := exec.CommandContext(ctx, name, args...)
		cmd.Dir = dir
		cmd.WaitDelay = 5 * time.Second
		var out, errb bytes.Buffer
		cmd.Stdout = &out
		cmd.Stderr = &errb
		runErr := cmd.Run()
		if ctxErr := ctx.Err(); ctxErr != nil {
			return out.Bytes(), errb.Bytes(), -1, fmt.Errorf("run %s: %w", name, ctxErr)
		}
		if runErr != nil {
			var ee *exec.ExitError
			if errors.As(runErr, &ee) {
				return out.Bytes(), errb.Bytes(), ee.ExitCode(), nil
			}
			return out.Bytes(), errb.Bytes(), -1, fmt.Errorf("run %s: %w", name, runErr)
		}
		return out.Bytes(), errb.Bytes(), 0, nil
	}
}

// Retry calls fn up to attempts times, sleeping 1s, 2s, 4s, ... between
// attempts (at least once, even when attempts <= 0). It stops early when ctx
// is done, including during the sleep, and returns the last error.
func Retry(ctx context.Context, attempts int, sleep func(time.Duration), fn func() error) error {
	if attempts < 1 {
		attempts = 1
	}
	var err error
	delay := time.Second
	for i := 0; i < attempts; i++ {
		if err = fn(); err == nil {
			return nil
		}
		if i == attempts-1 || ctx.Err() != nil {
			return err
		}
		sleep(delay)
		if ctx.Err() != nil {
			return err
		}
		delay *= 2
	}
	return err
}
