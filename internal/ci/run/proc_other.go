//go:build !unix

package run

import "os/exec"

func setGroup(*exec.Cmd) {}

// killGroup kills only the process; process groups are unix-only.
func killGroup(c *exec.Cmd) error {
	if c.Process == nil {
		return nil
	}
	return c.Process.Kill()
}
