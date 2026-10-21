//go:build unix

package run

import (
	"os/exec"
	"syscall"
)

// setGroup puts the command in its own process group.
func setGroup(c *exec.Cmd) {
	c.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// killGroup SIGKILLs the command's whole process group.
func killGroup(c *exec.Cmd) error {
	if c.Process == nil {
		return nil
	}
	return syscall.Kill(-c.Process.Pid, syscall.SIGKILL)
}
