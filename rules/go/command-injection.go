package main

import (
	"context"
	"os/exec"
)

func bad(user string, ctx context.Context) {
	// ruleid: shipguard.go.command-injection
	exec.Command("sh", "-c", "ls "+user)
	// ruleid: shipguard.go.command-injection
	exec.Command("bash", "-c", user).Run()
	// ruleid: shipguard.go.command-injection
	exec.CommandContext(ctx, "sh", "-c", "echo "+user)
}

func good(user string) {
	// ok: shipguard.go.command-injection
	exec.Command("sh", "-c", "echo hello")
	// ok: shipguard.go.command-injection
	exec.Command("ls", "-l", user)
}
