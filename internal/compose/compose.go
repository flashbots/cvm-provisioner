// Package compose is a thin wrapper around the `podman-compose` CLI.
package compose

import (
	"fmt"
	"os"
	"os/exec"
)

type Runner struct {
	// Dir contains compose.yaml (and optionally .env).
	Dir string
}

func (r Runner) Up() error {
	if _, err := os.Stat(r.Dir + "/compose.yaml"); err != nil {
		return fmt.Errorf("compose.yaml missing in %s: %w", r.Dir, err)
	}
	cmd := exec.Command("podman-compose", "-f", "compose.yaml", "up", "-d")
	cmd.Dir = r.Dir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("podman-compose up: %w", err)
	}
	return nil
}

func (r Runner) Down() error {
	cmd := exec.Command("podman-compose", "-f", "compose.yaml", "down")
	cmd.Dir = r.Dir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
