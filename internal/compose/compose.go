// Package compose is a thin wrapper around the `podman-compose` CLI.
package compose

import (
	"fmt"
	"os"
	"os/exec"
)

// Up runs `podman-compose -f compose.yaml up -d` in dir.
func Up(dir string) error {
	if _, err := os.Stat(dir + "/compose.yaml"); err != nil {
		return fmt.Errorf("compose.yaml missing in %s: %w", dir, err)
	}
	cmd := exec.Command("podman-compose", "-f", "compose.yaml", "up", "-d")
	cmd.Dir = dir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("podman-compose up: %w", err)
	}
	return nil
}

// Down runs `podman-compose -f compose.yaml down` in dir.
func Down(dir string) error {
	cmd := exec.Command("podman-compose", "-f", "compose.yaml", "down")
	cmd.Dir = dir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
