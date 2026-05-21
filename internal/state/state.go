// Package state manages on-disk persistence of the deployed manifest plus
// a tmpfs flag that survives service restart but not TD reboot. The split
// ensures that systemd restarts do not double-extend RTMR3 within one boot,
// while a TD reboot deterministically replays the manifest from disk.
package state

import (
	"errors"
	"os"
	"path/filepath"
)

type Store struct {
	// PersistentDir survives TD reboot (e.g. /persistent for the LUKS-backed
	// disk in v1; /var/lib/cvm-provisioner in v0 — best-effort only).
	PersistentDir string

	// RuntimeDir lives on tmpfs (e.g. /run/cvm-provisioner). Used to track
	// that RTMR3 has already been extended this boot.
	RuntimeDir string
}

func (s Store) ComposePath() string  { return filepath.Join(s.PersistentDir, "compose.yaml") }
func (s Store) EnvPath() string      { return filepath.Join(s.PersistentDir, ".env") }
func (s Store) ExtendedFlag() string { return filepath.Join(s.RuntimeDir, "extended") }

func (s Store) HasCompose() bool {
	_, err := os.Stat(s.ComposePath())
	return err == nil
}

func (s Store) ReadCompose() ([]byte, error) {
	return os.ReadFile(s.ComposePath())
}

func (s Store) WriteCompose(compose, env []byte) error {
	if err := os.MkdirAll(s.PersistentDir, 0o700); err != nil {
		return err
	}
	if err := writeAtomic(s.ComposePath(), compose, 0o600); err != nil {
		return err
	}
	if len(env) > 0 {
		if err := writeAtomic(s.EnvPath(), env, 0o600); err != nil {
			return err
		}
	}
	return nil
}

func (s Store) AlreadyExtended() bool {
	_, err := os.Stat(s.ExtendedFlag())
	return err == nil
}

func (s Store) MarkExtended(digestHex string) error {
	if err := os.MkdirAll(s.RuntimeDir, 0o700); err != nil {
		return err
	}
	return os.WriteFile(s.ExtendedFlag(), []byte(digestHex+"\n"), 0o600)
}

func (s Store) ReadExtendedDigest() (string, error) {
	b, err := os.ReadFile(s.ExtendedFlag())
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	if path == "" {
		return errors.New("empty path")
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
