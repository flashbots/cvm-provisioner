// Package state manages on-disk persistence of the deployed manifest plus
// a tmpfs flag that survives service restart but not TD reboot.
//
// v1: PersistentDir is set by Promote() once /init succeeds. Before Promote,
// the store rejects writes. The same mechanism serves both modes:
//   - ephemeral: Promote(/run/cvm-provisioner/state) — state lives on tmpfs.
//   - persistent: Promote(/persistent/cvm-provisioner) — state survives reboot.
package state

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
)

type Store struct {
	mu            sync.RWMutex
	persistentDir string
	runtimeDir    string
}

func New(runtimeDir string) *Store { return &Store{runtimeDir: runtimeDir} }

func (s *Store) Promote(dir string) error {
	if dir == "" {
		return errors.New("promote: empty dir")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	s.mu.Lock()
	s.persistentDir = dir
	s.mu.Unlock()
	return nil
}

func (s *Store) PersistentDir() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.persistentDir
}

func (s *Store) IsPromoted() bool { return s.PersistentDir() != "" }

func (s *Store) ComposePath() string {
	if d := s.PersistentDir(); d != "" {
		return filepath.Join(d, "compose.yaml")
	}
	return ""
}

func (s *Store) EnvPath() string {
	if d := s.PersistentDir(); d != "" {
		return filepath.Join(d, ".env")
	}
	return ""
}

func (s *Store) ExtendedFlag() string {
	return filepath.Join(s.runtimeDir, "extended")
}

func (s *Store) HasCompose() bool {
	p := s.ComposePath()
	if p == "" {
		return false
	}
	_, err := os.Stat(p)
	return err == nil
}

func (s *Store) ReadCompose() ([]byte, error) {
	p := s.ComposePath()
	if p == "" {
		return nil, errors.New("persistent storage not initialized")
	}
	return os.ReadFile(p)
}

func (s *Store) WriteCompose(compose, env []byte) error {
	if !s.IsPromoted() {
		return errors.New("persistent storage not initialized")
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

func (s *Store) AlreadyExtended() bool {
	_, err := os.Stat(s.ExtendedFlag())
	return err == nil
}

func (s *Store) MarkExtended(digestHex string) error {
	if err := os.MkdirAll(s.runtimeDir, 0o700); err != nil {
		return err
	}
	return os.WriteFile(s.ExtendedFlag(), []byte(digestHex+"\n"), 0o600)
}

func (s *Store) ReadExtendedDigest() (string, error) {
	b, err := os.ReadFile(s.ExtendedFlag())
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
