// Package persistence handles optional LUKS bring-up. Two modes:
//
//   - tdx: exec /usr/bin/tdx-init set-passphrase with the passphrase piped to
//     stdin (tdx-init reads via fmt.Scanln). The kernel-level cryptsetup +
//     mount happens inside that subprocess.
//   - mock: mkdir the path so callers see "ready". Used for laptop development.
package persistence

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/flashbots/cvm-provisioner/internal/mount"
)

type Persistence interface {
	// Init drives the LUKS bring-up. Returns the mount path on success.
	Init(passphrase string) (string, error)
	// IsReady reports whether the persistent area is available for writes.
	IsReady() bool
	Mode() string
}

type Mode int

const (
	ModeAuto Mode = iota
	ModeReal
	ModeMock
)

func ParseMode(s string) (Mode, error) {
	switch s {
	case "auto":
		return ModeAuto, nil
	case "real":
		return ModeReal, nil
	case "mock":
		return ModeMock, nil
	default:
		return 0, fmt.Errorf("unknown mode %q", s)
	}
}

type Opts struct {
	MountPath       string
	TDXInitBinary   string
	WaitForMount    time.Duration
	WaitForMountTry time.Duration
}

func (o Opts) withDefaults() Opts {
	if o.MountPath == "" {
		o.MountPath = "/persistent"
	}
	if o.TDXInitBinary == "" {
		o.TDXInitBinary = "/usr/bin/tdx-init"
	}
	if o.WaitForMount == 0 {
		o.WaitForMount = 10 * time.Second
	}
	if o.WaitForMountTry == 0 {
		o.WaitForMountTry = 200 * time.Millisecond
	}
	return o
}

func New(m Mode, opts Opts) (Persistence, error) {
	opts = opts.withDefaults()
	switch m {
	case ModeReal:
		if _, err := os.Stat(opts.TDXInitBinary); err != nil {
			return nil, fmt.Errorf("--mode real requires %s: %w", opts.TDXInitBinary, err)
		}
		return &tdxPersistence{opts: opts}, nil
	case ModeMock:
		return &mockPersistence{path: opts.MountPath}, nil
	case ModeAuto:
		if _, err := os.Stat(opts.TDXInitBinary); err == nil {
			return &tdxPersistence{opts: opts}, nil
		}
		log.Printf("persistence: %s not found, using mock mode", opts.TDXInitBinary)
		return &mockPersistence{path: opts.MountPath}, nil
	}
	return nil, fmt.Errorf("invalid mode")
}

type tdxPersistence struct{ opts Opts }

func (t *tdxPersistence) Init(passphrase string) (string, error) {
	cmd := exec.Command(t.opts.TDXInitBinary, "set-passphrase")
	cmd.Stdin = strings.NewReader(passphrase + "\n")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("tdx-init set-passphrase: %w", err)
	}
	deadline := time.Now().Add(t.opts.WaitForMount)
	for time.Now().Before(deadline) {
		if mount.IsMounted(t.opts.MountPath) {
			return t.opts.MountPath, nil
		}
		time.Sleep(t.opts.WaitForMountTry)
	}
	return "", fmt.Errorf("tdx-init returned but %s not in /proc/mounts after %s",
		t.opts.MountPath, t.opts.WaitForMount)
}

func (t *tdxPersistence) IsReady() bool { return mount.IsMounted(t.opts.MountPath) }
func (t *tdxPersistence) Mode() string  { return "tdx" }

type mockPersistence struct{ path string }

func (m *mockPersistence) Init(passphrase string) (string, error) {
	log.Printf("MOCK init: passphrase len=%d, simulating mount at %s", len(passphrase), m.path)
	if err := os.MkdirAll(m.path, 0o700); err != nil {
		return "", err
	}
	return m.path, nil
}

func (m *mockPersistence) IsReady() bool {
	fi, err := os.Stat(m.path)
	return err == nil && fi.IsDir()
}
func (m *mockPersistence) Mode() string { return "mock" }
