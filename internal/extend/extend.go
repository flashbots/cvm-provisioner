// Package extend wraps RTMR3 extension behind a small interface so the
// service can run without TDX hardware (mock mode) for local development.
package extend

import (
	"fmt"
	"log"
	"os"

	"github.com/google/go-tdx-guest/rtmr"
)

const (
	sysfsRTMR3Node    = "/sys/class/misc/tdx_guest/measurements/rtmr3:sha384"
	configfsRTMRsPath = "/sys/kernel/config/tsm/rtmrs"
)

type Extender interface {
	Extend(index int, digest []byte) error
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
		return 0, fmt.Errorf("unknown mode %q (expected auto|real|mock)", s)
	}
}

// New picks an Extender according to mode. In auto, it falls back to mock
// with a warning when no TDX kernel interface is present.
func New(m Mode) (Extender, error) {
	switch m {
	case ModeReal:
		if !tdxAvailable() {
			return nil, fmt.Errorf("--mode real requires TDX kernel interface (%s or %s), neither found",
				sysfsRTMR3Node, configfsRTMRsPath)
		}
		return realExtender{}, nil
	case ModeMock:
		return mockExtender{}, nil
	case ModeAuto:
		if tdxAvailable() {
			return realExtender{}, nil
		}
		log.Printf("extend: no TDX kernel interface found, falling back to mock mode (use --mode real to require TDX)")
		return mockExtender{}, nil
	}
	return nil, fmt.Errorf("invalid mode")
}

func tdxAvailable() bool {
	if _, err := os.Stat(sysfsRTMR3Node); err == nil {
		return true
	}
	if _, err := os.Stat(configfsRTMRsPath); err == nil {
		return true
	}
	return false
}

type realExtender struct{}

func (realExtender) Extend(index int, digest []byte) error {
	if len(digest) != 48 {
		return fmt.Errorf("digest must be 48 bytes, got %d", len(digest))
	}
	return rtmr.ExtendDigest(index, digest)
}
func (realExtender) Mode() string { return "tdx" }

type mockExtender struct{}

func (mockExtender) Extend(index int, digest []byte) error {
	if len(digest) != 48 {
		return fmt.Errorf("digest must be 48 bytes, got %d", len(digest))
	}
	log.Printf("MOCK extend RTMR%d <- sha384=%x", index, digest)
	return nil
}
func (mockExtender) Mode() string { return "mock" }
