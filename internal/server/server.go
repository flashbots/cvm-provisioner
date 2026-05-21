// Package server hosts the HTTP API: POST /manifest to provision, GET /status to inspect.
package server

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"

	"github.com/flashbots/cvm-provisioner/internal/compose"
	"github.com/flashbots/cvm-provisioner/internal/extend"
	"github.com/flashbots/cvm-provisioner/internal/hash"
	"github.com/flashbots/cvm-provisioner/internal/state"
)

// ManifestRequest is the body accepted by POST /manifest.
// Only `compose` is measured into RTMR3; `env` is treated as a runtime secret.
type ManifestRequest struct {
	Compose string `json:"compose"`
	Env     string `json:"env,omitempty"`
}

type Status struct {
	Provisioned     bool   `json:"provisioned"`
	ComposeDigest   string `json:"compose_sha384,omitempty"`
	ExtendMode      string `json:"extend_mode"`
	RTMR3Extended   bool   `json:"rtmr3_extended"`
	ComposeBytes    int    `json:"compose_bytes,omitempty"`
}

type Server struct {
	State    state.Store
	Extender extend.Extender
	Compose  compose.Runner

	mu          sync.Mutex
	provisioned bool
	digestHex   string
	composeLen  int
}

func New(s state.Store, e extend.Extender, c compose.Runner) *Server {
	srv := &Server{State: s, Extender: e, Compose: c}
	// Reflect on-disk reality at construction so /status is meaningful before
	// any POST. provisioned (workload up) is set later by Provision; here we
	// only surface the already-extended digest if a previous run left one.
	if s.AlreadyExtended() {
		if d, err := s.ReadExtendedDigest(); err == nil {
			srv.digestHex = trim(d)
		}
	}
	return srv
}

func (s *Server) Routes() *http.ServeMux {
	m := http.NewServeMux()
	m.HandleFunc("POST /manifest", s.handleManifest)
	m.HandleFunc("GET /status", s.handleStatus)
	m.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	return m
}

// Provision is the shared code path used by both startup-replay and POST /manifest.
// It hashes the compose bytes, extends RTMR3 once, marks the runtime flag,
// then starts the workload. The disk-backed runtime flag is the source of
// truth — re-extending RTMR3 within one TD lifetime would corrupt the
// deterministic-replay property, so we reject if it is already set.
func (s *Server) Provision(composeBytes, envBytes []byte, persist bool) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.State.AlreadyExtended() {
		return "", errAlreadyProvisioned
	}

	d := hash.Sha384(composeBytes)
	hexDigest := hash.Hex(d)

	if persist {
		if err := s.State.WriteCompose(composeBytes, envBytes); err != nil {
			return "", fmt.Errorf("persist compose: %w", err)
		}
	}

	if err := s.Extender.Extend(3, d[:]); err != nil {
		return "", fmt.Errorf("rtmr3 extend: %w", err)
	}
	// Mark immediately after extend: RTMR3 cannot be un-extended, so even if a
	// later step (compose up) fails, a retry must NOT re-extend.
	if err := s.State.MarkExtended(hexDigest); err != nil {
		return "", fmt.Errorf("mark extended: %w", err)
	}
	s.digestHex = hexDigest
	s.composeLen = len(composeBytes)

	if err := s.Compose.Up(); err != nil {
		return hexDigest, fmt.Errorf("podman-compose up: %w", err)
	}

	s.provisioned = true
	log.Printf("provisioned: compose_sha384=%s bytes=%d extend_mode=%s", hexDigest, len(composeBytes), s.Extender.Mode())
	return hexDigest, nil
}

var errAlreadyProvisioned = fmt.Errorf("already provisioned this boot; reboot the TD to update")

func (s *Server) handleManifest(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20)) // 1 MiB cap
	if err != nil {
		http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
		return
	}
	var req ManifestRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "parse json: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.Compose == "" {
		http.Error(w, "compose field is required", http.StatusBadRequest)
		return
	}

	hexDigest, err := s.Provision([]byte(req.Compose), []byte(req.Env), true)
	if err == errAlreadyProvisioned {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status":         "provisioned",
		"compose_sha384": hexDigest,
		"extend_mode":    s.Extender.Mode(),
	})
}

func (s *Server) handleStatus(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	st := Status{
		Provisioned:   s.provisioned,
		ComposeDigest: s.digestHex,
		ExtendMode:    s.Extender.Mode(),
		RTMR3Extended: s.State.AlreadyExtended(),
		ComposeBytes:  s.composeLen,
	}
	s.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(st)
}

func trim(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r' || s[len(s)-1] == ' ') {
		s = s[:len(s)-1]
	}
	return s
}
