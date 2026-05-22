// Package server hosts the HTTP API. v1 splits endpoints by auth requirement:
//
// Read endpoints (no mTLS): /healthz, /cert, /status
// Write endpoints (mTLS):   /init, /manifest, /reboot
//
// The same mux serves both kinds; per-handler middleware enforces mTLS where
// required. The cmd/cvm-provisioner binary mounts the *full* mux on the public
// TLS listener and a *read-only* mux on a loopback plaintext listener that
// cvm-reverse-proxy forwards into.
package server

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os/exec"
	"sync"

	"github.com/flashbots/cvm-provisioner/internal/compose"
	"github.com/flashbots/cvm-provisioner/internal/extend"
	"github.com/flashbots/cvm-provisioner/internal/hash"
	"github.com/flashbots/cvm-provisioner/internal/persistence"
	"github.com/flashbots/cvm-provisioner/internal/state"
	"github.com/flashbots/cvm-provisioner/internal/tlsx"
)

type Phase string

const (
	PhaseAwaitingInit     Phase = "awaiting-init"
	PhaseAwaitingManifest Phase = "awaiting-manifest"
	PhaseProvisioned      Phase = "provisioned"
)

type Server struct {
	State          *state.Store
	Extender       extend.Extender
	Persistence    persistence.Persistence
	AuthorizedPub  ed25519.PublicKey
	ServerCertPEM  []byte
	RuntimeDir     string
	PersistentRoot string // path under which state goes after persistent init
	EphemeralRoot  string // path under which state goes for ephemeral init

	initMu      sync.Mutex
	initDone    bool
	initPersist bool
}

func New(s *state.Store, e extend.Extender, p persistence.Persistence) *Server {
	return &Server{State: s, Extender: e, Persistence: p}
}

// CurrentPhase derives the phase from observable state.
func (s *Server) CurrentPhase() Phase {
	if !s.State.IsPromoted() {
		return PhaseAwaitingInit
	}
	if !s.State.AlreadyExtended() {
		return PhaseAwaitingManifest
	}
	return PhaseProvisioned
}

// FullMux returns the mux for the public TLS listener (every endpoint).
func (s *Server) FullMux() *http.ServeMux {
	m := http.NewServeMux()
	m.HandleFunc("GET /healthz", s.handleHealthz)
	m.HandleFunc("GET /cert", s.handleCert)
	m.HandleFunc("GET /status", s.handleStatus)
	m.HandleFunc("POST /init", s.requireMTLS(s.handleInit))
	m.HandleFunc("POST /manifest", s.requireMTLS(s.handleManifest))
	m.HandleFunc("POST /reboot", s.requireMTLS(s.handleReboot))
	return m
}

// ReadOnlyMux returns the mux for the loopback plaintext listener that
// cvm-reverse-proxy forwards into. Only the unauthed read endpoints.
func (s *Server) ReadOnlyMux() *http.ServeMux {
	m := http.NewServeMux()
	m.HandleFunc("GET /healthz", s.handleHealthz)
	m.HandleFunc("GET /cert", s.handleCert)
	m.HandleFunc("GET /status", s.handleStatus)
	return m
}

// requireMTLS enforces that the request was made over TLS with a client cert
// whose ed25519 pubkey matches /etc/searcher_key.
func (s *Server) requireMTLS(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil {
			http.Error(w, "TLS required", http.StatusForbidden)
			return
		}
		if len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, "client cert required", http.StatusUnauthorized)
			return
		}
		if !tlsx.VerifyClientCertPubkey(r.TLS.PeerCertificates[0], s.AuthorizedPub) {
			http.Error(w, "client cert pubkey not authorized", http.StatusForbidden)
			return
		}
		h(w, r)
	}
}

// ----- handlers -----

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func (s *Server) handleCert(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/x-pem-file")
	_, _ = w.Write(s.ServerCertPEM)
}

type StatusResponse struct {
	Phase         Phase  `json:"phase"`
	ExtendMode    string `json:"extend_mode"`
	InitMode      string `json:"init_mode"`
	Persistent    bool   `json:"persistent"`
	ComposeSHA384 string `json:"compose_sha384,omitempty"`
	ComposeBytes  int    `json:"compose_bytes,omitempty"`
}

func (s *Server) handleStatus(w http.ResponseWriter, _ *http.Request) {
	resp := StatusResponse{
		Phase:      s.CurrentPhase(),
		ExtendMode: s.Extender.Mode(),
		InitMode:   s.Persistence.Mode(),
		Persistent: s.initPersist,
	}
	if d, err := s.State.ReadExtendedDigest(); err == nil {
		resp.ComposeSHA384 = trim(d)
	}
	if s.State.HasCompose() {
		if b, err := s.State.ReadCompose(); err == nil {
			resp.ComposeBytes = len(b)
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

type InitRequest struct {
	Persistent bool   `json:"persistent,omitempty"`
	Passphrase string `json:"passphrase,omitempty"`
}

type InitResponse struct {
	Phase         Phase  `json:"phase"`
	Persistent    bool   `json:"persistent"`
	ComposeSHA384 string `json:"compose_sha384,omitempty"`
}

func (s *Server) handleInit(w http.ResponseWriter, r *http.Request) {
	s.initMu.Lock()
	defer s.initMu.Unlock()

	if s.CurrentPhase() != PhaseAwaitingInit {
		http.Error(w, "init already done; reboot the TD to re-init", http.StatusConflict)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 8192))
	if err != nil {
		http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
		return
	}
	var req InitRequest
	// Empty body is OK — defaults to ephemeral.
	if len(body) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "parse json: "+err.Error(), http.StatusBadRequest)
			return
		}
	}
	if req.Persistent && req.Passphrase == "" {
		http.Error(w, "persistent=true requires passphrase", http.StatusBadRequest)
		return
	}

	var stateDir string
	if req.Persistent {
		mountPath, err := s.Persistence.Init(req.Passphrase)
		if err != nil {
			http.Error(w, "persistence init: "+err.Error(), http.StatusInternalServerError)
			return
		}
		stateDir = mountPath + "/cvm-provisioner"
	} else {
		stateDir = s.EphemeralRoot
	}
	if err := s.State.Promote(stateDir); err != nil {
		http.Error(w, "promote: "+err.Error(), http.StatusInternalServerError)
		return
	}
	s.initDone = true
	s.initPersist = req.Persistent
	log.Printf("init: mode=%s state-dir=%s", initModeStr(req.Persistent), stateDir)

	resp := InitResponse{Phase: s.CurrentPhase(), Persistent: req.Persistent}

	// Auto-replay if a manifest is already present (persistent reboot case).
	if s.State.HasCompose() && !s.State.AlreadyExtended() {
		composeBytes, _ := s.State.ReadCompose()
		hexDigest, err := s.provisionLocked(composeBytes, nil, false)
		if err != nil {
			log.Printf("auto-replay failed: %v", err)
			// Don't fail /init — operator can retry /manifest manually. But surface it.
			resp.ComposeSHA384 = hexDigest
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(w).Encode(resp)
			return
		}
		resp.ComposeSHA384 = hexDigest
		resp.Phase = s.CurrentPhase()
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

type ManifestRequest struct {
	Compose string `json:"compose"`
	Env     string `json:"env,omitempty"`
}

type ManifestResponse struct {
	Phase         Phase  `json:"phase"`
	ComposeSHA384 string `json:"compose_sha384"`
	ExtendMode    string `json:"extend_mode"`
}

func (s *Server) handleManifest(w http.ResponseWriter, r *http.Request) {
	phase := s.CurrentPhase()
	if phase == PhaseAwaitingInit {
		http.Error(w, "init not done; POST /init first", http.StatusPreconditionFailed)
		return
	}
	if phase == PhaseProvisioned {
		http.Error(w, "already provisioned this boot; reboot the TD to update", http.StatusConflict)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
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
		http.Error(w, "compose is required", http.StatusBadRequest)
		return
	}

	// Note: provisionLocked uses its own guard against double-extend.
	hexDigest, err := s.provision([]byte(req.Compose), []byte(req.Env), true)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(ManifestResponse{
		Phase:         s.CurrentPhase(),
		ComposeSHA384: hexDigest,
		ExtendMode:    s.Extender.Mode(),
	})
}

func (s *Server) handleReboot(w http.ResponseWriter, _ *http.Request) {
	log.Printf("reboot requested")
	go func() {
		// Detach so the HTTP response can flush first.
		if err := exec.Command("/sbin/reboot").Run(); err != nil {
			log.Printf("reboot exec: %v", err)
		}
	}()
	w.WriteHeader(http.StatusAccepted)
	_, _ = w.Write([]byte("reboot scheduled\n"))
}

// ----- provisioning core -----

// provision is the locked entry point used by POST /manifest. It serializes
// against /init's auto-replay via s.initMu.
func (s *Server) provision(composeBytes, envBytes []byte, persist bool) (string, error) {
	s.initMu.Lock()
	defer s.initMu.Unlock()
	return s.provisionLocked(composeBytes, envBytes, persist)
}

// provisionLocked must be called with s.initMu held.
func (s *Server) provisionLocked(composeBytes, envBytes []byte, persist bool) (string, error) {
	if s.State.AlreadyExtended() {
		return "", fmt.Errorf("already extended this boot")
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
	if err := s.State.MarkExtended(hexDigest); err != nil {
		return "", fmt.Errorf("mark extended: %w", err)
	}
	if err := compose.Up(s.State.PersistentDir()); err != nil {
		return hexDigest, fmt.Errorf("podman-compose up: %w", err)
	}
	log.Printf("provisioned: compose_sha384=%s bytes=%d extend_mode=%s",
		hexDigest, len(composeBytes), s.Extender.Mode())
	return hexDigest, nil
}

// ----- helpers -----

func initModeStr(persistent bool) string {
	if persistent {
		return "persistent"
	}
	return "ephemeral"
}

func trim(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r' || s[len(s)-1] == ' ') {
		s = s[:len(s)-1]
	}
	return s
}

// ensure imports
var _ = hex.EncodeToString
