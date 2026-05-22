// Command cvm-provisioner is the in-CVM agent. v1 collapses LUKS bring-up
// and manifest deployment behind a single mTLS-authenticated HTTP API.
//
// Two listeners:
//   - public TLS on --listen (default :8888): full API. Write endpoints
//     (/init, /manifest, /reboot) require mTLS where the client cert's
//     ed25519 pubkey matches /etc/searcher_key. Read endpoints (/healthz,
//     /cert, /status) work without a client cert.
//   - loopback plaintext on --listen-loopback (default 127.0.0.1:8889):
//     read-only subset. This is the target cvm-reverse-proxy forwards into
//     so its aTLS channel exposes the read endpoints to remote callers.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/flashbots/cvm-provisioner/internal/extend"
	"github.com/flashbots/cvm-provisioner/internal/persistence"
	"github.com/flashbots/cvm-provisioner/internal/server"
	"github.com/flashbots/cvm-provisioner/internal/state"
	"github.com/flashbots/cvm-provisioner/internal/tlsx"
)

func main() {
	var (
		listen         = flag.String("listen", "0.0.0.0:8888", "public TLS listen address")
		listenLoopback = flag.String("listen-loopback", "127.0.0.1:8889", "plaintext loopback for cvm-reverse-proxy front")
		runtimeDir     = flag.String("runtime-dir", "/run/cvm-provisioner", "tmpfs dir for server cert + extended flag")
		persistentRoot = flag.String("persistent-mount", "/persistent", "where /init (persistent mode) mounts the LUKS volume")
		tdxInit        = flag.String("tdx-init-binary", "/usr/bin/tdx-init", "path to tdx-init for set-passphrase")
		authPubkey     = flag.String("authorized-pubkey-file", "/etc/searcher_key", "raw OpenSSH base64 ed25519 pubkey (written by tdx-init wait-for-key)")
		modeFlag       = flag.String("mode", "auto", "auto|real|mock — governs both RTMR3 extend and tdx-init bring-up")
	)
	flag.Parse()

	if err := os.MkdirAll(*runtimeDir, 0o700); err != nil {
		log.Fatalf("mkdir runtime-dir: %v", err)
	}

	exMode, err := extend.ParseMode(*modeFlag)
	if err != nil {
		log.Fatalf("--mode: %v", err)
	}
	ex, err := extend.New(exMode)
	if err != nil {
		log.Fatalf("extend.New: %v", err)
	}
	pMode, err := persistence.ParseMode(*modeFlag)
	if err != nil {
		log.Fatalf("--mode: %v", err)
	}
	pst, err := persistence.New(pMode, persistence.Opts{
		MountPath:     *persistentRoot,
		TDXInitBinary: *tdxInit,
	})
	if err != nil {
		log.Fatalf("persistence.New: %v", err)
	}

	st := state.New(*runtimeDir)

	serverCert, serverCertPEM, err := tlsx.LoadOrGenerateServerCert(*runtimeDir)
	if err != nil {
		log.Fatalf("server cert: %v", err)
	}
	authPub, err := tlsx.LoadAuthorizedPubkey(*authPubkey)
	if err != nil {
		log.Fatalf("authorized pubkey (%s): %v", *authPubkey, err)
	}
	log.Printf("authorized pubkey loaded: %x (32 bytes)", []byte(authPub))

	srv := server.New(st, ex, pst)
	srv.AuthorizedPub = authPub
	srv.ServerCertPEM = serverCertPEM
	srv.RuntimeDir = *runtimeDir
	srv.PersistentRoot = *persistentRoot
	srv.EphemeralRoot = *runtimeDir + "/state"

	log.Printf("cvm-provisioner v1 starting: listen=%s loopback=%s extend-mode=%s init-mode=%s",
		*listen, *listenLoopback, ex.Mode(), pst.Mode())

	// RequestClientCert: ask the client to present a cert, but skip Go's
	// chain verification (the user's cert is self-signed, derived from their
	// SSH key — there is no CA). Our middleware verifies the cert's ed25519
	// pubkey against /etc/searcher_key directly.
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequestClientCert,
		MinVersion:   tls.VersionTLS12,
	}

	pubSrv := &http.Server{
		Addr:              *listen,
		Handler:           srv.FullMux(),
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: 10 * time.Second,
	}
	loopbackSrv := &http.Server{
		Addr:              *listenLoopback,
		Handler:           srv.ReadOnlyMux(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		log.Printf("listening (TLS) on %s", *listen)
		if err := pubSrv.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("public TLS: %v", err)
		}
	}()
	go func() {
		log.Printf("listening (plaintext, loopback) on %s", *listenLoopback)
		if err := loopbackSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("loopback: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	log.Printf("shutting down")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = pubSrv.Shutdown(ctx)
	_ = loopbackSrv.Shutdown(ctx)
}
