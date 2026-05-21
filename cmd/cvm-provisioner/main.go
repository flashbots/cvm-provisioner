// Command cvm-provisioner is the in-CVM agent that receives a docker-compose
// manifest at runtime, extends RTMR3 with its SHA384, and launches the workload
// via podman-compose. On TD reboot, the persisted manifest is replayed
// deterministically so the post-boot RTMR3 matches the operator's pinned value.
package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/flashbots/cvm-provisioner/internal/compose"
	"github.com/flashbots/cvm-provisioner/internal/extend"
	"github.com/flashbots/cvm-provisioner/internal/server"
	"github.com/flashbots/cvm-provisioner/internal/state"
)

func main() {
	var (
		listen     = flag.String("listen", ":8888", "HTTP listen address")
		stateDir   = flag.String("state-dir", "/var/lib/cvm-provisioner", "persistent manifest dir (survives TD reboot if backed by persistent disk)")
		runtimeDir = flag.String("runtime-dir", "/run/cvm-provisioner", "tmpfs flag dir (survives service restart, lost on TD reboot)")
		modeFlag   = flag.String("mode", "auto", "RTMR3 extend mode: auto|real|mock")
	)
	flag.Parse()

	mode, err := extend.ParseMode(*modeFlag)
	if err != nil {
		log.Fatalf("bad --mode: %v", err)
	}
	ext, err := extend.New(mode)
	if err != nil {
		log.Fatalf("extend.New: %v", err)
	}
	log.Printf("cvm-provisioner starting: listen=%s state-dir=%s runtime-dir=%s extend-mode=%s",
		*listen, *stateDir, *runtimeDir, ext.Mode())

	st := state.Store{PersistentDir: *stateDir, RuntimeDir: *runtimeDir}
	cmp := compose.Runner{Dir: *stateDir}
	srv := server.New(st, ext, cmp)

	if err := bootProvision(srv, st, cmp); err != nil {
		// Boot provisioning failure is non-fatal: we still expose /status and
		// /healthz so the operator can diagnose. POST /manifest will return 409
		// if RTMR3 was already extended.
		log.Printf("boot provision: %v", err)
	}

	httpSrv := &http.Server{
		Addr:              *listen,
		Handler:           srv.Routes(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		log.Printf("listening on %s", *listen)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("http: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	log.Printf("shutting down")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(ctx)
}

// bootProvision runs the startup-time replay path:
//   - If RTMR3 was already extended this boot (tmpfs flag present), do nothing.
//     The service restarted; the manifest is up and RTMR3 should not be re-extended.
//   - Else if a persisted manifest exists, replay: extend RTMR3 then `compose up`.
//   - Else, do nothing — wait for POST /manifest.
func bootProvision(srv *server.Server, st state.Store, _ compose.Runner) error {
	if st.AlreadyExtended() {
		log.Printf("boot: RTMR3 already extended this boot (flag present), skipping replay")
		return nil
	}
	if !st.HasCompose() {
		log.Printf("boot: no persisted manifest, waiting for POST /manifest")
		return nil
	}
	composeBytes, err := st.ReadCompose()
	if err != nil {
		return err
	}
	envBytes, _ := os.ReadFile(st.EnvPath())
	log.Printf("boot: replaying persisted manifest (%d bytes)", len(composeBytes))
	_, err = srv.Provision(composeBytes, envBytes, false)
	return err
}
