// Command cvm-ctl is the user-side CLI for cvm-provisioner. It wraps mTLS
// handshakes with the user's SSH-derived TLS keypair (produced by
// scripts/ssh_to_tls_cert.py) and pins the provisioner's self-signed server
// cert after a one-time `bootstrap` fetch.
//
// Subcommands:
//
//	cvm-ctl bootstrap [--via http://localhost:N]   fetch + save server cert
//	cvm-ctl init [--persistent] [--passphrase-file FILE]
//	cvm-ctl deploy COMPOSE.YAML [--env FILE]
//	cvm-ctl status
//	cvm-ctl reboot
package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/term"
)

type globalFlags struct {
	cvm        string
	certPath   string
	pinnedPath string
	insecure   bool
}

func main() {
	if len(os.Args) < 2 {
		usage(os.Stderr)
		os.Exit(2)
	}
	cmd := os.Args[1]
	if cmd == "-h" || cmd == "--help" || cmd == "help" {
		usage(os.Stdout)
		return
	}

	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	g := defaultGlobalFlags()
	fs.StringVar(&g.cvm, "cvm", g.cvm, "cvm-provisioner endpoint (host:port). Also CVM_HOST env.")
	fs.StringVar(&g.certPath, "cert", g.certPath, "TLS keypair PEM (output of ssh_to_tls_cert.py)")
	fs.StringVar(&g.pinnedPath, "pinned-cert", g.pinnedPath, "pinned server cert PEM (set by `bootstrap`)")
	fs.BoolVar(&g.insecure, "insecure", false, "skip server cert pinning (testing only)")

	var err error
	switch cmd {
	case "bootstrap":
		via := fs.String("via", "", "URL of a local cvm-reverse-proxy proxy-client (e.g. http://localhost:5000). If empty, fetches direct over insecure TLS (TOFU).")
		fs.Parse(os.Args[2:])
		err = cmdBootstrap(g, *via)
	case "init":
		persistent := fs.Bool("persistent", false, "use LUKS-backed persistent storage")
		ppFile := fs.String("passphrase-file", "", "read passphrase from file ('-' for stdin); only used with --persistent. Without this, prompts interactively.")
		fs.Parse(os.Args[2:])
		err = cmdInit(g, *persistent, *ppFile)
	case "deploy":
		envFile := fs.String("env", "", "optional .env file path (not measured into RTMR3)")
		fs.Parse(os.Args[2:])
		if fs.NArg() != 1 {
			fmt.Fprintln(os.Stderr, "deploy: expected exactly one compose.yaml argument")
			os.Exit(2)
		}
		err = cmdDeploy(g, fs.Arg(0), *envFile)
	case "status":
		fs.Parse(os.Args[2:])
		err = cmdStatus(g)
	case "reboot":
		fs.Parse(os.Args[2:])
		err = cmdReboot(g)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", cmd)
		usage(os.Stderr)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func defaultGlobalFlags() globalFlags {
	home, _ := os.UserHomeDir()
	return globalFlags{
		cvm:        os.Getenv("CVM_HOST"),
		certPath:   filepath.Join(home, ".config/cvm-ctl/client.pem"),
		pinnedPath: filepath.Join(home, ".config/cvm-ctl/server.pem"),
	}
}

func usage(w io.Writer) {
	fmt.Fprint(w, `Usage: cvm-ctl <command> [flags]

Commands:
  bootstrap                Fetch + pin the provisioner self-signed server cert.
                           Use --via http://localhost:N to go through a local
                           cvm-reverse-proxy proxy-client for aTLS attestation.
                           Without --via, fetches directly (TOFU; only safe
                           if you have verified the CVM out-of-band).
  init [--persistent]      POST /init. Defaults to ephemeral (no LUKS).
                           --persistent triggers LUKS bring-up; passphrase
                           via --passphrase-file FILE ('-' = stdin) or
                           interactive prompt.
  deploy COMPOSE.YAML      POST /manifest with the compose bytes.
                           --env FILE optionally attaches a .env passthrough.
  status                   GET /status (phase, digest, modes).
  reboot                   POST /reboot.

Flags go AFTER the command, e.g.  cvm-ctl init --cvm host:port --persistent

Common flags (every command accepts these):
  --cvm HOST:PORT          provisioner endpoint (or env CVM_HOST)
  --cert FILE              TLS keypair PEM (output of ssh_to_tls_cert.py)
                           default: ~/.config/cvm-ctl/client.pem
  --pinned-cert FILE       pinned server cert PEM
                           default: ~/.config/cvm-ctl/server.pem
  --insecure               skip server cert pinning (testing only)

Typical first-time setup:
  python3 scripts/ssh_to_tls_cert.py ~/.ssh/id_ed25519 ~/.config/cvm-ctl/client.pem
  cvm-ctl bootstrap --cvm cvm:8888                    # or --via http://localhost:5000
  cvm-ctl init --cvm cvm:8888 --persistent            # prompts for passphrase
  cvm-ctl deploy compose.yaml --cvm cvm:8888
  cvm-ctl status --cvm cvm:8888
`)
}

// ----- commands -----

func cmdBootstrap(g globalFlags, via string) error {
	var url string
	if via != "" {
		url = strings.TrimRight(via, "/") + "/cert"
	} else {
		if g.cvm == "" {
			return errors.New("--cvm or CVM_HOST is required")
		}
		url = "https://" + g.cvm + "/cert"
	}

	// Server cert pinning isn't possible yet — we're fetching the pin itself.
	tr := &http.Transport{TLSClientConfig: &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	}}
	resp, err := (&http.Client{Transport: tr}).Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: status %d", url, resp.StatusCode)
	}
	certPEM, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return errors.New("response is not a PEM-encoded cert")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse cert: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(g.pinnedPath), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(g.pinnedPath, certPEM, 0o600); err != nil {
		return err
	}
	fmt.Printf("pinned server cert saved to %s\n", g.pinnedPath)
	fmt.Printf("  subject:     %s\n", cert.Subject)
	fmt.Printf("  not_before:  %s\n", cert.NotBefore.Format("2006-01-02 15:04:05Z"))
	fmt.Printf("  not_after:   %s\n", cert.NotAfter.Format("2006-01-02 15:04:05Z"))
	return nil
}

func cmdInit(g globalFlags, persistent bool, ppFile string) error {
	body := map[string]any{}
	if persistent {
		passphrase, err := readPassphrase(ppFile)
		if err != nil {
			return err
		}
		if passphrase == "" {
			return errors.New("passphrase is empty")
		}
		body["persistent"] = true
		body["passphrase"] = passphrase
	}
	return doJSONRequest(g, "POST", "/init", body)
}

func cmdDeploy(g globalFlags, composePath, envPath string) error {
	composeBytes, err := os.ReadFile(composePath)
	if err != nil {
		return fmt.Errorf("read compose: %w", err)
	}
	body := map[string]any{"compose": string(composeBytes)}
	if envPath != "" {
		envBytes, err := os.ReadFile(envPath)
		if err != nil {
			return fmt.Errorf("read env: %w", err)
		}
		body["env"] = string(envBytes)
	}
	return doJSONRequest(g, "POST", "/manifest", body)
}

func cmdStatus(g globalFlags) error {
	return doJSONRequest(g, "GET", "/status", nil)
}

func cmdReboot(g globalFlags) error {
	return doJSONRequest(g, "POST", "/reboot", nil)
}

// ----- helpers -----

func readPassphrase(ppFile string) (string, error) {
	if ppFile == "" {
		fmt.Fprint(os.Stderr, "Passphrase: ")
		raw, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", err
		}
		return string(raw), nil
	}
	var raw []byte
	var err error
	if ppFile == "-" {
		raw, err = io.ReadAll(os.Stdin)
	} else {
		raw, err = os.ReadFile(ppFile)
	}
	if err != nil {
		return "", err
	}
	return strings.TrimRight(string(raw), "\r\n"), nil
}

func buildHTTPClient(g globalFlags) (*http.Client, error) {
	certData, err := os.ReadFile(g.certPath)
	if err != nil {
		return nil, fmt.Errorf("read --cert %s: %w", g.certPath, err)
	}
	cert, err := tls.X509KeyPair(certData, certData)
	if err != nil {
		return nil, fmt.Errorf("parse --cert: %w", err)
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
	if g.insecure {
		tlsCfg.InsecureSkipVerify = true
	} else {
		pinned, err := loadPinnedCert(g.pinnedPath)
		if err != nil {
			return nil, fmt.Errorf("load pinned cert %s: %w (run `cvm-ctl bootstrap` or pass --insecure)",
				g.pinnedPath, err)
		}
		tlsCfg.InsecureSkipVerify = true
		tlsCfg.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("server presented no cert")
			}
			if !bytes.Equal(cs.PeerCertificates[0].Raw, pinned.Raw) {
				return errors.New("server cert does not match pinned cert")
			}
			return nil
		}
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: tlsCfg}}, nil
}

func loadPinnedCert(path string) (*x509.Certificate, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, errors.New("no PEM block")
	}
	return x509.ParseCertificate(block.Bytes)
}

func doJSONRequest(g globalFlags, method, path string, body any) error {
	if g.cvm == "" {
		return errors.New("--cvm or CVM_HOST is required")
	}
	client, err := buildHTTPClient(g)
	if err != nil {
		return err
	}
	url := "https://" + g.cvm + path

	var reqBody io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reqBody = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, url, reqBody)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	fmt.Printf("%s %s\n", resp.Proto, resp.Status)
	if len(rb) > 0 {
		var pretty bytes.Buffer
		if json.Indent(&pretty, rb, "", "  ") == nil {
			fmt.Println(pretty.String())
		} else {
			os.Stdout.Write(rb)
			if rb[len(rb)-1] != '\n' {
				fmt.Println()
			}
		}
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("non-2xx response: %d", resp.StatusCode)
	}
	return nil
}
