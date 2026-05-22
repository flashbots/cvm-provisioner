// Package tlsx handles the provisioner's TLS setup:
//   - Generate (or load) a self-signed ed25519 server cert at startup.
//   - Load the authorized client pubkey from /etc/searcher_key (raw OpenSSH
//     base64 ed25519 pubkey, written by tdx-init wait-for-key).
//   - Verify a client cert's ed25519 pubkey matches that authorized pubkey
//     in constant time.
package tlsx

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// LoadOrGenerateServerCert reads server.crt+server.key from dir, or generates
// a fresh self-signed ed25519 keypair and writes them. Returns the parsed
// tls.Certificate plus the PEM-encoded cert bytes for /cert.
func LoadOrGenerateServerCert(dir string) (tls.Certificate, []byte, error) {
	crtPath := filepath.Join(dir, "server.crt")
	keyPath := filepath.Join(dir, "server.key")

	if crtBytes, err := os.ReadFile(crtPath); err == nil {
		if keyBytes, err := os.ReadFile(keyPath); err == nil {
			cert, err := tls.X509KeyPair(crtBytes, keyBytes)
			if err == nil {
				return cert, crtBytes, nil
			}
		}
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return tls.Certificate{}, nil, err
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "cvm-provisioner"},
		NotBefore:             time.Now().Add(-1 * time.Minute),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	crtPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	if err := os.WriteFile(crtPath, crtPEM, 0o600); err != nil {
		return tls.Certificate{}, nil, err
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return tls.Certificate{}, nil, err
	}

	cert, err := tls.X509KeyPair(crtPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	return cert, crtPEM, nil
}

// LoadAuthorizedPubkey reads /etc/searcher_key (raw base64 OpenSSH ed25519
// pubkey, no "ssh-ed25519 " prefix — tdx-init validates that shape) and
// returns the 32 raw ed25519 pubkey bytes.
//
// OpenSSH wire format for ed25519 pubkey is:
//
//	uint32(11) || "ssh-ed25519" || uint32(32) || <32 raw bytes>
//
// Base64-encoded, this is 68 chars.
func LoadAuthorizedPubkey(path string) (ed25519.PublicKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	s := strings.TrimSpace(string(b))
	if i := strings.IndexByte(s, ' '); i >= 0 {
		// Tolerate "ssh-ed25519 <base64>" form too.
		s = strings.TrimSpace(s[i+1:])
	}
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("authorized pubkey: base64 decode: %w", err)
	}
	if len(raw) < 4 {
		return nil, errors.New("authorized pubkey: truncated")
	}
	nameLen := binary.BigEndian.Uint32(raw[:4])
	if int(4+nameLen+4+32) != len(raw) {
		return nil, fmt.Errorf("authorized pubkey: unexpected wire length %d", len(raw))
	}
	name := string(raw[4 : 4+nameLen])
	if name != "ssh-ed25519" {
		return nil, fmt.Errorf("authorized pubkey: unsupported algo %q", name)
	}
	keyLen := binary.BigEndian.Uint32(raw[4+nameLen : 4+nameLen+4])
	if keyLen != 32 {
		return nil, fmt.Errorf("authorized pubkey: unexpected key length %d", keyLen)
	}
	return ed25519.PublicKey(raw[4+nameLen+4:]), nil
}

// VerifyClientCertPubkey returns true iff the client cert's public key is an
// ed25519 key matching `expected` in constant time.
func VerifyClientCertPubkey(cert *x509.Certificate, expected ed25519.PublicKey) bool {
	pub, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok {
		return false
	}
	if len(pub) != len(expected) {
		return false
	}
	return subtle.ConstantTimeCompare(pub, expected) == 1
}
