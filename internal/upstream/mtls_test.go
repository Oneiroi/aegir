package upstream

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aegishjalmur/aegir/internal/config"
	"github.com/aegishjalmur/aegir/internal/logging"
)

// selfSignedCert generates an in-memory self-signed ECDSA certificate and
// returns the tls.Certificate, the DER-encoded leaf cert bytes, and the
// SHA-256 hex fingerprint.
func selfSignedCert(t *testing.T) (tls.Certificate, []byte, string) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-upstream"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	digest := sha256.Sum256(certDER)
	fingerprint := hex.EncodeToString(digest[:])

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("failed to marshal private key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("failed to create tls.Certificate: %v", err)
	}

	return tlsCert, certDER, fingerprint
}

// writePEMFiles writes cert+key PEM to temporary files and returns their paths.
func writePEMFiles(t *testing.T, certPEM, keyPEM []byte) (string, string) {
	t.Helper()
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, certPEM, 0600); err != nil {
		t.Fatalf("failed to write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		t.Fatalf("failed to write key: %v", err)
	}
	return certPath, keyPath
}

// newTestManager builds a minimal Manager that is suitable for TLS tests.
// Health-check and discovery goroutines are disabled to avoid background
// noise in unit tests.
func newTestManager(t *testing.T) *Manager {
	t.Helper()
	cfg := &config.Upstream{
		LoadBalancing:  config.LoadBalancing{Strategy: "round_robin"},
		HealthCheck:    config.HealthCheck{Enabled: false, Timeout: 5},
		Discovery:      config.Discovery{Enabled: false},
		CircuitBreaker: config.CircuitBreaker{Enabled: false},
		Retry:          config.RetryConfig{Enabled: false},
	}
	logger, err := logging.New(config.Logging{
		Level:   "error",
		Format:  "json",
		HMACKey: "00000000000000000000000000000000", // 32-char placeholder for tests
	})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	return NewManager(cfg, logger)
}

// startTLSServer starts an httptest TLS server backed by the given tls.Certificate.
// The server returns 200 OK for every request.  The returned URL is usable
// inside tests.
func startTLSServer(t *testing.T, cert tls.Certificate) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// serviceStateForURL builds a minimal *ServiceState pointing at addr.
func serviceStateForURL(url string) *ServiceState {
	return &ServiceState{
		Service: &config.UpstreamService{
			Name:    "test-service",
			URL:     url,
			Timeout: 5,
			Weight:  1,
			Enabled: true,
			TLS: config.UpstreamTLS{
				Enabled:    true,
				SkipVerify: true, // we own the cert; skip chain verification so only pinning matters
			},
		},
		Healthy:      true,
		CircuitState: CircuitClosed,
	}
}

// httpClientForService wires the manager's TLS config into an http.Client for
// the given service.  It bypasses the DNS-rebinding guard by substituting the
// default dialer so that connections to 127.0.0.1 (used by httptest) succeed.
func httpClientForService(m *Manager, svc *ServiceState) *http.Client {
	client := m.createHTTPClient(svc)
	// Replace the SSRF-guarded dialer with the standard one for loopback tests.
	if tr, ok := client.Transport.(*http.Transport); ok {
		tr.DialContext = nil // use default — allows 127.0.0.1
	}
	return client
}

// TestUpstreamCertPinMatch verifies that a connection to a TLS server succeeds
// when the configured pin matches the server certificate's SHA-256 fingerprint.
func TestUpstreamCertPinMatch(t *testing.T) {
	tlsCert, _, fingerprint := selfSignedCert(t)
	srv := startTLSServer(t, tlsCert)

	mgr := newTestManager(t)
	if err := mgr.ConfigureTLS(UpstreamTLSConfig{CertPin: fingerprint}); err != nil {
		t.Fatalf("ConfigureTLS failed: %v", err)
	}

	svc := serviceStateForURL(srv.URL)
	client := httpClientForService(mgr, svc)

	resp, err := client.Get(srv.URL + "/")
	if err != nil {
		t.Fatalf("expected successful connection with correct pin, got error: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", resp.StatusCode)
	}
}

// TestUpstreamCertPinMismatch verifies that a connection is rejected — with an
// "upstream_cert_mismatch" message in the error — when the configured pin does
// not match the server certificate.
func TestUpstreamCertPinMismatch(t *testing.T) {
	tlsCert, _, _ := selfSignedCert(t)
	srv := startTLSServer(t, tlsCert)

	// Use a syntactically valid but wrong fingerprint.
	wrongPin := strings.Repeat("ab", 32) // 64 hex chars, all "ab"

	mgr := newTestManager(t)
	if err := mgr.ConfigureTLS(UpstreamTLSConfig{CertPin: wrongPin}); err != nil {
		t.Fatalf("ConfigureTLS failed: %v", err)
	}

	svc := serviceStateForURL(srv.URL)
	client := httpClientForService(mgr, svc)

	_, err := client.Get(srv.URL + "/")
	if err == nil {
		t.Fatal("expected connection to be rejected due to cert pin mismatch, got nil error")
	}
	if !strings.Contains(err.Error(), "upstream_cert_mismatch") {
		t.Fatalf("expected error to contain \"upstream_cert_mismatch\", got: %v", err)
	}
}

// TestConfigureTLS_InvalidPin verifies that ConfigureTLS rejects a pin that is
// not a valid 64-character hex string.
func TestConfigureTLS_InvalidPin(t *testing.T) {
	mgr := newTestManager(t)

	// Too short.
	if err := mgr.ConfigureTLS(UpstreamTLSConfig{CertPin: "deadbeef"}); err == nil {
		t.Fatal("expected error for too-short pin, got nil")
	}
	// Not hex.
	if err := mgr.ConfigureTLS(UpstreamTLSConfig{CertPin: strings.Repeat("zz", 32)}); err == nil {
		t.Fatal("expected error for non-hex pin, got nil")
	}
}

// TestConfigureTLS_mTLS verifies that ConfigureTLS accepts valid PEM cert+key
// files and errors on a mismatched pair.
func TestConfigureTLS_mTLS(t *testing.T) {
	// Generate two separate key pairs so we can produce a mismatched pair.
	priv1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	priv2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	makeFiles := func(pub *ecdsa.PublicKey, priv *ecdsa.PrivateKey) (certPath, keyPath string) {
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(2),
			Subject:      pkix.Name{CommonName: "client"},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
		}
		certDER, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
		keyDER, _ := x509.MarshalECPrivateKey(priv)
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
		return writePEMFiles(t, certPEM, keyPEM)
	}

	certPath1, keyPath1 := makeFiles(&priv1.PublicKey, priv1)
	_, keyPath2 := makeFiles(&priv2.PublicKey, priv2)

	mgr := newTestManager(t)

	// Valid matching pair — must succeed.
	if err := mgr.ConfigureTLS(UpstreamTLSConfig{ClientCert: certPath1, ClientKey: keyPath1}); err != nil {
		t.Fatalf("ConfigureTLS with valid pair failed: %v", err)
	}

	// Mismatched cert+key — must fail.
	if err := mgr.ConfigureTLS(UpstreamTLSConfig{ClientCert: certPath1, ClientKey: keyPath2}); err == nil {
		t.Fatal("expected error for mismatched cert/key pair, got nil")
	}

	// Only cert set without key — must fail.
	if err := mgr.ConfigureTLS(UpstreamTLSConfig{ClientCert: certPath1}); err == nil {
		t.Fatal("expected error when only ClientCert is set without ClientKey")
	}
}
