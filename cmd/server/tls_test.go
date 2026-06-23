package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/aegishjalmur/aegir/internal/config"
)

// TestTLSMinimumVersionIsTLS13 is the ISC-73 probe: TLS 1.3 minimum enforced.
// It asserts the configured MinVersion and proves it behaviorally by driving a
// real handshake with the server side using createTLSConfig — a client capped
// at TLS 1.2 must be refused, a TLS 1.3 client must succeed and negotiate 1.3.
// (In-process equivalent of `openssl s_client -tls1_2` being rejected.) Uses an
// in-memory net.Pipe with HandshakeContext deadlines, so it is deterministic
// and cannot hang.
func TestTLSMinimumVersionIsTLS13(t *testing.T) {
	serverCfg := createTLSConfig(&config.Config{})
	if serverCfg.MinVersion != tls.VersionTLS13 {
		t.Fatalf("MinVersion = 0x%04x, want TLS 1.3 (0x%04x)", serverCfg.MinVersion, tls.VersionTLS13)
	}
	serverCfg = serverCfg.Clone()
	serverCfg.Certificates = []tls.Certificate{selfSignedCert(t)}

	handshake := func(clientMax uint16) (tls.ConnectionState, error) {
		serverConn, clientConn := net.Pipe()
		defer serverConn.Close()
		defer clientConn.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		server := tls.Server(serverConn, serverCfg)
		client := tls.Client(clientConn, &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // test client against the test's own self-signed cert
			MinVersion:         tls.VersionTLS12,
			MaxVersion:         clientMax,
		})

		srvErr := make(chan error, 1)
		go func() { srvErr <- server.HandshakeContext(ctx) }()
		clientErr := client.HandshakeContext(ctx)
		<-srvErr // let the server goroutine finish

		if clientErr != nil {
			return tls.ConnectionState{}, clientErr
		}
		return client.ConnectionState(), nil
	}

	t.Run("TLS 1.2 client is rejected", func(t *testing.T) {
		if _, err := handshake(tls.VersionTLS12); err == nil {
			t.Fatal("expected TLS 1.2 handshake to be rejected, but it succeeded")
		}
	})

	t.Run("TLS 1.3 client succeeds", func(t *testing.T) {
		state, err := handshake(tls.VersionTLS13)
		if err != nil {
			t.Fatalf("expected TLS 1.3 handshake to succeed, got: %v", err)
		}
		if state.Version != tls.VersionTLS13 {
			t.Fatalf("negotiated version = 0x%04x, want TLS 1.3 (0x%04x)", state.Version, tls.VersionTLS13)
		}
	})
}

// selfSignedCert returns an ephemeral cert for the in-process TLS server side.
func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}
