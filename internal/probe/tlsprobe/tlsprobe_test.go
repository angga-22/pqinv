package tlsprobe

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"
)

// The probe is tested against real local tls.Servers pinned to specific
// parameters — no mocks, the same handshakes production runs.

func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "pqinv-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func startTLSServer(t *testing.T, cfg *tls.Config) net.Listener {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				// tls.Listen hands back lazy connections; Handshake()
				// drives the negotiation the probe is measuring.
				_ = c.(*tls.Conn).Handshake()
				_ = c.Close()
			}(conn)
		}
	}()
	return ln
}

func scanAlgorithms(t *testing.T, srvCfg *tls.Config, usage string) map[string]bool {
	t.Helper()
	ln := startTLSServer(t, srvCfg)
	p := &Probe{Timeout: 3 * time.Second}
	assets, err := p.Scan(context.Background(), ln.Addr().String())
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	got := map[string]bool{}
	for _, a := range assets {
		if string(a.Usage) == usage {
			got[a.Algorithm] = true
		}
	}
	return got
}

func TestScanDetectsHybridKeyExchange(t *testing.T) {
	// A default Go ≥1.24 server negotiates X25519MLKEM768 — the same
	// detection the cloudflare.com demo exercises, but offline.
	srvCfg := &tls.Config{Certificates: []tls.Certificate{selfSignedCert(t)}}
	got := scanAlgorithms(t, srvCfg, "KeyExchange")
	for _, want := range []string{"X25519MLKEM768", "X25519", "P-256"} {
		if !got[want] {
			t.Errorf("expected key-exchange group %s to be detected, got %v", want, got)
		}
	}
}

func TestScanRespectsServerGroupRestrictions(t *testing.T) {
	srvCfg := &tls.Config{
		Certificates:     []tls.Certificate{selfSignedCert(t)},
		CurvePreferences: []tls.CurveID{tls.CurveP256},
	}
	got := scanAlgorithms(t, srvCfg, "KeyExchange")
	if !got["P-256"] {
		t.Errorf("P-256 should be detected, got %v", got)
	}
	for _, absent := range []string{"X25519", "X25519MLKEM768", "P-384"} {
		if got[absent] {
			t.Errorf("%s reported supported but server only allows P-256 (got %v)", absent, got)
		}
	}
}

func TestScanEnumeratesProtocolVersions(t *testing.T) {
	// Default Go server: MinVersion TLS 1.2, so 1.0/1.1 must not appear.
	srvCfg := &tls.Config{Certificates: []tls.Certificate{selfSignedCert(t)}}
	got := scanAlgorithms(t, srvCfg, "Protocol")
	if !got["TLS 1.2"] || !got["TLS 1.3"] {
		t.Errorf("expected TLS 1.2 and 1.3, got %v", got)
	}
	if got["TLS 1.0"] || got["TLS 1.1"] {
		t.Errorf("legacy versions reported against a modern server: %v", got)
	}
}

func TestScanInventoriesCertificateChain(t *testing.T) {
	srvCfg := &tls.Config{Certificates: []tls.Certificate{selfSignedCert(t)}}
	ln := startTLSServer(t, srvCfg)
	p := &Probe{Timeout: 3 * time.Second}
	assets, err := p.Scan(context.Background(), ln.Addr().String())
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	found := false
	for _, a := range assets {
		if a.Usage != "Signature" {
			continue
		}
		found = true
		if a.Algorithm != "ECDSA P-256" || a.KeyBits != 256 {
			t.Errorf("cert asset = %s/%d bits, want ECDSA P-256/256", a.Algorithm, a.KeyBits)
		}
		if a.Metadata["subject"] == "" || a.Metadata["not_after"] == "" {
			t.Errorf("cert metadata incomplete: %v", a.Metadata)
		}
	}
	if !found {
		t.Error("no certificate asset emitted")
	}
}

func rsaCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "pqinv-rsa-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func TestScanDetectsRSAKeyTransport(t *testing.T) {
	// A server that still accepts RSA key exchange — invisible to a
	// default Go handshake since 1.22, hence the dedicated pass.
	srvCfg := &tls.Config{
		Certificates: []tls.Certificate{rsaCert(t)},
		CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, tls.TLS_RSA_WITH_AES_128_GCM_SHA256},
		MaxVersion:   tls.VersionTLS12,
	}
	got := scanAlgorithms(t, srvCfg, "KeyExchange")
	if !got["RSA"] {
		t.Errorf("RSA key transport should be detected, got %v", got)
	}
	if !got["X25519"] {
		t.Errorf("ECDHE groups must still be enumerated alongside, got %v", got)
	}
}

func TestScanNoFalseRSAKeyTransport(t *testing.T) {
	// An ECDSA-only server cannot do RSA key transport at all; an RSA
	// server with modern defaults refuses the suites. Neither may show it.
	for name, cfg := range map[string]*tls.Config{
		"ecdsa server":        {Certificates: []tls.Certificate{selfSignedCert(t)}},
		"rsa modern defaults": {Certificates: []tls.Certificate{rsaCert(t)}},
	} {
		got := scanAlgorithms(t, cfg, "KeyExchange")
		if got["RSA"] {
			t.Errorf("%s: RSA key transport reported but the server does not offer it (%v)", name, got)
		}
	}
}

func TestScanLegacyOnlyServerIsNotUnreachable(t *testing.T) {
	// TLS 1.2 + RSA key transport only: nothing Go offers by default.
	// The worst-case server must be inventoried, not reported as down.
	srvCfg := &tls.Config{
		Certificates: []tls.Certificate{rsaCert(t)},
		CipherSuites: []uint16{tls.TLS_RSA_WITH_AES_128_CBC_SHA},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS12,
	}
	ln := startTLSServer(t, srvCfg)
	p := &Probe{Timeout: 3 * time.Second}
	assets, err := p.Scan(context.Background(), ln.Addr().String())
	if err != nil {
		t.Fatalf("legacy-only server must scan, got: %v", err)
	}
	have := map[string]bool{}
	for _, a := range assets {
		have[string(a.Usage)+"/"+a.Algorithm] = true
	}
	for _, want := range []string{"KeyExchange/RSA", "Protocol/TLS 1.2", "Encryption/TLS_RSA_WITH_AES_128_CBC_SHA"} {
		if !have[want] {
			t.Errorf("missing %s in %v", want, have)
		}
	}
}

func TestScanEmitsCertificateSignatureHash(t *testing.T) {
	srvCfg := &tls.Config{Certificates: []tls.Certificate{selfSignedCert(t)}}
	got := scanAlgorithms(t, srvCfg, "Hash")
	if !got["SHA-256"] {
		t.Errorf("the chain's signature hash should be inventoried, got %v", got)
	}
}
