package tlsprobe

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/angga-22/pqinv/internal/model"
	"github.com/angga-22/pqinv/internal/probe/certs"
)

const defaultTimeout = 10 * time.Second

type Probe struct {
	Timeout time.Duration
}

func (p *Probe) Name() string { return "tls" }

// kexGroups are offered one at a time. X25519MLKEM768 is the hybrid
// classical+PQ group Go ships since 1.24 (ML-KEM-768, FIPS 203) — pure
// stdlib, no external crypto needed to detect PQ readiness.
var kexGroups = []struct {
	id   tls.CurveID
	name string
}{
	{tls.X25519MLKEM768, "X25519MLKEM768"},
	{tls.X25519, "X25519"},
	{tls.CurveP256, "P-256"},
	{tls.CurveP384, "P-384"},
}

// ecdheOnlyCiphers pins TLS ≤1.2 handshakes to ECDHE suites during group
// enumeration. Without this, a TLS 1.2 server could pick a plain-RSA
// key-transport suite and the handshake would succeed *without using the
// group we offered* — a false "supported" for that group. (The
// CipherSuites field is ignored for TLS 1.3, whose suites are all
// ephemeral anyway.)
var ecdheOnlyCiphers = []uint16{
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
}

// rsaKexCiphers are the RSA key-transport suites: the client encrypts
// the premaster secret to the server's RSA key, so there is no forward
// secrecy and every recorded session falls with that one key — to a
// leak today or to Shor later. Go dropped them from its defaults in
// 1.22, which is exactly why they need their own pass: a server that
// still accepts them is invisible to a default handshake.
var rsaKexCiphers = []uint16{
	tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
	tls.TLS_RSA_WITH_AES_128_CBC_SHA,
	tls.TLS_RSA_WITH_AES_256_CBC_SHA,
	tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
}

var versions = []struct {
	id   uint16
	name string
}{
	{tls.VersionTLS10, "TLS 1.0"},
	{tls.VersionTLS11, "TLS 1.1"},
	{tls.VersionTLS12, "TLS 1.2"},
	{tls.VersionTLS13, "TLS 1.3"},
}

func (p *Probe) Scan(ctx context.Context, target string) ([]model.CryptoAsset, error) {
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		return nil, fmt.Errorf("target must be host:port: %w", err)
	}

	base := &tls.Config{ServerName: host, InsecureSkipVerify: true}

	cs, err := p.handshake(ctx, target, base.Clone())
	if err != nil {
		// A legacy-only server (TLS 1.2, RSA key transport, nothing Go
		// offers by default) must still be inventoried — it is the worst
		// case, not an unreachable one. Retry with every suite we know.
		legacy := base.Clone()
		legacy.CipherSuites = append(append([]uint16{}, ecdheOnlyCiphers...), rsaKexCiphers...)
		legacy.MaxVersion = tls.VersionTLS12
		var legacyErr error
		if cs, legacyErr = p.handshake(ctx, target, legacy); legacyErr != nil {
			return nil, fmt.Errorf("baseline handshake with %s failed: %w", target, err)
		}
	}

	var assets []model.CryptoAsset

	assets = append(assets, model.CryptoAsset{
		Source:    p.Name(),
		Location:  target,
		Usage:     model.UsageEncryption,
		Algorithm: tls.CipherSuiteName(cs.CipherSuite),
		Metadata: map[string]string{
			"kind":        "cipher-suite",
			"tls_version": tls.VersionName(cs.Version),
		},
	})

	for i, cert := range cs.PeerCertificates {
		loc := fmt.Sprintf("%s cert#%d", target, i)
		assets = append(assets, certs.Assets(p.Name(), loc, model.UsageSignature, cert)...)
	}

	for _, g := range kexGroups {
		if ctx.Err() != nil {
			return assets, ctx.Err()
		}
		cfg := base.Clone()
		cfg.CurvePreferences = []tls.CurveID{g.id}
		cfg.CipherSuites = ecdheOnlyCiphers
		gcs, err := p.handshake(ctx, target, cfg)
		if err != nil {
			continue
		}
		assets = append(assets, model.CryptoAsset{
			Source:    p.Name(),
			Location:  target,
			Usage:     model.UsageKeyExchange,
			Algorithm: g.name,
			Metadata: map[string]string{
				"kind":        "key-exchange-group",
				"tls_version": tls.VersionName(gcs.Version),
			},
		})
	}

	// RSA key transport: offer only TLS_RSA_* suites and cap at TLS 1.2
	// (1.3 ignores the suite list, which would make this a false
	// positive). Success proves the server still does RSA key exchange.
	if ctx.Err() != nil {
		return assets, ctx.Err()
	}
	rsaCfg := base.Clone()
	rsaCfg.CipherSuites = rsaKexCiphers
	rsaCfg.MaxVersion = tls.VersionTLS12
	if rcs, err := p.handshake(ctx, target, rsaCfg); err == nil {
		assets = append(assets, model.CryptoAsset{
			Source:    p.Name(),
			Location:  target,
			Usage:     model.UsageKeyExchange,
			Algorithm: "RSA",
			Metadata: map[string]string{
				"kind":         "key-exchange-group",
				"tls_version":  tls.VersionName(rcs.Version),
				"cipher_suite": tls.CipherSuiteName(rcs.CipherSuite),
			},
		})
	}

	for _, v := range versions {
		if ctx.Err() != nil {
			return assets, ctx.Err()
		}
		cfg := base.Clone()
		cfg.MinVersion, cfg.MaxVersion = v.id, v.id
		if v.id < tls.VersionTLS13 {
			// Legacy-only servers answer only legacy suites; offer them
			// all so a TLS 1.0 server that does RSA key transport is
			// still seen to accept TLS 1.0.
			cfg.CipherSuites = append(append([]uint16{}, ecdheOnlyCiphers...), rsaKexCiphers...)
		}
		if _, err := p.handshake(ctx, target, cfg); err != nil {
			continue
		}
		assets = append(assets, model.CryptoAsset{
			Source:    p.Name(),
			Location:  target,
			Usage:     model.UsageProtocol,
			Algorithm: v.name,
			Metadata:  map[string]string{"kind": "protocol-version"},
		})
	}

	return assets, nil
}

func (p *Probe) handshake(ctx context.Context, target string, cfg *tls.Config) (tls.ConnectionState, error) {
	timeout := p.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	d := tls.Dialer{Config: cfg}
	conn, err := d.DialContext(ctx, "tcp", target)
	if err != nil {
		return tls.ConnectionState{}, err
	}
	defer conn.Close()
	return conn.(*tls.Conn).ConnectionState(), nil
}
