package oidc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"

	"github.com/angga-22/pqinv/internal/model"
	"github.com/angga-22/pqinv/internal/probe/tlsprobe"
)

func newFakeIssuer(t *testing.T) *httptest.Server {
	t.Helper()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsaJWK, err := jwk.FromRaw(rsaKey.Public())
	if err != nil {
		t.Fatal(err)
	}
	mustSet(t, rsaJWK, jwk.KeyIDKey, "rsa-sig")
	mustSet(t, rsaJWK, jwk.KeyUsageKey, "sig")
	mustSet(t, rsaJWK, jwk.AlgorithmKey, jwa.RS256)

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecJWK, err := jwk.FromRaw(ecKey.Public())
	if err != nil {
		t.Fatal(err)
	}
	mustSet(t, ecJWK, jwk.KeyIDKey, "ec-sig")
	mustSet(t, ecJWK, jwk.KeyUsageKey, "sig")
	mustSet(t, ecJWK, jwk.AlgorithmKey, jwa.ES256)

	encKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	encJWK, err := jwk.FromRaw(encKey.Public())
	if err != nil {
		t.Fatal(err)
	}
	mustSet(t, encJWK, jwk.KeyIDKey, "rsa-enc")
	mustSet(t, encJWK, jwk.KeyUsageKey, "enc")
	mustSet(t, encJWK, jwk.AlgorithmKey, jwa.RSA_OAEP)

	set := jwk.NewSet()
	for _, k := range []jwk.Key{rsaJWK, ecJWK, encJWK} {
		if err := set.AddKey(k); err != nil {
			t.Fatal(err)
		}
	}

	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                srv.URL,
			"jwks_uri":                              srv.URL + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256", "ES256", "HS256", "none"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(set)
	})
	return srv
}

func mustSet(t *testing.T, key jwk.Key, name string, value any) {
	t.Helper()
	if err := key.Set(name, value); err != nil {
		t.Fatalf("set %s: %v", name, err)
	}
}

func TestScanFakeIssuer(t *testing.T) {
	srv := newFakeIssuer(t)
	p := &Probe{Client: srv.Client()}

	assets, err := p.Scan(context.Background(), srv.URL+"/") // trailing slash must not break the well-known path
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	find := func(kind, alg string) *model.CryptoAsset {
		for i := range assets {
			if assets[i].Metadata["kind"] == kind && assets[i].Algorithm == alg {
				return &assets[i]
			}
		}
		return nil
	}

	// Stream 1: advertised capabilities, including "none".
	for _, alg := range []string{"RS256", "ES256", "HS256", "none"} {
		if find("advertised-signing-alg", alg) == nil {
			t.Errorf("advertised alg %s not reported", alg)
		}
	}

	// Stream 2: published keys with real key sizes.
	rs := find("jwk", "RS256")
	if rs == nil {
		t.Fatal("published RS256 key not reported")
	}
	if rs.KeyBits != 2048 || rs.Usage != model.UsageSignature || rs.Metadata["kid"] != "rsa-sig" {
		t.Errorf("RS256 asset = %d bits, usage %s, kid %s; want 2048/Signature/rsa-sig",
			rs.KeyBits, rs.Usage, rs.Metadata["kid"])
	}

	es := find("jwk", "ES256")
	if es == nil {
		t.Fatal("published ES256 key not reported")
	}
	if es.KeyBits != 256 {
		t.Errorf("ES256 key bits = %d, want 256", es.KeyBits)
	}

	enc := find("jwk", "RSA-OAEP")
	if enc == nil {
		t.Fatal("published RSA-OAEP encryption key not reported")
	}
	if enc.Usage != model.UsageEncryption {
		t.Errorf("RSA-OAEP usage = %s, want Encryption", enc.Usage)
	}
}

func TestScanFailsWithoutJWKSURI(t *testing.T) {
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"issuer": srv.URL})
	})

	p := &Probe{Client: srv.Client()}
	if _, err := p.Scan(context.Background(), srv.URL); err == nil {
		t.Error("expected error for discovery document without jwks_uri")
	}
}

// fakeTLS records which endpoints the OIDC probe asked it to inventory.
type fakeTLS struct{ scanned []string }

func (f *fakeTLS) Name() string { return "tls" }
func (f *fakeTLS) Scan(ctx context.Context, target string) ([]model.CryptoAsset, error) {
	f.scanned = append(f.scanned, target)
	return []model.CryptoAsset{{Source: "tls", Location: target, Usage: model.UsageKeyExchange, Algorithm: "X25519MLKEM768"}}, nil
}

func TestScanInventoriesIssuerTransport(t *testing.T) {
	srv := newFakeIssuer(t) // plain http: the transport itself is the finding
	tlsp := &fakeTLS{}
	p := &Probe{Client: srv.Client(), TLS: tlsp}

	assets, err := p.Scan(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(tlsp.scanned) != 0 {
		t.Errorf("TLS probe must not be invoked for an http:// issuer, got %v", tlsp.scanned)
	}
	found := false
	for _, a := range assets {
		if a.Usage == model.UsageProtocol && a.Algorithm == "HTTP" && a.Metadata["kind"] == "plaintext-transport" {
			found = true
		}
	}
	if !found {
		t.Error("a plain-HTTP issuer must yield a Protocol/HTTP asset")
	}
}

func TestScanRunsTLSProbeOnHTTPSIssuer(t *testing.T) {
	srv := newFakeTLSIssuer(t)
	tlsp := &fakeTLS{}
	p := &Probe{Client: srv.Client(), TLS: tlsp}

	assets, err := p.Scan(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	u, _ := url.Parse(srv.URL)
	if len(tlsp.scanned) != 1 || tlsp.scanned[0] != u.Host {
		t.Errorf("TLS probe should run exactly once on %s (issuer and JWKS share a host), got %v", u.Host, tlsp.scanned)
	}
	kex := 0
	for _, a := range assets {
		if a.Source == "tls" && a.Usage == model.UsageKeyExchange {
			kex++
		}
	}
	if kex != 1 {
		t.Errorf("TLS assets should be merged into the OIDC scan, got %d key-exchange assets", kex)
	}
}

func TestScanWithRealTLSProbe(t *testing.T) {
	// End to end: a Go httptest TLS server negotiates X25519MLKEM768 by
	// default, and `scan oidc` should surface that for the issuer.
	srv := newFakeTLSIssuer(t)
	p := &Probe{Client: srv.Client(), TLS: &tlsprobe.Probe{Timeout: 3 * time.Second}}

	assets, err := p.Scan(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	got := map[string]bool{}
	for _, a := range assets {
		if a.Source == "tls" {
			got[string(a.Usage)+"/"+a.Algorithm] = true
		}
	}
	for _, want := range []string{"KeyExchange/X25519MLKEM768", "Protocol/TLS 1.3", "Signature/RSA"} {
		if !got[want] {
			t.Errorf("missing %s from issuer transport inventory: %v", want, got)
		}
	}
}

func TestScanNilTLSSkipsTransport(t *testing.T) {
	srv := newFakeIssuer(t)
	p := &Probe{Client: srv.Client()}
	assets, err := p.Scan(context.Background(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range assets {
		if a.Source == "tls" || a.Metadata["kind"] == "plaintext-transport" {
			t.Errorf("transport asset emitted without a TLS probe configured: %+v", a)
		}
	}
}

func TestScanDedupesAdvertisedAlgorithms(t *testing.T) {
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                           srv.URL,
			"jwks_uri":                                         srv.URL + "/jwks",
			"id_token_signing_alg_values_supported":            []string{"RS256", "ES256"},
			"userinfo_signing_alg_values_supported":            []string{"RS256"},
			"request_object_signing_alg_values_supported":      []string{"RS256", "none"},
			"token_endpoint_auth_signing_alg_values_supported": []string{"RS256"},
			"id_token_encryption_alg_values_supported":         []string{"RSA-OAEP", "ECDH-ES", "dir"},
			"id_token_encryption_enc_values_supported":         []string{"A128CBC-HS256", "A256GCM"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(jwk.NewSet())
	})

	p := &Probe{Client: srv.Client()}
	assets, err := p.Scan(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	byKey := map[string]model.CryptoAsset{}
	for _, a := range assets {
		byKey[string(a.Usage)+"/"+a.Algorithm] = a
	}
	rs, ok := byKey["Signature/RS256"]
	if !ok {
		t.Fatal("RS256 not reported")
	}
	count := 0
	for _, a := range assets {
		if a.Algorithm == "RS256" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("RS256 advertised in four lists must be one asset, got %d", count)
	}
	for _, field := range []string{"id_token_signing", "userinfo_signing", "request_object_signing", "token_endpoint_auth_signing"} {
		if !strings.Contains(rs.Metadata["advertised_in"], field) {
			t.Errorf("advertised_in should name %s: %q", field, rs.Metadata["advertised_in"])
		}
	}
	for _, want := range []string{"Encryption/RSA-OAEP", "Encryption/ECDH-ES", "Encryption/dir", "Encryption/A128CBC-HS256", "Encryption/A256GCM", "Signature/none"} {
		a, ok := byKey[want]
		if !ok {
			t.Errorf("missing %s", want)
			continue
		}
		if a.Usage == model.UsageEncryption && a.Metadata["kind"] != "advertised-encryption-alg" {
			t.Errorf("%s kind = %s", want, a.Metadata["kind"])
		}
	}
}

func TestKeyAssetWithoutAlgField(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name     string
		raw      any
		use      string
		wantAlg  string
		wantUse  model.Usage
		wantBits int
	}{
		{"rsa enc without alg", rsaKey.Public(), "enc", "RSA", model.UsageEncryption, 2048},
		{"ec enc without alg is ECDH", ecKey.Public(), "enc", "ECDH P-256", model.UsageEncryption, 256},
		{"ec sig without alg is ECDSA", ecKey.Public(), "sig", "ECDSA P-256", model.UsageSignature, 256},
		{"rsa no use defaults to signature", rsaKey.Public(), "", "RSA", model.UsageSignature, 2048},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			k, err := jwk.FromRaw(tc.raw)
			if err != nil {
				t.Fatal(err)
			}
			if tc.use != "" {
				mustSet(t, k, jwk.KeyUsageKey, tc.use)
			}
			a := keyAsset(discovery{JWKSURI: "u"}, k)
			if a.Algorithm != tc.wantAlg || a.Usage != tc.wantUse || a.KeyBits != tc.wantBits {
				t.Errorf("got %s/%s/%d, want %s/%s/%d", a.Algorithm, a.Usage, a.KeyBits, tc.wantAlg, tc.wantUse, tc.wantBits)
			}
		})
	}
}

// newFakeTLSIssuer is newFakeIssuer served over TLS, with an empty JWKS.
func newFakeTLSIssuer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                srv.URL,
			"jwks_uri":                              srv.URL + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(jwk.NewSet())
	})
	return srv
}
