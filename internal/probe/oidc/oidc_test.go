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
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"

	"github.com/angga-22/pqinv/internal/model"
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
