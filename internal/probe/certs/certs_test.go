package certs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/angga-22/pqinv/internal/model"
)

func selfSigned(t *testing.T, key any, pub any, sigAlg x509.SignatureAlgorithm) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber:       big.NewInt(7),
		Subject:            pkix.Name{CommonName: "certs-test"},
		NotBefore:          time.Now().Add(-time.Hour),
		NotAfter:           time.Now().Add(time.Hour),
		SignatureAlgorithm: sigAlg,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestAssetsSplitsKeyAndSignatureHash(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	// SHA-1 signatures are the whole reason the hash is its own asset.
	cert := selfSigned(t, key, &key.PublicKey, x509.SHA1WithRSA)

	assets := Assets("tls", "x:443 cert#0", model.UsageSignature, cert)
	if len(assets) != 2 {
		t.Fatalf("got %d assets, want key + signature hash", len(assets))
	}
	k, h := assets[0], assets[1]
	if k.Algorithm != "RSA" || k.KeyBits != 2048 || k.Usage != model.UsageSignature || k.Metadata["kind"] != "certificate" {
		t.Errorf("key asset = %+v", k)
	}
	if h.Algorithm != "SHA-1" || h.Usage != model.UsageHash || h.Metadata["kind"] != "certificate-signature" {
		t.Errorf("signature asset = %+v", h)
	}
	if k.Metadata["subject"] == "" || k.Metadata["not_after"] == "" || k.Metadata["signature_algorithm"] != "SHA1-RSA" {
		t.Errorf("metadata incomplete: %v", k.Metadata)
	}
}

func TestAssetsECDSAAndUsagePassThrough(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := selfSigned(t, key, &key.PublicKey, x509.ECDSAWithSHA384)
	assets := Assets("saml", "entity", model.UsageEncryption, cert)
	if assets[0].Algorithm != "ECDSA P-384" || assets[0].KeyBits != 384 || assets[0].Usage != model.UsageEncryption {
		t.Errorf("key asset = %+v", assets[0])
	}
	if assets[1].Algorithm != "SHA-384" {
		t.Errorf("hash = %s, want SHA-384", assets[1].Algorithm)
	}
}

func TestSignatureHashTable(t *testing.T) {
	cases := map[x509.SignatureAlgorithm]string{
		x509.MD5WithRSA:       "MD5",
		x509.SHA1WithRSA:      "SHA-1",
		x509.ECDSAWithSHA1:    "SHA-1",
		x509.SHA256WithRSA:    "SHA-256",
		x509.SHA256WithRSAPSS: "SHA-256",
		x509.ECDSAWithSHA512:  "SHA-512",
		x509.PureEd25519:      "",
	}
	for in, want := range cases {
		if got := SignatureHash(in); got != want {
			t.Errorf("SignatureHash(%s) = %q, want %q", in, got, want)
		}
	}
	if got := SignatureHash(x509.UnknownSignatureAlgorithm); got != "Unknown" {
		t.Errorf("unknown algorithm must surface, got %q", got)
	}
}
