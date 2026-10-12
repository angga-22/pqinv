// Package certs turns X.509 certificates into inventory. It is shared by
// every probe that sees a certificate (TLS chains, SAML metadata) so they
// all describe one the same way.
package certs

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"strconv"
	"time"

	"github.com/angga-22/pqinv/internal/model"
)

// Assets describes one certificate as two findings: the public key it
// carries (usage given by the caller — a TLS leaf signs the handshake, a
// SAML encryption cert wraps assertion keys) and the hash its issuer
// signed it with. The second one matters on its own: a SHA-1 signature is
// a finding even under a 4096-bit key.
func Assets(source, location string, usage model.Usage, cert *x509.Certificate) []model.CryptoAsset {
	alg, bits := PublicKey(cert.PublicKey)
	common := func(kind string) map[string]string {
		return map[string]string{
			"kind":                kind,
			"subject":             cert.Subject.String(),
			"issuer":              cert.Issuer.String(),
			"signature_algorithm": cert.SignatureAlgorithm.String(),
			"not_after":           cert.NotAfter.UTC().Format(time.RFC3339),
			"is_ca":               strconv.FormatBool(cert.IsCA),
			"serial":              cert.SerialNumber.Text(16),
		}
	}
	assets := []model.CryptoAsset{{
		Source:    source,
		Location:  location,
		Usage:     usage,
		Algorithm: alg,
		KeyBits:   bits,
		Metadata:  common("certificate"),
	}}
	if h := SignatureHash(cert.SignatureAlgorithm); h != "" {
		assets = append(assets, model.CryptoAsset{
			Source:    source,
			Location:  location,
			Usage:     model.UsageHash,
			Algorithm: h,
			Metadata:  common("certificate-signature"),
		})
	}
	return assets
}

// PublicKey names a public key the way rules.yaml expects and reports its
// size. Unknown key types are named "Unknown" so they surface as such
// rather than vanish.
func PublicKey(pub any) (alg string, bits int) {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return "RSA", k.N.BitLen()
	case *ecdsa.PublicKey:
		return "ECDSA " + k.Curve.Params().Name, k.Curve.Params().BitSize
	case ed25519.PublicKey:
		return "Ed25519", 256
	}
	return "Unknown", 0
}

// SignatureHash is the hash function inside a certificate's signature
// algorithm. Ed25519 returns "" — its SHA-512 is part of the scheme, not
// a choice anyone made. An algorithm Go cannot name comes back as-is so
// the classifier reports it as Unknown instead of dropping it.
func SignatureHash(sa x509.SignatureAlgorithm) string {
	switch sa {
	case x509.MD2WithRSA:
		return "MD2"
	case x509.MD5WithRSA:
		return "MD5"
	case x509.SHA1WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1:
		return "SHA-1"
	case x509.SHA256WithRSA, x509.DSAWithSHA256, x509.ECDSAWithSHA256, x509.SHA256WithRSAPSS:
		return "SHA-256"
	case x509.SHA384WithRSA, x509.ECDSAWithSHA384, x509.SHA384WithRSAPSS:
		return "SHA-384"
	case x509.SHA512WithRSA, x509.ECDSAWithSHA512, x509.SHA512WithRSAPSS:
		return "SHA-512"
	case x509.PureEd25519:
		return ""
	case x509.UnknownSignatureAlgorithm:
		return "Unknown"
	}
	return sa.String()
}
