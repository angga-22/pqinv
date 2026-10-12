package classify

import (
	"testing"

	"github.com/angga-22/pqinv/internal/model"
)

// One table over the embedded rules.yaml: every row encodes a design
// decision (HNDL makes key exchange High while signatures are Medium,
// Grover vs Shor for symmetric crypto, RSA<2048 broken classically…).
func TestClassifySeedRules(t *testing.T) {
	c, err := New()
	if err != nil {
		t.Fatalf("loading embedded rules: %v", err)
	}

	cases := []struct {
		name      string
		algorithm string
		usage     model.Usage
		keyBits   int
		wantClass model.Class
		wantUrg   model.Urgency
	}{
		{"hybrid kex", "X25519MLKEM768", model.UsageKeyExchange, 0, model.ClassHybrid, model.UrgencyNone},
		{"pure ML-KEM", "ML-KEM-768", model.UsageKeyExchange, 0, model.ClassPQSafe, model.UrgencyNone},
		{"pure ML-DSA", "ML-DSA-65", model.UsageSignature, 0, model.ClassPQSafe, model.UrgencyNone},

		{"classical x25519 kex is HNDL-urgent", "X25519", model.UsageKeyExchange, 0, model.ClassVulnerable, model.UrgencyHigh},
		{"classical p-256 kex", "P-256", model.UsageKeyExchange, 0, model.ClassVulnerable, model.UrgencyHigh},

		{"cert key rsa-2048", "RSA", model.UsageSignature, 2048, model.ClassVulnerable, model.UrgencyMedium},
		{"cert key ecdsa", "ECDSA P-256", model.UsageSignature, 256, model.ClassVulnerable, model.UrgencyMedium},
		{"rsa-1024 broken classically", "RSA", model.UsageSignature, 1024, model.ClassWeakClassical, model.UrgencyHigh},

		// A leaked key is compromised today; it must outrank the "RSA import"
		// verdict even though both carry an RSA algorithm label.
		{"committed rsa private key", "RSA private key", model.UsageSignature, 0, model.ClassWeakClassical, model.UrgencyHigh},
		{"committed pkcs8 private key", "PKCS#8 private key", model.UsageSignature, 0, model.ClassWeakClassical, model.UrgencyHigh},
		{"committed openssh private key", "OpenSSH private key", model.UsageSignature, 0, model.ClassWeakClassical, model.UrgencyHigh},

		{"jwk rs256", "RS256", model.UsageSignature, 2048, model.ClassVulnerable, model.UrgencyMedium},
		{"advertised es256 (no key bits)", "ES256", model.UsageSignature, 0, model.ClassVulnerable, model.UrgencyMedium},
		{"advertised eddsa", "EdDSA", model.UsageSignature, 0, model.ClassVulnerable, model.UrgencyMedium},
		{"alg none", "none", model.UsageSignature, 0, model.ClassWeakClassical, model.UrgencyMedium},
		{"hmac hs256", "HS256", model.UsageSignature, 0, model.ClassAcceptable, model.UrgencyLow},
		{"jwe rsa-oaep is HNDL-urgent", "RSA-OAEP", model.UsageEncryption, 2048, model.ClassVulnerable, model.UrgencyHigh},

		{"tls 1.0", "TLS 1.0", model.UsageProtocol, 0, model.ClassWeakClassical, model.UrgencyHigh},
		{"tls 1.2", "TLS 1.2", model.UsageProtocol, 0, model.ClassAcceptable, model.UrgencyLow},
		{"tls 1.3", "TLS 1.3", model.UsageProtocol, 0, model.ClassAcceptable, model.UrgencyNone},

		{"aes-128 suite (Grover)", "TLS_AES_128_GCM_SHA256", model.UsageEncryption, 0, model.ClassAcceptable, model.UrgencyLow},
		{"aes-256 suite", "TLS_AES_256_GCM_SHA384", model.UsageEncryption, 0, model.ClassAcceptable, model.UrgencyNone},
		{"chacha20 suite", "TLS_CHACHA20_POLY1305_SHA256", model.UsageEncryption, 0, model.ClassAcceptable, model.UrgencyNone},
		{"md5", "MD5", model.UsageHash, 0, model.ClassWeakClassical, model.UrgencyHigh},

		{"unknown surfaces loudly", "FROBNICATE-9000", model.UsageHash, 0, model.ClassUnknown, model.UrgencyMedium},
		// 0.3.0: issuer transport, JOSE/XML encryption, SAML names, cert signature hashes
		{"issuer on plain http", "HTTP", model.UsageProtocol, 0, model.ClassWeakClassical, model.UrgencyHigh},
		{"enc jwk without alg is HNDL-urgent", "RSA", model.UsageEncryption, 2048, model.ClassVulnerable, model.UrgencyHigh},
		{"ecdh-es jwe is HNDL-urgent", "ECDH-ES", model.UsageEncryption, 0, model.ClassVulnerable, model.UrgencyHigh},
		{"ecdh enc key without alg", "ECDH P-256", model.UsageEncryption, 256, model.ClassVulnerable, model.UrgencyHigh},
		{"jwe dir", "dir", model.UsageEncryption, 0, model.ClassAcceptable, model.UrgencyNone},
		{"jwe a128cbc-hs256", "A128CBC-HS256", model.UsageEncryption, 0, model.ClassAcceptable, model.UrgencyLow},
		{"jwe a256gcm", "A256GCM", model.UsageEncryption, 0, model.ClassAcceptable, model.UrgencyNone},
		{"jwe pbes2", "PBES2-HS256+A128KW", model.UsageEncryption, 0, model.ClassAcceptable, model.UrgencyLow},
		{"saml rsa-sha1 signature", "RSA-SHA1", model.UsageSignature, 0, model.ClassWeakClassical, model.UrgencyHigh},
		{"saml rsa-sha256 signature", "RSA-SHA256", model.UsageSignature, 0, model.ClassVulnerable, model.UrgencyMedium},
		{"saml rsa-pss signature", "RSA-PSS-SHA256", model.UsageSignature, 0, model.ClassVulnerable, model.UrgencyMedium},
		{"saml ecdsa-sha256 signature", "ECDSA-SHA256", model.UsageSignature, 0, model.ClassVulnerable, model.UrgencyMedium},
		{"saml rsa-1_5 key transport", "RSA1_5", model.UsageEncryption, 0, model.ClassVulnerable, model.UrgencyHigh},
		{"saml 3des", "3DES-CBC", model.UsageEncryption, 0, model.ClassWeakClassical, model.UrgencyHigh},
		{"saml aes-128-cbc", "AES-128-CBC", model.UsageEncryption, 0, model.ClassAcceptable, model.UrgencyLow},
		{"saml aes-256-gcm", "AES-256-GCM", model.UsageEncryption, 0, model.ClassAcceptable, model.UrgencyNone},
		{"rsa key transport in tls", "RSA", model.UsageKeyExchange, 0, model.ClassVulnerable, model.UrgencyHigh},
		{"tls 3des suite", "TLS_RSA_WITH_3DES_EDE_CBC_SHA", model.UsageEncryption, 0, model.ClassWeakClassical, model.UrgencyHigh},
		{"cert signed with sha-1", "SHA-1", model.UsageHash, 0, model.ClassWeakClassical, model.UrgencyHigh},
		{"cert signed with sha-256", "SHA-256", model.UsageHash, 0, model.ClassAcceptable, model.UrgencyNone},
		{"cert signed with sha-384", "SHA-384", model.UsageHash, 0, model.ClassAcceptable, model.UrgencyNone},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := c.Classify(model.CryptoAsset{
				Source:    "test",
				Location:  "test",
				Usage:     tc.usage,
				Algorithm: tc.algorithm,
				KeyBits:   tc.keyBits,
			})
			if v.Class != tc.wantClass || v.Urgency != tc.wantUrg {
				t.Errorf("%s (%s, %d bits) = %s/%s, want %s/%s",
					tc.algorithm, tc.usage, tc.keyBits, v.Class, v.Urgency, tc.wantClass, tc.wantUrg)
			}
			if v.Rationale == "" {
				t.Errorf("%s: verdict has no rationale", tc.algorithm)
			}
		})
	}
}

func TestNewFromYAMLRejectsInvalidRules(t *testing.T) {
	bad := []struct {
		name string
		yaml string
	}{
		{"empty set", "rules: []"},
		{"unknown class", `
rules:
  - name: x
    match: {algorithms: ["A"]}
    class: SuperSafe
    urgency: Low`},
		{"unknown urgency", `
rules:
  - name: x
    match: {algorithms: ["A"]}
    class: Acceptable
    urgency: Panic`},
		{"bad glob", `
rules:
  - name: x
    match: {algorithms: ["[unclosed"]}
    class: Acceptable
    urgency: Low`},
		{"no algorithms", `
rules:
  - name: x
    match: {usages: [Signature]}
    class: Acceptable
    urgency: Low`},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewFromYAML([]byte(tc.yaml)); err == nil {
				t.Error("expected validation error, got nil")
			}
		})
	}
}
