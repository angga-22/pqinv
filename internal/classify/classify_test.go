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
