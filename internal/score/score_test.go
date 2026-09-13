package score

import (
	"testing"

	"github.com/angga-22/pqinv/internal/model"
)

func v(usage model.Usage, urgency model.Urgency) model.Verdict {
	return model.Verdict{
		Asset:   model.CryptoAsset{Usage: usage},
		Urgency: urgency,
	}
}

func TestCompute(t *testing.T) {
	cases := []struct {
		name      string
		verdicts  []model.Verdict
		wantScore int
		wantGrade string
	}{
		{"empty scan is perfect", nil, 100, "A"},
		{"all-none is perfect",
			[]model.Verdict{v(model.UsageKeyExchange, model.UrgencyNone)}, 100, "A"},

		{"one high kex finding",
			[]model.Verdict{v(model.UsageKeyExchange, model.UrgencyHigh)}, 75, "B"},

		// GitHub-shaped: no PQ kex (2 high), classical chain (3 medium),
		// TLS 1.2 + AES-128 (2 low). Kex 50 (capped) + sig 15 (capped) +
		// protocol 2 + encryption 2 = 69 → 31.
		{"no-PQ endpoint lands in D",
			[]model.Verdict{
				v(model.UsageKeyExchange, model.UrgencyHigh),
				v(model.UsageKeyExchange, model.UrgencyHigh),
				v(model.UsageSignature, model.UrgencyMedium),
				v(model.UsageSignature, model.UrgencyMedium),
				v(model.UsageSignature, model.UrgencyMedium),
				v(model.UsageProtocol, model.UrgencyLow),
				v(model.UsageEncryption, model.UrgencyLow),
			}, 31, "D"},

		// Cloudflare-shaped after correlation: hybrid present (kex all
		// Low/None), but TLS 1.0+1.1 (2 high protocol, capped at 25),
		// classical chain (3 medium sig, capped 15), AES-128 low.
		{"hybrid-ready with legacy TLS lands in C",
			[]model.Verdict{
				v(model.UsageKeyExchange, model.UrgencyNone),
				v(model.UsageKeyExchange, model.UrgencyLow),
				v(model.UsageKeyExchange, model.UrgencyLow),
				v(model.UsageKeyExchange, model.UrgencyLow),
				v(model.UsageProtocol, model.UrgencyHigh),
				v(model.UsageProtocol, model.UrgencyHigh),
				v(model.UsageProtocol, model.UrgencyLow),
				v(model.UsageProtocol, model.UrgencyNone),
				v(model.UsageSignature, model.UrgencyMedium),
				v(model.UsageSignature, model.UrgencyMedium),
				v(model.UsageSignature, model.UrgencyMedium),
				v(model.UsageEncryption, model.UrgencyLow),
			}, 52, "C"},

		// A flood of identical medium signature findings (Keycloak's
		// advertised-alg list) cannot deduct more than the signature cap.
		{"many identical mediums are capped",
			[]model.Verdict{
				v(model.UsageSignature, model.UrgencyMedium),
				v(model.UsageSignature, model.UrgencyMedium),
				v(model.UsageSignature, model.UrgencyMedium),
				v(model.UsageSignature, model.UrgencyMedium),
				v(model.UsageSignature, model.UrgencyMedium),
				v(model.UsageSignature, model.UrgencyMedium),
				v(model.UsageSignature, model.UrgencyMedium),
				v(model.UsageSignature, model.UrgencyMedium),
				v(model.UsageSignature, model.UrgencyMedium),
				v(model.UsageSignature, model.UrgencyMedium),
				v(model.UsageSignature, model.UrgencyMedium),
			}, 85, "B"},

		{"score floors at zero",
			[]model.Verdict{
				v(model.UsageKeyExchange, model.UrgencyHigh),
				v(model.UsageKeyExchange, model.UrgencyHigh),
				v(model.UsageEncryption, model.UrgencyHigh),
				v(model.UsageProtocol, model.UrgencyHigh),
				v(model.UsageSignature, model.UrgencyHigh),
				v(model.UsageHash, model.UrgencyHigh),
			}, 0, "F"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Compute(tc.verdicts)
			if got.Score != tc.wantScore || got.Grade != tc.wantGrade {
				t.Errorf("Compute() = %d/%s, want %d/%s",
					got.Score, got.Grade, tc.wantScore, tc.wantGrade)
			}
		})
	}
}
