package classify

import (
	"testing"

	"github.com/angga-22/pqinv/internal/model"
)

func kexVerdict(location, alg string, class model.Class, urgency model.Urgency) model.Verdict {
	return model.Verdict{
		Asset: model.CryptoAsset{
			Source: "tls", Location: location,
			Usage: model.UsageKeyExchange, Algorithm: alg,
		},
		Class: class, Urgency: urgency,
		Rationale: "base rationale.",
	}
}

func TestCorrelateDowngradesClassicalFallback(t *testing.T) {
	verdicts := []model.Verdict{
		kexVerdict("a:443", "X25519MLKEM768", model.ClassHybrid, model.UrgencyNone),
		kexVerdict("a:443", "X25519", model.ClassVulnerable, model.UrgencyHigh),
		// different endpoint, no hybrid — must keep full urgency
		kexVerdict("b:443", "X25519", model.ClassVulnerable, model.UrgencyHigh),
	}
	out := Correlate(verdicts)

	if out[1].Urgency != model.UrgencyLow {
		t.Errorf("classical fallback next to hybrid = %s, want Low", out[1].Urgency)
	}
	if out[1].Class != model.ClassVulnerable {
		t.Errorf("downgrade must not change class, got %s", out[1].Class)
	}
	if out[2].Urgency != model.UrgencyHigh {
		t.Errorf("endpoint without hybrid = %s, want High kept", out[2].Urgency)
	}
}

func TestCorrelateLeavesSignaturesAlone(t *testing.T) {
	verdicts := []model.Verdict{
		kexVerdict("a:443", "X25519MLKEM768", model.ClassHybrid, model.UrgencyNone),
		{
			Asset: model.CryptoAsset{
				Source: "tls", Location: "a:443",
				Usage: model.UsageSignature, Algorithm: "ECDSA P-256",
			},
			Class: model.ClassVulnerable, Urgency: model.UrgencyMedium,
		},
	}
	out := Correlate(verdicts)
	if out[1].Urgency != model.UrgencyMedium {
		t.Errorf("signature verdict changed to %s; correlation only applies to key exchange", out[1].Urgency)
	}
}
