package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/angga-22/pqinv/internal/model"
)

// Regression guard for the cyclonedx-go v0.12.0 converter bug: its
// EncodeVersion path rewrites cryptographic-asset components to type
// "application" and would gut the CBOM. If a library upgrade ever
// reintroduces conversion, this fails loudly.
func TestCBOMKeepsCryptoTyping(t *testing.T) {
	reports := []TargetReport{{
		Probe: "tls", Target: "example.com:443", Score: 75, Grade: "B",
		Verdicts: []model.Verdict{{
			Asset: model.CryptoAsset{
				Source: "tls", Location: "example.com:443",
				Usage: model.UsageKeyExchange, Algorithm: "X25519MLKEM768",
			},
			Class: model.ClassHybrid, Urgency: model.UrgencyNone,
		}},
	}}

	var buf bytes.Buffer
	if err := CBOM(&buf, "test", reports); err != nil {
		t.Fatalf("CBOM: %v", err)
	}
	out := buf.String()

	if !json.Valid(buf.Bytes()) {
		t.Fatal("CBOM output is not valid JSON")
	}
	for _, want := range []string{
		`"specVersion": "1.6"`,
		`"type": "cryptographic-asset"`,
		`"cryptoProperties"`,
		`"primitive": "key-agree"`,
		`"name": "X25519MLKEM768"`,
		`"pqinv:class"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("CBOM output missing %s", want)
		}
	}
	if strings.Contains(out, `"timestamp"`) || strings.Contains(out, `"serialNumber"`) {
		t.Error("CBOM output must stay deterministic: no timestamp or serial number")
	}
}
