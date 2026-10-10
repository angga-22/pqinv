package report

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/angga-22/pqinv/internal/model"
)

func decodeResults(t *testing.T, reports []TargetReport) []map[string]any {
	t.Helper()
	var buf bytes.Buffer
	if err := JSON(&buf, "test", reports); err != nil {
		t.Fatalf("JSON: %v", err)
	}
	var doc struct {
		Results []map[string]any `json:"results"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, buf.String())
	}
	return doc.Results
}

func TestJSONScoredTarget(t *testing.T) {
	results := decodeResults(t, []TargetReport{{
		Probe: "tls", Target: "example.com:443", Score: 75, Grade: "B",
		Verdicts: []model.Verdict{{
			Asset: model.CryptoAsset{Source: "tls", Location: "example.com:443", Usage: model.UsageKeyExchange, Algorithm: "X25519MLKEM768"},
			Class: model.ClassHybrid, Urgency: model.UrgencyNone,
		}},
	}})
	r := results[0]
	if r["status"] != StatusOK {
		t.Errorf("status = %v, want %q", r["status"], StatusOK)
	}
	if r["score"] != float64(75) || r["grade"] != "B" {
		t.Errorf("score/grade = %v/%v, want 75/B", r["score"], r["grade"])
	}
	if _, has := r["error"]; has {
		t.Error("a scored target must not carry an error field")
	}
}

func TestJSONUnreachableTargetHasNoScore(t *testing.T) {
	results := decodeResults(t, []TargetReport{{
		Probe: "tls", Target: "down.example:443", Error: "dial tcp: connection refused",
	}})
	r := results[0]
	if r["status"] != StatusUnreachable {
		t.Errorf("status = %v, want %q", r["status"], StatusUnreachable)
	}
	if r["error"] != "dial tcp: connection refused" {
		t.Errorf("error = %v, want the probe error verbatim", r["error"])
	}
	for _, forbidden := range []string{"score", "grade"} {
		if _, has := r[forbidden]; has {
			t.Errorf("unreachable target must not carry %q — a zero there reads as an F", forbidden)
		}
	}
	verdicts, ok := r["verdicts"].([]any)
	if !ok || len(verdicts) != 0 {
		t.Errorf("verdicts = %v, want an empty array (never null)", r["verdicts"])
	}
}

func TestJSONIsDeterministic(t *testing.T) {
	reports := []TargetReport{{
		Probe: "oidc", Target: "https://id.example", Score: 60, Grade: "C",
		Verdicts: []model.Verdict{{
			Asset: model.CryptoAsset{Source: "oidc", Location: "x", Usage: model.UsageSignature, Algorithm: "RS256",
				Metadata: map[string]string{"kid": "a", "issuer": "b", "kind": "jwk"}},
			Class: model.ClassVulnerable, Urgency: model.UrgencyMedium,
		}},
	}}
	var a, b bytes.Buffer
	if err := JSON(&a, "v", reports); err != nil {
		t.Fatal(err)
	}
	if err := JSON(&b, "v", reports); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.Bytes(), b.Bytes()) {
		t.Error("identical input must produce identical bytes")
	}
	if bytes.Contains(a.Bytes(), []byte(`"timestamp"`)) {
		t.Error("JSON output must not carry a timestamp")
	}
}
