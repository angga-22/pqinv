package baseline

import (
	"bytes"
	"strings"
	"testing"

	"github.com/angga-22/pqinv/internal/model"
	"github.com/angga-22/pqinv/internal/report"
)

func verdict(source, loc string, usage model.Usage, alg string, urg model.Urgency) model.Verdict {
	return model.Verdict{
		Asset:   model.CryptoAsset{Source: source, Location: loc, Usage: usage, Algorithm: alg},
		Class:   model.ClassVulnerable,
		Urgency: urg,
	}
}

func TestNewFindingsIsAMultisetDifference(t *testing.T) {
	old := []report.TargetReport{{Probe: "tls", Target: "a:443", Verdicts: []model.Verdict{
		verdict("tls", "a:443", model.UsageKeyExchange, "X25519", model.UrgencyHigh),
		verdict("tls", "a:443", model.UsageSignature, "RSA", model.UrgencyMedium),
	}}}
	b := FromReports(old)

	current := []report.TargetReport{{Probe: "tls", Target: "a:443", Verdicts: []model.Verdict{
		verdict("tls", "a:443", model.UsageKeyExchange, "X25519", model.UrgencyHigh), // inherited
		verdict("tls", "a:443", model.UsageSignature, "RSA", model.UrgencyMedium),    // inherited
		verdict("tls", "a:443", model.UsageSignature, "RSA", model.UrgencyMedium),    // one more than before
		verdict("tls", "a:443", model.UsageProtocol, "TLS 1.0", model.UrgencyHigh),   // brand new
	}}}
	got := b.NewFindings(current)
	if len(got) != 2 {
		t.Fatalf("got %d new findings, want 2: %+v", len(got), got)
	}
	if got[0].Verdict.Asset.Algorithm != "RSA" || got[1].Verdict.Asset.Algorithm != "TLS 1.0" {
		t.Errorf("new = %s, %s", got[0].Verdict.Asset.Algorithm, got[1].Verdict.Asset.Algorithm)
	}
}

func TestEscalationIsNew(t *testing.T) {
	b := FromReports([]report.TargetReport{{Probe: "tls", Target: "a:443", Verdicts: []model.Verdict{
		verdict("tls", "a:443", model.UsageKeyExchange, "X25519", model.UrgencyLow), // was a fallback behind hybrid
	}}})
	got := b.NewFindings([]report.TargetReport{{Probe: "tls", Target: "a:443", Verdicts: []model.Verdict{
		verdict("tls", "a:443", model.UsageKeyExchange, "X25519", model.UrgencyHigh), // hybrid removed
	}}})
	if len(got) != 1 {
		t.Errorf("Low → High on the same asset must count as new, got %d", len(got))
	}
}

func TestRepoLineShiftsAreNotNew(t *testing.T) {
	b := FromReports([]report.TargetReport{{Probe: "repo", Target: ".", Verdicts: []model.Verdict{
		verdict("repo", "pkg/hash.go:12", model.UsageHash, "MD5", model.UrgencyHigh),
	}}})
	got := b.NewFindings([]report.TargetReport{{Probe: "repo", Target: ".", Verdicts: []model.Verdict{
		verdict("repo", "pkg/hash.go:40", model.UsageHash, "MD5", model.UrgencyHigh),
	}}})
	if len(got) != 0 {
		t.Errorf("same finding on a different line is not new, got %+v", got)
	}

	// But a second MD5 in that file is.
	got = b.NewFindings([]report.TargetReport{{Probe: "repo", Target: ".", Verdicts: []model.Verdict{
		verdict("repo", "pkg/hash.go:40", model.UsageHash, "MD5", model.UrgencyHigh),
		verdict("repo", "pkg/hash.go:41", model.UsageHash, "MD5", model.UrgencyHigh),
	}}})
	if len(got) != 1 {
		t.Errorf("an additional MD5 in the same file is new, got %d", len(got))
	}
	if _, isTLS := map[string]bool{"tls": true}[got[0].Verdict.Asset.Source]; isTLS {
		t.Error("source must be preserved")
	}
}

func TestDifferentTargetsDoNotMatch(t *testing.T) {
	b := FromReports([]report.TargetReport{{Probe: "tls", Target: "a:443", Verdicts: []model.Verdict{
		verdict("tls", "a:443", model.UsageKeyExchange, "X25519", model.UrgencyHigh),
	}}})
	got := b.NewFindings([]report.TargetReport{{Probe: "tls", Target: "b:443", Verdicts: []model.Verdict{
		verdict("tls", "b:443", model.UsageKeyExchange, "X25519", model.UrgencyHigh),
	}}})
	if len(got) != 1 {
		t.Error("the same finding on a different target is new")
	}
}

func TestLoadRoundTripsThroughJSON(t *testing.T) {
	reports := []report.TargetReport{
		{Probe: "tls", Target: "a:443", Score: 31, Grade: "D", Verdicts: []model.Verdict{
			verdict("tls", "a:443", model.UsageKeyExchange, "X25519", model.UrgencyHigh),
		}},
		{Probe: "tls", Target: "down:443", Error: "refused"},
	}
	var buf bytes.Buffer
	if err := report.JSON(&buf, "test", reports); err != nil {
		t.Fatal(err)
	}
	b, err := Load(&buf)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if b.Targets != 2 {
		t.Errorf("Targets = %d, want 2", b.Targets)
	}
	if got := b.NewFindings(reports); len(got) != 0 {
		t.Errorf("a report compared with itself has no new findings, got %+v", got)
	}
}

func TestLoadRejectsForeignJSON(t *testing.T) {
	for name, body := range map[string]string{
		"not pqinv": `{"tool":"other","results":[]}`,
		"not json":  `garbage`,
		"empty":     ``,
	} {
		if _, err := Load(strings.NewReader(body)); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}
