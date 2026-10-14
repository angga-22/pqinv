package pipeline

import (
	"errors"
	"testing"

	"github.com/angga-22/pqinv/internal/classify"
	"github.com/angga-22/pqinv/internal/model"
	"github.com/angga-22/pqinv/internal/scan"
)

func TestReportsKeepOrderAndMarkFailures(t *testing.T) {
	c, err := classify.New()
	if err != nil {
		t.Fatal(err)
	}
	results := []scan.Result{
		{Target: scan.Target{Probe: "tls", Target: "a:443"}, Assets: []model.CryptoAsset{
			{Source: "tls", Location: "a:443", Usage: model.UsageKeyExchange, Algorithm: "X25519MLKEM768"},
			{Source: "tls", Location: "a:443", Usage: model.UsageKeyExchange, Algorithm: "X25519"},
		}},
		{Target: scan.Target{Probe: "tls", Target: "b:443"}, Err: errors.New("refused")},
	}
	reports := Reports(c, results)
	if len(reports) != 2 || reports[0].Target != "a:443" || reports[1].Target != "b:443" {
		t.Fatalf("reports = %+v", reports)
	}
	a := reports[0]
	if a.Error != "" || a.Grade == "" || len(a.Verdicts) != 2 {
		t.Errorf("reachable report = %+v", a)
	}
	// Correlation ran: X25519 next to the hybrid is a Low fallback, not High.
	for _, v := range a.Verdicts {
		if v.Asset.Algorithm == "X25519" && v.Urgency != model.UrgencyLow {
			t.Errorf("X25519 urgency = %s, want Low (correlated behind hybrid)", v.Urgency)
		}
	}
	if reports[1].Error != "refused" || reports[1].Grade != "" || len(reports[1].Verdicts) != 0 {
		t.Errorf("unreachable report = %+v", reports[1])
	}
}
