package main

import (
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/angga-22/pqinv/internal/baseline"
	"github.com/angga-22/pqinv/internal/model"
	"github.com/angga-22/pqinv/internal/report"
)

func withVerdicts(urgencies ...model.Urgency) report.TargetReport {
	r := report.TargetReport{Probe: "tls", Target: "x:443", Score: 50, Grade: "C"}
	for _, u := range urgencies {
		r.Verdicts = append(r.Verdicts, model.Verdict{Urgency: u})
	}
	return r
}

// The gate is what CI trusts; every row is a promise the README makes.
func TestCheckFailOn(t *testing.T) {
	unreachable := report.TargetReport{Probe: "tls", Target: "down:443", Error: "connection refused"}

	cases := []struct {
		name     string
		failOn   string
		reports  []report.TargetReport
		wantFail bool
	}{
		{"no flag never fails", "", []report.TargetReport{withVerdicts(model.UrgencyHigh), unreachable}, false},
		{"high trips on high", "high", []report.TargetReport{withVerdicts(model.UrgencyHigh)}, true},
		{"high ignores medium", "high", []report.TargetReport{withVerdicts(model.UrgencyMedium, model.UrgencyLow)}, false},
		{"medium trips on medium", "medium", []report.TargetReport{withVerdicts(model.UrgencyMedium)}, true},
		{"medium trips on high too", "medium", []report.TargetReport{withVerdicts(model.UrgencyHigh)}, true},
		{"low trips on low", "low", []report.TargetReport{withVerdicts(model.UrgencyLow)}, true},
		{"low ignores none", "low", []report.TargetReport{withVerdicts(model.UrgencyNone)}, false},
		{"case-insensitive", "HIGH", []report.TargetReport{withVerdicts(model.UrgencyHigh)}, true},
		{"unreachable always trips", "high", []report.TargetReport{withVerdicts(model.UrgencyNone), unreachable}, true},
		{"clean scan passes", "low", []report.TargetReport{withVerdicts(model.UrgencyNone), withVerdicts()}, false},
		{"bad threshold is an error", "panic", []report.TargetReport{withVerdicts()}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := checkFailOn(tc.failOn, tc.reports, nil)
			if (err != nil) != tc.wantFail {
				t.Errorf("checkFailOn(%q) = %v, wantFail=%v", tc.failOn, err, tc.wantFail)
			}
		})
	}
}

func TestCheckFailOnAgainstBaseline(t *testing.T) {
	high := func(alg string) model.Verdict {
		return model.Verdict{
			Asset:   model.CryptoAsset{Source: "tls", Location: "x:443", Usage: model.UsageKeyExchange, Algorithm: alg},
			Class:   model.ClassVulnerable,
			Urgency: model.UrgencyHigh,
		}
	}
	inherited := report.TargetReport{Probe: "tls", Target: "x:443", Verdicts: []model.Verdict{high("X25519")}}
	bl := baseline.FromReports([]report.TargetReport{inherited})

	if err := checkFailOn("high", []report.TargetReport{inherited}, bl); err != nil {
		t.Errorf("findings already in the baseline must not trip the gate: %v", err)
	}

	regressed := report.TargetReport{Probe: "tls", Target: "x:443", Verdicts: []model.Verdict{high("X25519"), high("P-256")}}
	err := checkFailOn("high", []report.TargetReport{regressed}, bl)
	if err == nil {
		t.Fatal("a finding not in the baseline must trip the gate")
	}
	if !strings.Contains(err.Error(), "1 new findings") || !strings.Contains(err.Error(), "P-256") {
		t.Errorf("error should count and name the new finding: %v", err)
	}
	if strings.Contains(err.Error(), "X25519") {
		t.Errorf("inherited findings must not be listed: %v", err)
	}

	down := report.TargetReport{Probe: "tls", Target: "down:443", Error: "refused"}
	if err := checkFailOn("high", []report.TargetReport{inherited, down}, bl); err == nil {
		t.Error("unreachable targets trip the gate even against a baseline")
	}
}

func TestGateErrorListsAtMostTen(t *testing.T) {
	var verdicts []model.Verdict
	for i := 0; i < 15; i++ {
		verdicts = append(verdicts, model.Verdict{
			Asset:   model.CryptoAsset{Source: "repo", Location: fmt.Sprintf("f%d.go:1", i), Usage: model.UsageHash, Algorithm: "MD5"},
			Urgency: model.UrgencyHigh,
		})
	}
	err := checkFailOn("high", []report.TargetReport{{Probe: "repo", Target: ".", Verdicts: verdicts}}, nil)
	if err == nil {
		t.Fatal("expected failure")
	}
	if got := strings.Count(err.Error(), "\n"); got != 11 {
		t.Errorf("expected 10 listed findings plus an overflow line, got %d lines:\n%s", got, err)
	}
	if !strings.Contains(err.Error(), "and 5 more") {
		t.Errorf("overflow line missing: %v", err)
	}
}

func TestNormalizeTarget(t *testing.T) {
	cases := map[string]string{
		"example.com":      "example.com:443",
		"example.com:8443": "example.com:8443",
		"::1":              "[::1]:443",
		"[::1]:8443":       "[::1]:8443",
		"10.0.0.1":         "10.0.0.1:443",
	}
	for in, want := range cases {
		if got := normalizeTarget(in); got != want {
			t.Errorf("normalizeTarget(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLoadTargets(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		t.Helper()
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}

	good := write("good.yaml", "targets:\n  - probe: tls\n    target: a:443\n  - probe: repo\n    target: .\n")
	targets, err := loadTargets(good)
	if err != nil {
		t.Fatalf("loadTargets: %v", err)
	}
	if len(targets) != 2 || targets[0].Probe != "tls" || targets[1].Target != "." {
		t.Errorf("targets = %+v", targets)
	}

	for name, body := range map[string]string{
		"empty.yaml":   "targets: []\n",
		"nolist.yaml":  "foo: bar\n",
		"partial.yaml": "targets:\n  - probe: tls\n",
		"broken.yaml":  "targets: [\n",
	} {
		if _, err := loadTargets(write(name, body)); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	if _, err := loadTargets(filepath.Join(dir, "missing.yaml")); err == nil {
		t.Error("missing file: expected an error")
	}
}

func TestNewHTTPClientTrustsCAFile(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	caPath := filepath.Join(t.TempDir(), "ca.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(caPath, pemBytes, 0o644); err != nil {
		t.Fatal(err)
	}

	get := func(c *http.Client) error {
		resp, err := c.Get(srv.URL)
		if err != nil {
			return err
		}
		resp.Body.Close()
		return nil
	}

	plain, err := newHTTPClient("", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := get(plain); err == nil {
		t.Error("a self-signed issuer must be rejected without --ca-file")
	}

	trusted, err := newHTTPClient(caPath, false)
	if err != nil {
		t.Fatalf("newHTTPClient(ca): %v", err)
	}
	if err := get(trusted); err != nil {
		t.Errorf("--ca-file should make the issuer trusted: %v", err)
	}

	insecure, err := newHTTPClient("", true)
	if err != nil {
		t.Fatal(err)
	}
	if err := get(insecure); err != nil {
		t.Errorf("--insecure should skip verification: %v", err)
	}
}

func TestNewHTTPClientRejectsBadCAFile(t *testing.T) {
	dir := t.TempDir()
	notPEM := filepath.Join(dir, "junk.pem")
	if err := os.WriteFile(notPEM, []byte("this is not a certificate"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := newHTTPClient(notPEM, false); err == nil {
		t.Error("a --ca-file with no certificates must be an error, not a silent no-op")
	}
	if _, err := newHTTPClient(filepath.Join(dir, "missing.pem"), false); err == nil {
		t.Error("a missing --ca-file must be an error")
	}
}
