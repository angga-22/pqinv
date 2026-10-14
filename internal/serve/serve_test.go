package serve

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/angga-22/pqinv/internal/baseline"
	"github.com/angga-22/pqinv/internal/classify"
	"github.com/angga-22/pqinv/internal/model"
	"github.com/angga-22/pqinv/internal/probe"
	"github.com/angga-22/pqinv/internal/report"
	"github.com/angga-22/pqinv/internal/scan"
)

// fakeProbe returns a fixed asset list, or grows one asset per call when
// `drift` is set, so tests can make a target regress between scans.
type fakeProbe struct {
	name   string
	err    error
	assets []model.CryptoAsset
	drift  bool
	calls  atomic.Int32
}

func (f *fakeProbe) Name() string { return f.name }
func (f *fakeProbe) Scan(ctx context.Context, target string) ([]model.CryptoAsset, error) {
	n := f.calls.Add(1)
	if f.err != nil {
		return nil, f.err
	}
	out := append([]model.CryptoAsset{}, f.assets...)
	if f.drift && n > 1 {
		out = append(out, model.CryptoAsset{Source: f.name, Location: target, Usage: model.UsageProtocol, Algorithm: "TLS 1.0"})
	}
	return out, nil
}

type logBuf struct{ bytes.Buffer }

func (l *logBuf) Printf(format string, v ...any) { fmt.Fprintf(&l.Buffer, format+"\n", v...) }

func newServer(t *testing.T, probes map[string]probe.Probe, targets []scan.Target) (*Server, *logBuf) {
	t.Helper()
	c, err := classify.New()
	if err != nil {
		t.Fatal(err)
	}
	lb := &logBuf{}
	return &Server{
		Runner:     &scan.Runner{Probes: probes, Concurrency: 2},
		Classifier: c,
		Targets:    targets,
		Interval:   time.Hour,
		Version:    "test",
		Log:        lb,
	}, lb
}

func hybridAssets(loc string) []model.CryptoAsset {
	return []model.CryptoAsset{
		{Source: "tls", Location: loc, Usage: model.UsageKeyExchange, Algorithm: "X25519MLKEM768"},
		{Source: "tls", Location: loc, Usage: model.UsageProtocol, Algorithm: "TLS 1.3"},
		{Source: "tls", Location: loc + " cert#0", Usage: model.UsageSignature, Algorithm: "RSA", KeyBits: 2048,
			Metadata: map[string]string{"kind": "certificate", "subject": `CN=a "quoted" name\x`, "not_after": "2031-01-02T03:04:05Z"}},
	}
}

func get(t *testing.T, h http.Handler, path string) (int, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec.Code, rec.Body.String()
}

func TestBeforeFirstScan(t *testing.T) {
	s, _ := newServer(t, map[string]probe.Probe{"tls": &fakeProbe{name: "tls"}}, []scan.Target{{Probe: "tls", Target: "a:443"}})
	h := s.Handler()

	if code, _ := get(t, h, "/healthz"); code != http.StatusServiceUnavailable {
		t.Errorf("healthz before first scan = %d, want 503", code)
	}
	if code, _ := get(t, h, "/report.json"); code != http.StatusServiceUnavailable {
		t.Errorf("report.json before first scan = %d, want 503", code)
	}
	code, body := get(t, h, "/metrics")
	if code != http.StatusOK {
		t.Fatalf("metrics = %d", code)
	}
	for _, want := range []string{`pqinv_build_info{version="test"} 1`, "pqinv_targets 1", "pqinv_scans_total 0"} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics before first scan missing %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, "pqinv_score") {
		t.Error("no score series may exist before a scan")
	}
}

var expiryUnix = func() string {
	ts, _ := time.Parse(time.RFC3339, "2031-01-02T03:04:05Z")
	return fmt.Sprint(ts.Unix())
}()

func TestMetricsAfterScan(t *testing.T) {
	probes := map[string]probe.Probe{
		"tls":  &fakeProbe{name: "tls", assets: hybridAssets("a:443")},
		"down": &fakeProbe{name: "down", err: errors.New("connection refused")},
	}
	targets := []scan.Target{{Probe: "tls", Target: "a:443"}, {Probe: "down", Target: "b:443"}}
	s, logs := newServer(t, probes, targets)
	s.ScanOnce(context.Background())
	h := s.Handler()

	if code, _ := get(t, h, "/healthz"); code != http.StatusOK {
		t.Errorf("healthz after scan = %d", code)
	}
	_, body := get(t, h, "/metrics")

	must := []string{
		"pqinv_scans_total 1",
		`pqinv_target_unreachable{probe="tls",target="a:443"} 0`,
		`pqinv_target_unreachable{probe="down",target="b:443"} 1`,
		`pqinv_findings{probe="tls",target="a:443",urgency="high"} 0`,
		`pqinv_findings{probe="tls",target="a:443",urgency="medium"} 1`,
		`pqinv_findings{probe="tls",target="a:443",urgency="none"} 2`,
		`pqinv_findings_by_class{probe="tls",target="a:443",class="Hybrid"} 1`,
		`pqinv_findings_by_class{probe="tls",target="a:443",class="Unknown"} 0`,
		`pqinv_new_findings_last_scan{probe="tls",target="a:443"} 0`,
		`pqinv_new_findings_total{probe="tls",target="a:443"} 0`,
		`pqinv_certificate_expiry_timestamp_seconds{probe="tls",target="a:443",location="a:443 cert#0",subject="CN=a \"quoted\" name\\x"} ` + expiryUnix,
		"# TYPE pqinv_score gauge",
		"# TYPE pqinv_new_findings_total counter",
	}
	for _, want := range must {
		if !strings.Contains(body, want) {
			t.Errorf("metrics missing %q", want)
		}
	}
	if m := regexp.MustCompile(`pqinv_score\{probe="tls",target="a:443"\} (\d+)`).FindStringSubmatch(body); m == nil || m[1] != "95" {
		t.Errorf("score series wrong: %v (hybrid kex + TLS 1.3 + one classical cert = 95)", m)
	}
	if strings.Contains(body, `pqinv_score{probe="down"`) {
		t.Error("unreachable targets must not have a score series — absent, not zero")
	}
	if strings.Contains(body, `pqinv_findings{probe="down"`) {
		t.Error("unreachable targets must not have finding series")
	}
	if !strings.Contains(logs.String(), "unreachable: down b:443: connection refused") {
		t.Errorf("unreachable target should be logged, got:\n%s", logs.String())
	}
	if !strings.Contains(logs.String(), "scan #1: 2 targets, 1 unreachable, 0 new findings") {
		t.Errorf("scan summary missing:\n%s", logs.String())
	}
}

func TestReportJSONUsesPublicSchema(t *testing.T) {
	s, _ := newServer(t, map[string]probe.Probe{"tls": &fakeProbe{name: "tls", assets: hybridAssets("a:443")}},
		[]scan.Target{{Probe: "tls", Target: "a:443"}})
	s.ScanOnce(context.Background())
	code, body := get(t, s.Handler(), "/report.json")
	if code != http.StatusOK {
		t.Fatalf("report.json = %d", code)
	}
	var doc struct {
		Tool    string                `json:"tool"`
		Version string                `json:"version"`
		Results []report.TargetReport `json:"results"`
	}
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		t.Fatalf("not valid report JSON: %v", err)
	}
	if doc.Tool != "pqinv" || doc.Version != "test" || len(doc.Results) != 1 || doc.Results[0].Grade != "A" {
		t.Errorf("doc = %+v", doc)
	}
	if !strings.Contains(body, `"status": "ok"`) {
		t.Error("report.json must carry the status field like --format json")
	}
	// It is a valid --baseline input.
	if _, err := baseline.Load(strings.NewReader(body)); err != nil {
		t.Errorf("report.json should load as a baseline: %v", err)
	}
}

func TestNewFindingsAcrossScans(t *testing.T) {
	drifting := &fakeProbe{name: "tls", assets: hybridAssets("a:443"), drift: true}
	s, logs := newServer(t, map[string]probe.Probe{"tls": drifting}, []scan.Target{{Probe: "tls", Target: "a:443"}})

	first := s.ScanOnce(context.Background())
	if len(first.NewFindings) != 0 {
		t.Errorf("first scan without a baseline has nothing to compare against, got %d new", len(first.NewFindings))
	}
	second := s.ScanOnce(context.Background())
	if len(second.NewFindings) != 1 || second.NewFindings[0].Verdict.Asset.Algorithm != "TLS 1.0" {
		t.Fatalf("second scan should report the regression, got %+v", second.NewFindings)
	}
	third := s.ScanOnce(context.Background())
	if len(third.NewFindings) != 0 {
		t.Errorf("a regression already seen is not new again, got %d", len(third.NewFindings))
	}

	_, body := get(t, s.Handler(), "/metrics")
	for _, want := range []string{
		"pqinv_scans_total 3",
		`pqinv_new_findings_last_scan{probe="tls",target="a:443"} 0`,
		`pqinv_new_findings_total{probe="tls",target="a:443"} 1`,
		`pqinv_findings{probe="tls",target="a:443",urgency="high"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics missing %q", want)
		}
	}
	if !strings.Contains(logs.String(), "new finding: tls a:443: High TLS 1.0 [Protocol]") {
		t.Errorf("regression should be logged:\n%s", logs.String())
	}
}

func TestInitialBaselineAppliesToFirstScan(t *testing.T) {
	// Operator ships a baseline from a previous `--format json`; the first
	// scheduled scan must compare against it, not treat everything as old.
	empty := baseline.FromReports([]report.TargetReport{{Probe: "tls", Target: "a:443"}})
	s, _ := newServer(t, map[string]probe.Probe{"tls": &fakeProbe{name: "tls", assets: hybridAssets("a:443")}},
		[]scan.Target{{Probe: "tls", Target: "a:443"}})
	s.Baseline = empty
	snap := s.ScanOnce(context.Background())
	if len(snap.NewFindings) != 3 {
		t.Errorf("every finding is new against an empty baseline, got %d", len(snap.NewFindings))
	}
	// And the second scan compares with the first, not the baseline again.
	if snap = s.ScanOnce(context.Background()); len(snap.NewFindings) != 0 {
		t.Errorf("second scan vs first: nothing new, got %d", len(snap.NewFindings))
	}
}

func TestRunLoopStopsOnCancel(t *testing.T) {
	p := &fakeProbe{name: "tls", assets: hybridAssets("a:443")}
	s, _ := newServer(t, map[string]probe.Probe{"tls": p}, []scan.Target{{Probe: "tls", Target: "a:443"}})
	s.Interval = 20 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()

	deadline := time.Now().Add(2 * time.Second)
	for p.calls.Load() < 3 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("Run returned %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
	if p.calls.Load() < 3 {
		t.Errorf("expected the loop to rescan on the interval, got %d scans", p.calls.Load())
	}
}

func TestFormatValue(t *testing.T) {
	cases := map[float64]string{0: "0", 1: "1", 95: "95", 1925089445: "1925089445", 0.25: "0.25", 1.5e-3: "0.0015"}
	for in, want := range cases {
		if got := formatValue(in); got != want {
			t.Errorf("formatValue(%v) = %q, want %q", in, got, want)
		}
	}
}

func TestEscapeLabel(t *testing.T) {
	cases := map[string]string{
		`plain`:         `plain`,
		`a\b`:           `a\\b`,
		`say "hi"`:      `say \"hi\"`,
		"two\nlines":    `two\nlines`,
		`CN=x, O=y\, z`: `CN=x, O=y\\, z`,
	}
	for in, want := range cases {
		if got := escapeLabel(in); got != want {
			t.Errorf("escapeLabel(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestIndexAndNotFound(t *testing.T) {
	s, _ := newServer(t, map[string]probe.Probe{}, nil)
	h := s.Handler()
	if code, body := get(t, h, "/"); code != http.StatusOK || !strings.Contains(body, "/metrics") {
		t.Errorf("index = %d %q", code, body)
	}
	if code, _ := get(t, h, "/nope"); code != http.StatusNotFound {
		t.Errorf("unknown path = %d, want 404", code)
	}
}
