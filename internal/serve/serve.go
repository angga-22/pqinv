// Package serve runs the scan pipeline on a schedule and exposes the
// result as Prometheus metrics and a JSON report. It is the continuous
// half of pqinv: the CI gate catches regressions in code, this catches
// them in the infrastructure that changes without a commit — an IdP
// upgrade, a certificate rotation, a console click.
//
// Nothing here prints or exits; cmd/ owns the process.
package serve

import (
	"context"
	"fmt"
	"io"
	"math"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/angga-22/pqinv/internal/baseline"
	"github.com/angga-22/pqinv/internal/classify"
	"github.com/angga-22/pqinv/internal/model"
	"github.com/angga-22/pqinv/internal/pipeline"
	"github.com/angga-22/pqinv/internal/report"
	"github.com/angga-22/pqinv/internal/scan"
)

// Logger is the subset of *log.Logger the server needs. Nil means silent.
type Logger interface {
	Printf(format string, v ...any)
}

// Server scans Targets every Interval and keeps the latest Snapshot.
type Server struct {
	Runner     *scan.Runner
	Classifier *classify.Classifier
	Targets    []scan.Target
	Interval   time.Duration
	Version    string
	// Baseline, when set, is what the first scan is compared against.
	// Every later scan is compared against the one before it.
	Baseline *baseline.Baseline
	Log      Logger

	mu       sync.RWMutex
	snap     *Snapshot
	scans    int
	prev     *baseline.Baseline
	newTotal map[string]int // probe\x1ftarget → cumulative new findings
}

// Snapshot is the outcome of one scheduled scan.
type Snapshot struct {
	Reports     []report.TargetReport
	ScannedAt   time.Time
	Duration    time.Duration
	NewFindings []baseline.Finding
}

// Run scans once immediately, then every Interval, until ctx is done.
// It returns ctx.Err().
func (s *Server) Run(ctx context.Context) error {
	s.ScanOnce(ctx)
	interval := s.Interval
	if interval <= 0 {
		interval = time.Hour
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			s.ScanOnce(ctx)
		}
	}
}

// ScanOnce runs the whole pipeline over Targets and publishes the result.
func (s *Server) ScanOnce(ctx context.Context) Snapshot {
	start := time.Now()
	results := s.Runner.Run(ctx, s.Targets)
	reports := pipeline.Reports(s.Classifier, results)

	s.mu.Lock()
	defer s.mu.Unlock()

	// First scan: compare against the operator-supplied baseline if any.
	// Every later scan compares against the one before it.
	if s.prev == nil {
		s.prev = s.Baseline
	}
	var fresh []baseline.Finding
	if s.prev != nil {
		fresh = s.prev.NewFindings(reports)
	}
	s.prev = baseline.FromReports(reports)
	if s.newTotal == nil {
		s.newTotal = map[string]int{}
	}
	for _, f := range fresh {
		s.newTotal[f.Probe+"\x1f"+f.Target]++
	}
	s.scans++
	snap := Snapshot{
		Reports:     reports,
		ScannedAt:   start,
		Duration:    time.Since(start),
		NewFindings: fresh,
	}
	s.snap = &snap
	s.logScan(snap)
	return snap
}

func (s *Server) logScan(snap Snapshot) {
	if s.Log == nil {
		return
	}
	unreachable := 0
	for _, r := range snap.Reports {
		if r.Error != "" {
			unreachable++
			s.Log.Printf("unreachable: %s %s: %s", r.Probe, r.Target, r.Error)
		}
	}
	for _, f := range snap.NewFindings {
		s.Log.Printf("new finding: %s %s: %s %s [%s] at %s",
			f.Probe, f.Target, f.Verdict.Urgency, f.Verdict.Asset.Algorithm, f.Verdict.Asset.Usage, f.Verdict.Asset.Location)
	}
	s.Log.Printf("scan #%d: %d targets, %d unreachable, %d new findings, %s",
		s.scans, len(snap.Reports), unreachable, len(snap.NewFindings), snap.Duration.Round(time.Millisecond))
}

// Snapshot returns the latest scan, and false before the first one.
func (s *Server) Snapshot() (Snapshot, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.snap == nil {
		return Snapshot{}, false
	}
	return *s.snap, true
}

// Handler serves /metrics, /report.json and /healthz.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintf(w, "pqinv %s\n/metrics      Prometheus exposition\n/report.json  latest report (pqinv JSON schema)\n/healthz      200 once the first scan has completed\n", s.Version)
	})
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		s.WriteMetrics(w)
	})
	mux.HandleFunc("/report.json", func(w http.ResponseWriter, r *http.Request) {
		snap, ok := s.Snapshot()
		if !ok {
			http.Error(w, "no scan completed yet", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = report.JSON(w, s.Version, snap.Reports)
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := s.Snapshot(); !ok {
			http.Error(w, "no scan completed yet", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		io.WriteString(w, "ok\n")
	})
	return mux
}

var (
	urgencies = []model.Urgency{model.UrgencyHigh, model.UrgencyMedium, model.UrgencyLow, model.UrgencyNone}
	classes   = []model.Class{
		model.ClassVulnerable, model.ClassHybrid, model.ClassPQSafe,
		model.ClassWeakClassical, model.ClassAcceptable, model.ClassUnknown,
	}
)

// WriteMetrics writes the Prometheus text exposition format. Series are
// emitted in a fixed order and every urgency/class series is present
// (zero included) so dashboards never see a gap when a count drops.
func (s *Server) WriteMetrics(w io.Writer) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	m := &metrics{w: w}
	m.header("pqinv_build_info", "gauge", "pqinv version running this exporter.")
	m.line("pqinv_build_info", labels{{"version", s.Version}}, 1)
	m.header("pqinv_targets", "gauge", "Number of configured targets.")
	m.line("pqinv_targets", nil, float64(len(s.Targets)))
	m.header("pqinv_scans_total", "counter", "Completed scheduled scans since start.")
	m.line("pqinv_scans_total", nil, float64(s.scans))

	if s.snap == nil {
		return
	}
	snap := s.snap
	m.header("pqinv_last_scan_timestamp_seconds", "gauge", "Unix time the latest scan started.")
	m.line("pqinv_last_scan_timestamp_seconds", nil, float64(snap.ScannedAt.Unix()))
	m.header("pqinv_last_scan_duration_seconds", "gauge", "Wall time of the latest scan.")
	m.line("pqinv_last_scan_duration_seconds", nil, snap.Duration.Seconds())

	m.header("pqinv_target_unreachable", "gauge", "1 when the latest scan could not reach the target. Treat as a failure: couldn't check is not all clear.")
	for _, r := range snap.Reports {
		m.line("pqinv_target_unreachable", target(r), b2f(r.Error != ""))
	}

	m.header("pqinv_score", "gauge", "PQ readiness score 0-100 (A>=90 B>=75 C>=50 D>=30 else F). Absent while unreachable.")
	for _, r := range snap.Reports {
		if r.Error == "" {
			m.line("pqinv_score", target(r), float64(r.Score))
		}
	}

	m.header("pqinv_findings", "gauge", "Findings in the latest scan by urgency.")
	for _, r := range snap.Reports {
		if r.Error != "" {
			continue
		}
		counts := map[model.Urgency]int{}
		for _, v := range r.Verdicts {
			counts[v.Urgency]++
		}
		for _, u := range urgencies {
			m.line("pqinv_findings", append(target(r), label{"urgency", strings.ToLower(string(u))}), float64(counts[u]))
		}
	}

	m.header("pqinv_findings_by_class", "gauge", "Findings in the latest scan by classification.")
	for _, r := range snap.Reports {
		if r.Error != "" {
			continue
		}
		counts := map[model.Class]int{}
		for _, v := range r.Verdicts {
			counts[v.Class]++
		}
		for _, c := range classes {
			m.line("pqinv_findings_by_class", append(target(r), label{"class", string(c)}), float64(counts[c]))
		}
	}

	m.header("pqinv_new_findings_last_scan", "gauge", "Findings in the latest scan that were not in the scan before it (or the --baseline for the first scan).")
	perTarget := map[string]int{}
	for _, f := range snap.NewFindings {
		perTarget[f.Probe+"\x1f"+f.Target]++
	}
	for _, r := range snap.Reports {
		m.line("pqinv_new_findings_last_scan", target(r), float64(perTarget[r.Probe+"\x1f"+r.Target]))
	}

	m.header("pqinv_new_findings_total", "counter", "Cumulative new findings observed since start. Alert on increase().")
	for _, r := range snap.Reports {
		m.line("pqinv_new_findings_total", target(r), float64(s.newTotal[r.Probe+"\x1f"+r.Target]))
	}

	m.header("pqinv_certificate_expiry_timestamp_seconds", "gauge", "NotAfter of every certificate seen, as Unix time.")
	for _, r := range snap.Reports {
		seen := map[string]bool{}
		for _, v := range r.Verdicts {
			md := v.Asset.Metadata
			if md["kind"] != "certificate" || md["not_after"] == "" {
				continue
			}
			key := v.Asset.Location + "|" + md["subject"]
			if seen[key] {
				continue
			}
			seen[key] = true
			t, err := time.Parse(time.RFC3339, md["not_after"])
			if err != nil {
				continue
			}
			m.line("pqinv_certificate_expiry_timestamp_seconds",
				append(target(r), label{"location", v.Asset.Location}, label{"subject", md["subject"]}), float64(t.Unix()))
		}
	}
}

type label struct{ k, v string }
type labels []label

func target(r report.TargetReport) labels {
	return labels{{"probe", r.Probe}, {"target", r.Target}}
}

type metrics struct{ w io.Writer }

func (m *metrics) header(name, typ, help string) {
	fmt.Fprintf(m.w, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, typ)
}

func (m *metrics) line(name string, ls labels, v float64) {
	var b strings.Builder
	b.WriteString(name)
	if len(ls) > 0 {
		b.WriteByte('{')
		for i, l := range ls {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(l.k)
			b.WriteString(`="`)
			b.WriteString(escapeLabel(l.v))
			b.WriteByte('"')
		}
		b.WriteByte('}')
	}
	b.WriteByte(' ')
	b.WriteString(formatValue(v))
	b.WriteByte('\n')
	io.WriteString(m.w, b.String())
}

// formatValue prints whole numbers (scores, counts, Unix timestamps)
// without an exponent; anything else gets the shortest exact form.
func formatValue(v float64) string {
	if v == math.Trunc(v) && math.Abs(v) < 1e15 {
		return strconv.FormatFloat(v, 'f', 0, 64)
	}
	return strconv.FormatFloat(v, 'g', -1, 64)
}

// escapeLabel applies the exposition-format rules: backslash, double
// quote and newline are escaped, nothing else.
func escapeLabel(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)
	return r.Replace(s)
}

func b2f(b bool) float64 {
	if b {
		return 1
	}
	return 0
}
