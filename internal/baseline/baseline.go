// Package baseline makes the CI gate adoptable. Every endpoint without
// hybrid key exchange has High findings today, so a gate that fails on
// any High is red on day one and gets turned off. Against a baseline —
// a previous pqinv JSON report — the gate fails only on findings that
// are new since then: regressions, not inherited debt.
package baseline

import (
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/angga-22/pqinv/internal/model"
	"github.com/angga-22/pqinv/internal/report"
)

// Baseline is a multiset of finding fingerprints from an earlier report.
type Baseline struct {
	counts  map[string]int
	Targets int
}

// Finding is a verdict that was not in the baseline, with the report it
// belongs to.
type Finding struct {
	Probe   string
	Target  string
	Verdict model.Verdict
}

// Load reads a report written by `pqinv ... --format json`.
func Load(r io.Reader) (*Baseline, error) {
	var doc struct {
		Tool    string                `json:"tool"`
		Results []report.TargetReport `json:"results"`
	}
	if err := json.NewDecoder(r).Decode(&doc); err != nil {
		return nil, fmt.Errorf("parse baseline: %w", err)
	}
	if doc.Tool != "pqinv" {
		return nil, fmt.Errorf("parse baseline: not a pqinv JSON report (tool = %q)", doc.Tool)
	}
	return FromReports(doc.Results), nil
}

// FromReports builds a baseline from in-memory reports.
func FromReports(reports []report.TargetReport) *Baseline {
	b := &Baseline{counts: map[string]int{}, Targets: len(reports)}
	for _, rep := range reports {
		for _, v := range rep.Verdicts {
			b.counts[Key(rep.Probe, rep.Target, v)]++
		}
	}
	return b
}

// NewFindings returns the verdicts in reports that the baseline does not
// account for. Matching is a multiset difference: two MD5 hits in one
// file against a baseline with one leaves one new finding.
func (b *Baseline) NewFindings(reports []report.TargetReport) []Finding {
	remaining := make(map[string]int, len(b.counts))
	for k, n := range b.counts {
		remaining[k] = n
	}
	var out []Finding
	for _, rep := range reports {
		for _, v := range rep.Verdicts {
			k := Key(rep.Probe, rep.Target, v)
			if remaining[k] > 0 {
				remaining[k]--
				continue
			}
			out = append(out, Finding{Probe: rep.Probe, Target: rep.Target, Verdict: v})
		}
	}
	return out
}

var lineSuffix = regexp.MustCompile(`:\d+$`)

// Key is a finding's identity across scans. It includes class and
// urgency, so a finding that was Low and is now High counts as new. For
// repo findings the line number is dropped: an edit above a finding
// moves it, it does not create it.
func Key(probe, target string, v model.Verdict) string {
	loc := v.Asset.Location
	if v.Asset.Source == "repo" {
		loc = lineSuffix.ReplaceAllString(loc, "")
	}
	return strings.Join([]string{
		probe, target, v.Asset.Source, loc, string(v.Asset.Usage), v.Asset.Algorithm,
		string(v.Class), string(v.Urgency),
	}, "\x1f")
}
