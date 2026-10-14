// Package pipeline is the one place that turns probe output into a
// TargetReport: sort → classify → correlate → score. `scan` and `serve`
// both call it, so a report means the same thing however it was made.
package pipeline

import (
	"github.com/angga-22/pqinv/internal/classify"
	"github.com/angga-22/pqinv/internal/model"
	"github.com/angga-22/pqinv/internal/report"
	"github.com/angga-22/pqinv/internal/scan"
	"github.com/angga-22/pqinv/internal/score"
)

// Report builds the report for one successfully probed target.
func Report(c *classify.Classifier, probeName, target string, assets []model.CryptoAsset) report.TargetReport {
	model.SortAssets(assets)
	verdicts := classify.Correlate(c.ClassifyAll(assets))
	sc := score.Compute(verdicts)
	return report.TargetReport{
		Probe: probeName, Target: target,
		Score: sc.Score, Grade: sc.Grade,
		Verdicts: verdicts,
	}
}

// Reports maps runner results to reports in order. A failed target
// becomes an unreachable report, never a dropped one.
func Reports(c *classify.Classifier, results []scan.Result) []report.TargetReport {
	reports := make([]report.TargetReport, 0, len(results))
	for _, res := range results {
		if res.Err != nil {
			reports = append(reports, report.TargetReport{
				Probe: res.Target.Probe, Target: res.Target.Target,
				Error: res.Err.Error(),
			})
			continue
		}
		reports = append(reports, Report(c, res.Target.Probe, res.Target.Target, res.Assets))
	}
	return reports
}
