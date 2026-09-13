package classify

import "github.com/angga-22/pqinv/internal/model"

// Correlate applies cross-finding adjustments that no single-asset rule
// can express — the rules engine sees one asset at a time, but some
// judgments only make sense across the whole scan.
//
// Today there is one: a classical key-exchange group offered ALONGSIDE
// a hybrid PQ group at the same endpoint is a fallback, not the
// ceiling. PQ-capable clients negotiate the hybrid group, so
// harvest-now-decrypt-later no longer applies to them, and the classical
// group's urgency drops from High to Low. An endpoint with no hybrid
// group at all keeps the full High — that is the real exposure.
func Correlate(verdicts []model.Verdict) []model.Verdict {
	hybridAt := map[string]bool{}
	for _, v := range verdicts {
		if v.Asset.Usage == model.UsageKeyExchange &&
			(v.Class == model.ClassHybrid || v.Class == model.ClassPQSafe) {
			hybridAt[v.Asset.Location] = true
		}
	}
	for i := range verdicts {
		v := &verdicts[i]
		if v.Asset.Usage == model.UsageKeyExchange &&
			v.Class == model.ClassVulnerable &&
			v.Urgency == model.UrgencyHigh &&
			hybridAt[v.Asset.Location] {
			v.Urgency = model.UrgencyLow
			v.Rationale += " Downgraded: hybrid PQ is live on this endpoint, so capable clients never touch this group — it survives as a fallback for older ones."
			v.Migration = "Watch which clients still negotiate classical groups; retire the fallbacks when they stop."
		}
	}
	return verdicts
}
