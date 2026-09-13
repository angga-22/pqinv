package score

import "github.com/angga-22/pqinv/internal/model"

type Result struct {
	Score int
	Grade string
}

var deductionPerFinding = map[model.Urgency]int{
	model.UrgencyHigh:   25,
	model.UrgencyMedium: 5,
	model.UrgencyLow:    2,
}

var usageCap = map[model.Usage]int{
	model.UsageKeyExchange: 50,
	model.UsageEncryption:  25,
	model.UsageProtocol:    25,
	model.UsageSignature:   15,
	model.UsageHash:        15,
}

const defaultCap = 15

func Compute(verdicts []model.Verdict) Result {
	perUsage := map[model.Usage]int{}
	for _, v := range verdicts {
		perUsage[v.Asset.Usage] += deductionPerFinding[v.Urgency]
	}

	total := 0
	for usage, d := range perUsage {
		limit, ok := usageCap[usage]
		if !ok {
			limit = defaultCap
		}
		total += min(d, limit)
	}

	s := max(0, 100-total)
	return Result{Score: s, Grade: grade(s)}
}

func grade(s int) string {
	switch {
	case s >= 90:
		return "A"
	case s >= 75:
		return "B"
	case s >= 50:
		return "C"
	case s >= 30:
		return "D"
	default:
		return "F"
	}
}
