package report

import (
	"encoding/json"
	"io"

	"github.com/angga-22/pqinv/internal/model"
)

type TargetReport struct {
	Probe    string          `json:"probe"`
	Target   string          `json:"target"`
	Error    string          `json:"error,omitempty"`
	Score    int             `json:"score"`
	Grade    string          `json:"grade"`
	Verdicts []model.Verdict `json:"verdicts"`
}

type envelope struct {
	Tool    string         `json:"tool"`
	Version string         `json:"version"`
	Results []TargetReport `json:"results"`
}

// JSON writes the machine-readable report: verbatim verdicts plus scan
// metadata.
func JSON(w io.Writer, version string, reports []TargetReport) error {
	for i := range reports {
		if reports[i].Verdicts == nil {
			reports[i].Verdicts = []model.Verdict{} // [] not null — kinder to consumers
		}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(envelope{Tool: "pqinv", Version: version, Results: reports})
}
