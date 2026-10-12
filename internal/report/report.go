package report

import (
	"encoding/json"
	"io"

	"github.com/angga-22/pqinv/internal/model"
)

// Status values carried in the JSON schema. An unreachable target is a
// first-class outcome, not a zero score.
const (
	StatusOK          = "ok"
	StatusUnreachable = "unreachable"
)

// TargetReport is what every renderer consumes. Its JSON form is the
// public schema — treat field names as API.
type TargetReport struct {
	Probe    string
	Target   string
	Error    string // set when the probe failed; the target is then "unreachable"
	Score    int
	Grade    string
	Verdicts []model.Verdict
}

// MarshalJSON adds an explicit status and withholds score and grade from
// an unreachable target. A zero score there would not be an F, it would
// be "we don't know", and a consumer must never be able to confuse the
// two. Verdicts are always an array, never null.
func (r TargetReport) MarshalJSON() ([]byte, error) {
	verdicts := r.Verdicts
	if verdicts == nil {
		verdicts = []model.Verdict{}
	}
	if r.Error != "" {
		return json.Marshal(struct {
			Probe    string          `json:"probe"`
			Target   string          `json:"target"`
			Status   string          `json:"status"`
			Error    string          `json:"error"`
			Verdicts []model.Verdict `json:"verdicts"`
		}{r.Probe, r.Target, StatusUnreachable, r.Error, verdicts})
	}
	return json.Marshal(struct {
		Probe    string          `json:"probe"`
		Target   string          `json:"target"`
		Status   string          `json:"status"`
		Score    int             `json:"score"`
		Grade    string          `json:"grade"`
		Verdicts []model.Verdict `json:"verdicts"`
	}{r.Probe, r.Target, StatusOK, r.Score, r.Grade, verdicts})
}

// UnmarshalJSON reads the schema MarshalJSON writes, so a report can be
// loaded back as a baseline. Status is derived from error, not stored.
func (r *TargetReport) UnmarshalJSON(data []byte) error {
	var raw struct {
		Probe    string          `json:"probe"`
		Target   string          `json:"target"`
		Error    string          `json:"error"`
		Score    int             `json:"score"`
		Grade    string          `json:"grade"`
		Verdicts []model.Verdict `json:"verdicts"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	*r = TargetReport{
		Probe: raw.Probe, Target: raw.Target, Error: raw.Error,
		Score: raw.Score, Grade: raw.Grade, Verdicts: raw.Verdicts,
	}
	return nil
}

type envelope struct {
	Tool    string         `json:"tool"`
	Version string         `json:"version"`
	Results []TargetReport `json:"results"`
}

// JSON writes the machine-readable report: verbatim verdicts plus scan
// metadata. No timestamp — identical scans produce identical bytes.
func JSON(w io.Writer, version string, reports []TargetReport) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(envelope{Tool: "pqinv", Version: version, Results: reports})
}
