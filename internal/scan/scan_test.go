package scan

import (
	"context"
	"errors"
	"testing"

	"github.com/angga-22/pqinv/internal/model"
	"github.com/angga-22/pqinv/internal/probe"
)

type fakeProbe struct {
	name string
	err  error
}

func (f *fakeProbe) Name() string { return f.name }

func (f *fakeProbe) Scan(ctx context.Context, target string) ([]model.CryptoAsset, error) {
	if f.err != nil {
		return nil, f.err
	}
	return []model.CryptoAsset{{Source: f.name, Location: target, Algorithm: "X25519"}}, nil
}

func TestRunPreservesOrderAndCapturesFailures(t *testing.T) {
	boom := errors.New("connection refused")
	r := &Runner{
		Concurrency: 2,
		Probes: map[string]probe.Probe{
			"ok":  &fakeProbe{name: "ok"},
			"bad": &fakeProbe{name: "bad", err: boom},
		},
	}
	targets := []Target{
		{Probe: "ok", Target: "a"},
		{Probe: "bad", Target: "b"},
		{Probe: "missing", Target: "c"},
		{Probe: "ok", Target: "d"},
	}
	results := r.Run(context.Background(), targets)

	if len(results) != 4 {
		t.Fatalf("got %d results, want 4", len(results))
	}
	for i, want := range targets {
		if results[i].Target != want {
			t.Errorf("result %d is for %+v, want %+v — order must match config", i, results[i].Target, want)
		}
	}
	if results[0].Err != nil || len(results[0].Assets) != 1 {
		t.Errorf("result 0 = %+v, want one asset and no error", results[0])
	}
	if !errors.Is(results[1].Err, boom) {
		t.Errorf("result 1 error = %v, want probe failure captured", results[1].Err)
	}
	if results[2].Err == nil {
		t.Error("result 2: unknown probe must produce an error entry")
	}
	if results[3].Err != nil {
		t.Errorf("a failed target must not abort others: result 3 err = %v", results[3].Err)
	}
}
