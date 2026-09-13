package scan

import (
	"context"
	"fmt"

	"golang.org/x/sync/errgroup"

	"github.com/angga-22/pqinv/internal/model"
	"github.com/angga-22/pqinv/internal/probe"
)

// Target is one entry of a targets.yaml config.
type Target struct {
	Probe  string `yaml:"probe"`
	Target string `yaml:"target"`
}

// Result pairs a target with what its probe returned. Assets come back
// sorted; classification happens downstream.
type Result struct {
	Target Target
	Assets []model.CryptoAsset
	Err    error
}

// Runner fans scans out across targets with bounded concurrency.
type Runner struct {
	Probes      map[string]probe.Probe // keyed by probe name: tls, oidc, repo
	Concurrency int
}

func (r *Runner) Run(ctx context.Context, targets []Target) []Result {
	results := make([]Result, len(targets))

	g, ctx := errgroup.WithContext(ctx)
	limit := r.Concurrency
	if limit <= 0 {
		limit = 8
	}
	g.SetLimit(limit)

	for i, t := range targets {
		g.Go(func() error {
			results[i].Target = t
			p, ok := r.Probes[t.Probe]
			if !ok {
				results[i].Err = fmt.Errorf("unknown probe %q", t.Probe)
				return nil
			}
			assets, err := p.Scan(ctx, t.Target)
			model.SortAssets(assets)
			results[i].Assets = assets
			results[i].Err = err
			return nil
		})
	}
	g.Wait() // always nil: target failures live in Results, not the group
	return results
}
