// Package probe defines the interface every evidence collector
// implements. Probes talk to the world and return raw findings as
// normalized CryptoAssets; they never classify.
package probe

import (
	"context"

	"github.com/angga-22/pqinv/internal/model"
)

type Probe interface {
	Name() string
	Scan(ctx context.Context, target string) ([]model.CryptoAsset, error)
}
