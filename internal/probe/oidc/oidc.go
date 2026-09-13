package oidc

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"

	"github.com/angga-22/pqinv/internal/model"
)

const (
	defaultTimeout = 10 * time.Second
	maxBody        = 1 << 20 // an IdP response larger than 1MB is not a JWKS
)

// Probe implements probe.Probe for OIDC issuers.
type Probe struct {
	Timeout time.Duration
	Client  *http.Client
}

func (p *Probe) Name() string { return "oidc" }

type discovery struct {
	Issuer             string   `json:"issuer"`
	JWKSURI            string   `json:"jwks_uri"`
	IDTokenSigningAlgs []string `json:"id_token_signing_alg_values_supported"`
}

func (p *Probe) Scan(ctx context.Context, issuer string) ([]model.CryptoAsset, error) {
	issuer = strings.TrimRight(issuer, "/")
	discoveryURL := issuer + "/.well-known/openid-configuration"

	body, err := p.get(ctx, discoveryURL)
	if err != nil {
		return nil, fmt.Errorf("fetch discovery document: %w", err)
	}
	var disc discovery
	if err := json.Unmarshal(body, &disc); err != nil {
		return nil, fmt.Errorf("parse discovery document at %s: %w", discoveryURL, err)
	}
	if disc.JWKSURI == "" {
		return nil, fmt.Errorf("discovery document at %s has no jwks_uri", discoveryURL)
	}

	var assets []model.CryptoAsset

	// Stream 1: what the IdP says it could sign ID tokens with — a
	// capability finding even when no such key is currently published.
	for _, alg := range disc.IDTokenSigningAlgs {
		assets = append(assets, model.CryptoAsset{
			Source:    p.Name(),
			Location:  discoveryURL,
			Usage:     model.UsageSignature,
			Algorithm: alg,
			Metadata: map[string]string{
				"kind":   "advertised-signing-alg",
				"issuer": disc.Issuer,
			},
		})
	}

	// Stream 2: the keys actually published in the JWKS.
	jwksBody, err := p.get(ctx, disc.JWKSURI)
	if err != nil {
		return nil, fmt.Errorf("fetch JWKS: %w", err)
	}
	set, err := jwk.Parse(jwksBody)
	if err != nil {
		return nil, fmt.Errorf("parse JWKS at %s: %w", disc.JWKSURI, err)
	}
	for i := 0; i < set.Len(); i++ {
		key, ok := set.Key(i)
		if !ok {
			continue
		}
		assets = append(assets, keyAsset(disc, key))
	}

	return assets, nil
}

func keyAsset(disc discovery, key jwk.Key) model.CryptoAsset {
	alg := ""
	if a := key.Algorithm(); a != nil {
		alg = a.String()
	}

	bits := 0
	var raw any
	if err := key.Raw(&raw); err == nil {
		switch pub := raw.(type) {
		case *rsa.PublicKey:
			bits = pub.N.BitLen()
			if alg == "" {
				alg = "RSA"
			}
		case *ecdsa.PublicKey:
			bits = pub.Curve.Params().BitSize
			if alg == "" {
				alg = "ECDSA " + pub.Curve.Params().Name
			}
		case ed25519.PublicKey:
			bits = 256
			if alg == "" {
				alg = "EdDSA"
			}
		}
	}
	if alg == "" {
		alg = key.KeyType().String()
	}

	usage := model.UsageSignature
	if key.KeyUsage() == "enc" {
		usage = model.UsageEncryption
	}

	return model.CryptoAsset{
		Source:    "oidc",
		Location:  disc.JWKSURI,
		Usage:     usage,
		Algorithm: alg,
		KeyBits:   bits,
		Metadata: map[string]string{
			"kind":   "jwk",
			"kid":    key.KeyID(),
			"kty":    key.KeyType().String(),
			"use":    key.KeyUsage(),
			"issuer": disc.Issuer,
		},
	}
}

func (p *Probe) get(ctx context.Context, url string) ([]byte, error) {
	timeout := p.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "pqinv/0.1")

	client := p.Client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxBody))
}
