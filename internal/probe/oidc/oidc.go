package oidc

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"

	"github.com/angga-22/pqinv/internal/model"
	"github.com/angga-22/pqinv/internal/probe"
)

const (
	defaultTimeout = 10 * time.Second
	maxBody        = 1 << 20 // an IdP response larger than 1MB is not a JWKS
)

// Probe implements probe.Probe for OIDC issuers.
type Probe struct {
	Timeout   time.Duration
	Client    *http.Client
	UserAgent string

	// TLS, when set, inventories the endpoints the issuer and its JWKS
	// are served from, so one scan covers the channel tokens travel over
	// as well as the keys that sign them. An issuer on plain HTTP is
	// reported as such. Nil skips transport inventory entirely.
	TLS probe.Probe
}

func (p *Probe) Name() string { return "oidc" }

// discovery is the subset of the OpenID Provider Metadata that names
// algorithms. Every *_values_supported list is a capability the IdP
// advertises, whether or not a key for it is currently published.
type discovery struct {
	Issuer  string `json:"issuer"`
	JWKSURI string `json:"jwks_uri"`

	IDTokenSigningAlgs  []string `json:"id_token_signing_alg_values_supported"`
	IDTokenEncAlgs      []string `json:"id_token_encryption_alg_values_supported"`
	IDTokenEncEncs      []string `json:"id_token_encryption_enc_values_supported"`
	UserinfoSigningAlgs []string `json:"userinfo_signing_alg_values_supported"`
	UserinfoEncAlgs     []string `json:"userinfo_encryption_alg_values_supported"`
	UserinfoEncEncs     []string `json:"userinfo_encryption_enc_values_supported"`
	RequestSigningAlgs  []string `json:"request_object_signing_alg_values_supported"`
	RequestEncAlgs      []string `json:"request_object_encryption_alg_values_supported"`
	RequestEncEncs      []string `json:"request_object_encryption_enc_values_supported"`
	TokenAuthSigning    []string `json:"token_endpoint_auth_signing_alg_values_supported"`
	AuthzSigningAlgs    []string `json:"authorization_signing_alg_values_supported"`
	AuthzEncAlgs        []string `json:"authorization_encryption_alg_values_supported"`
	AuthzEncEncs        []string `json:"authorization_encryption_enc_values_supported"`
}

// advertised returns every advertised algorithm list with the discovery
// field it came from and the usage it implies.
func (d discovery) advertised() []struct {
	field string
	usage model.Usage
	algs  []string
} {
	type entry = struct {
		field string
		usage model.Usage
		algs  []string
	}
	return []entry{
		{"id_token_signing_alg_values_supported", model.UsageSignature, d.IDTokenSigningAlgs},
		{"userinfo_signing_alg_values_supported", model.UsageSignature, d.UserinfoSigningAlgs},
		{"request_object_signing_alg_values_supported", model.UsageSignature, d.RequestSigningAlgs},
		{"token_endpoint_auth_signing_alg_values_supported", model.UsageSignature, d.TokenAuthSigning},
		{"authorization_signing_alg_values_supported", model.UsageSignature, d.AuthzSigningAlgs},
		{"id_token_encryption_alg_values_supported", model.UsageEncryption, d.IDTokenEncAlgs},
		{"id_token_encryption_enc_values_supported", model.UsageEncryption, d.IDTokenEncEncs},
		{"userinfo_encryption_alg_values_supported", model.UsageEncryption, d.UserinfoEncAlgs},
		{"userinfo_encryption_enc_values_supported", model.UsageEncryption, d.UserinfoEncEncs},
		{"request_object_encryption_alg_values_supported", model.UsageEncryption, d.RequestEncAlgs},
		{"request_object_encryption_enc_values_supported", model.UsageEncryption, d.RequestEncEncs},
		{"authorization_encryption_alg_values_supported", model.UsageEncryption, d.AuthzEncAlgs},
		{"authorization_encryption_enc_values_supported", model.UsageEncryption, d.AuthzEncEncs},
	}
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

	// Stream 1: what the IdP says it can do. One asset per (usage,
	// algorithm) — a realm advertising RS256 in five lists is one fact,
	// recorded once with every list that names it.
	type advKey struct {
		usage model.Usage
		alg   string
	}
	advIndex := map[advKey]int{}
	for _, list := range disc.advertised() {
		for _, alg := range list.algs {
			k := advKey{list.usage, alg}
			if i, seen := advIndex[k]; seen {
				assets[i].Metadata["advertised_in"] += "," + list.field
				continue
			}
			kind := "advertised-signing-alg"
			if list.usage == model.UsageEncryption {
				kind = "advertised-encryption-alg"
			}
			advIndex[k] = len(assets)
			assets = append(assets, model.CryptoAsset{
				Source:    p.Name(),
				Location:  discoveryURL,
				Usage:     list.usage,
				Algorithm: alg,
				Metadata: map[string]string{
					"kind":          kind,
					"issuer":        disc.Issuer,
					"advertised_in": list.field,
				},
			})
		}
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

	// Stream 3: the transport. Tokens are harvested on the wire, so the
	// issuer's TLS is part of the issuer's PQ readiness.
	if p.TLS != nil {
		transport, err := p.transportAssets(ctx, issuer, disc.JWKSURI)
		if err != nil {
			return nil, err
		}
		assets = append(assets, transport...)
	}

	return assets, nil
}

// transportAssets inventories each distinct host:port the issuer and
// JWKS live on. HTTPS endpoints get the full TLS probe; a plain-HTTP
// endpoint is itself the finding.
func (p *Probe) transportAssets(ctx context.Context, urls ...string) ([]model.CryptoAsset, error) {
	var assets []model.CryptoAsset
	seen := map[string]bool{}
	for _, raw := range urls {
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			continue
		}
		port := u.Port()
		if port == "" {
			port = "443"
			if u.Scheme == "http" {
				port = "80"
			}
		}
		hostport := net.JoinHostPort(u.Hostname(), port)
		if seen[hostport] {
			continue
		}
		seen[hostport] = true

		if u.Scheme != "https" {
			assets = append(assets, model.CryptoAsset{
				Source:    p.Name(),
				Location:  hostport,
				Usage:     model.UsageProtocol,
				Algorithm: "HTTP",
				Metadata:  map[string]string{"kind": "plaintext-transport", "url": raw},
			})
			continue
		}
		tlsAssets, err := p.TLS.Scan(ctx, hostport)
		if err != nil {
			return nil, fmt.Errorf("inventory TLS of %s: %w", hostport, err)
		}
		assets = append(assets, tlsAssets...)
	}
	return assets, nil
}

func keyAsset(disc discovery, key jwk.Key) model.CryptoAsset {
	usage := model.UsageSignature
	if key.KeyUsage() == "enc" {
		usage = model.UsageEncryption
	}

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
				// An EC key published for encryption is used for ECDH-ES
				// key agreement, not for signing.
				if usage == model.UsageEncryption {
					alg = "ECDH " + pub.Curve.Params().Name
				} else {
					alg = "ECDSA " + pub.Curve.Params().Name
				}
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
	ua := p.UserAgent
	if ua == "" {
		ua = "pqinv"
	}
	req.Header.Set("User-Agent", ua)

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
