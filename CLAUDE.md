# pqinv — post-quantum crypto inventory

An identity-first Go CLI that inventories the cryptography a system actually uses (OIDC/JWKS signing keys, TLS handshakes, certificate chains, source code), classifies each finding against the NIST post-quantum migration timeline, and emits pretty/JSON/CycloneDX-CBOM reports.

**Status (2026-09-13):** v0.1.0 feature-complete, preparing first release. All three probes (tls/oidc/repo), classifier + correlation, scoring, pretty/json/cbom output, `--fail-on` CI gate, `scan all`, tests across every package, README + vhs demo GIF. The as-built architecture doc is `docs/architecture.md` (Markdown + Mermaid) — the source of truth for design decisions. The original pre-code sketch survives as a Claude artifact: https://claude.ai/code/artifact/7f323b2d-2027-438e-ab07-9afa2dd74fd2

## Working with Angga

- Angga runs all shell commands themselves — provide instructions/commands to copy, never execute them directly.
- This is a learning + portfolio project: explain the *why* behind crypto and Go design choices, not just the what. Angga is an identity engineer (Keycloak, VCs, WebAuthn) growing into Go/DevOps, and is also using this project as interview prep for PQC/PKI/FIDO2 fundamentals.

## Core design decisions (see docs/architecture.html for detail)

- Four-stage pipeline: probes (oidc/tls/repo) → normalize to `CryptoAsset` → data-driven classifier (`rules/rules.yaml`, embedded via go:embed) → reporters (pretty/json/cbom). Probes never classify; the classifier never knows sources.
- Urgency is a function of **usage**, not just algorithm: vulnerable key exchange = High (harvest-now-decrypt-later); vulnerable signatures = Medium.
- `internal/` must stay free of CLI assumptions (no printing, no os.Exit) — a v2 Kubernetes operator (`cmd/pqinv-operator/`, controller-runtime, Prometheus metrics) reuses it.
- Go ≥ 1.24 (X25519MLKEM768 in stdlib). Libraries: cobra, lipgloss, lestrrat-go/jwx/v2, cyclonedx-go, x/sync/errgroup.
- `--fail-on <urgency>` makes it a CI gate; deterministic sorted output is required for that and for golden tests.

## Positioning (from competitor analysis, 2026-09-11)

Named `pqinv` because `pqready` is taken by github.com/degan/pqready (single-host X25519MLKEM768 yes/no checker). Other prior art: github.com/anvilsecure/pqcutils (TLS/SSH advertised-capability scan + PCAP analysis). Both are point checkers; pqinv's unclaimed ground = identity-layer scanning (OIDC/JWKS), classification/urgency/migration advice, CBOM output, CI gate, K8s operator. Headline: "the PQ readiness scanner for identity infrastructure." Cite both tools as related work in the README with the comparison table.

## MVP order

1. Week 1 — `model` + TLS probe (constrained-handshake enumeration + cert chain) + minimal pretty output. Demo: detect hybrid ML-KEM on cloudflare.com:443.
2. Week 2 — OIDC/JWKS probe + classifier. Demo: readiness verdict on Angga's own Keycloak realm (the unique screenshot).
3. Week 3 — repo probe + scoring + `scan all`.
4. Week 4 — JSON + CBOM output, `--fail-on`, README, v0.1.0 via goreleaser.
