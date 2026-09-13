# pqinv — post-quantum crypto inventory

[![Go Reference](https://pkg.go.dev/badge/github.com/angga-22/pqinv.svg)](https://pkg.go.dev/github.com/angga-22/pqinv)
[![Go Report Card](https://goreportcard.com/badge/github.com/angga-22/pqinv)](https://goreportcard.com/report/github.com/angga-22/pqinv)
[![Release](https://img.shields.io/github/v/release/angga-22/pqinv)](https://github.com/angga-22/pqinv/releases)
[![Go Version](https://img.shields.io/github/go-mod/go-version/angga-22/pqinv)](go.mod)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**The PQ readiness scanner for identity infrastructure.** pqinv inventories the cryptography a system *actually uses* — OIDC/JWKS signing keys, TLS handshakes, certificate chains, source code — classifies every finding against the NIST post-quantum migration timeline, and tells you what to do about it. Point it at a Keycloak realm and learn whether your identity platform is quantum-ready.

```
pqinv scan oidc https://id.example.com/realms/main   # discovery doc + JWKS — the headline
pqinv scan tls  id.example.com:443                   # handshake enumeration + cert chain
pqinv scan repo ./my-service                         # static crypto-usage scan
pqinv scan all  --config targets.yaml                # many targets, one report
```

![pqinv demo: TLS, OIDC, repo scans and the CI gate](docs/img/demo.gif)

## Why

Two deadlines drive the post-quantum migration ([NIST IR 8547](https://csrc.nist.gov/pubs/ir/8547/ipd)): classical public-key crypto is **deprecated after 2030** and **disallowed after 2035**. But the urgent problem is earlier than any quantum computer: **harvest-now-decrypt-later**. TLS traffic and encrypted tokens recorded today can be decrypted retroactively once a cryptographically relevant quantum computer exists — so quantum-vulnerable *key exchange* is a today-problem, while quantum-vulnerable *signatures* (which can't be forged retroactively) are a plan-now problem. pqinv's classifier encodes exactly that distinction: urgency is a function of **usage**, not just algorithm.

Identity infrastructure sits at the sharp end. Every ID token your IdP issues is signed with RS256 or ES256, both broken by Shor's algorithm, and no standardized post-quantum JOSE algorithm exists yet (ML-DSA for JOSE/COSE is an IETF draft). You can't fix that today — but you can't manage what you haven't inventoried.

## What it does

Everything is a pipeline — probes collect evidence, a data-driven classifier (`rules/rules.yaml`, embedded in the binary) turns it into verdicts with rationale and migration advice, and reporters render pretty terminal output, stable JSON, or a CycloneDX 1.6 CBOM. How each stage works, and why it's shaped that way, lives in **[docs/architecture.md](docs/architecture.md)**.

- **TLS probe** — detects hybrid post-quantum key exchange (`X25519MLKEM768`), supported classical groups, protocol versions TLS 1.0→1.3, and every certificate in the presented chain.
- **OIDC probe** — points at any OIDC issuer (Keycloak, Auth0, Entra, Okta) and classifies both the *published* JWKS keys and the *advertised* signing algorithms.
- **Repo probe** — finds crypto imports, JOSE algorithm literals, and committed private keys in source, with `file.go:42` locations.
- **Verdicts that understand context** — a classical key-exchange group offered *alongside* a hybrid PQ one is flagged as a fallback, not screamed about as an exposure.
- **A readiness score** — 0–100 with a letter grade per target (see [Reading the score](#reading-the-score)).
- **CI gate** — `--fail-on high` exits 1 on findings at or above the threshold; unreachable targets always fail, because "couldn't check" must never read as "all clear".

Real scans, September 2026:

| Target | Grade | The story |
|---|---|---|
| cloudflare.com | **C 52** | Hybrid ML-KEM live — but TLS 1.0/1.1 still accepted |
| github.com | **D 31** | No PQ key exchange at all: classical X25519/P-256 only |
| a Keycloak realm | **C 60** | Every token signature quantum-vulnerable; RSA-OAEP enc key is HNDL-urgent |

## Install

```bash
go install github.com/angga-22/pqinv/cmd/pqinv@latest
```

Requires Go ≥ 1.24 to build (X25519MLKEM768 in the standard library). Or grab a release binary.

## Output formats

`--format json` emits a stable, timestamp-free document (identical scans produce identical bytes — reports are diffable in CI):

```json
{
  "tool": "pqinv",
  "version": "0.1.0",
  "results": [
    {
      "probe": "tls",
      "target": "github.com:443",
      "score": 31,
      "grade": "D",
      "verdicts": [
        {
          "asset": {"source": "tls", "location": "github.com:443", "usage": "KeyExchange", "algorithm": "X25519"},
          "class": "Vulnerable",
          "urgency": "High",
          "rationale": "…harvest-now-decrypt-later…",
          "migration": "Enable hybrid key exchange X25519MLKEM768 …"
        }
      ]
    }
  ]
}
```

`--format cbom` emits a [CycloneDX 1.6 Cryptography Bill of Materials](https://cyclonedx.org/capabilities/cbom/): one `cryptographic-asset` component per finding, pqinv's classification carried in `pqinv:*` properties.

## CI gate

```yaml
# .github/workflows/pq-readiness.yml
- name: PQ readiness gate
  run: pqinv scan all --config targets.yaml --fail-on high --format json --out pq-report.json
```

## Reading the score

Grades: **A ≥90 · B ≥75 · C ≥50 · D ≥30 · else F.** Findings deduct points by urgency, capped per usage category, so many findings restating one fact (a realm advertising ten classical JOSE algorithms, say) count as one capped fact — and classical certificate signatures, unavoidable in 2026, can't drag an otherwise well-configured system to F. Roughly: **A/B** means hybrid PQ key exchange is live and hygiene is good, **C** means either no PQ yet or legacy protocol debt, **D/F** means harvest-now-decrypt-later exposure with nothing mitigating it. The exact formula, caps, and real-site calibration are in the [architecture doc](docs/architecture.md#scoring).

## Related work

| Capability | [pqcscan](https://github.com/anvilsecure/pqcutils) (Anvil) | [pqready](https://github.com/degan/pqready) | pqinv |
|---|:-:|:-:|:-:|
| TLS PQC key-exchange check | ✓ | ✓ | ✓ |
| SSH check | ✓ | — | roadmap |
| Certificate chain analysis | — | — | ✓ |
| OIDC / JWKS / token signing | — | — | ✓ |
| Source-code crypto scanning | — | — | ✓ |
| Classification + urgency model (HNDL) | — | — | ✓ |
| Migration advice per finding | — | — | ✓ |
| CBOM (CycloneDX 1.6) output | — | — | ✓ |
| CI gate (`--fail-on`) | — | — | ✓ |
| Continuous monitoring (K8s operator) | — | — | v2 |

Both tools answer "does this endpoint advertise PQC key exchange?" — a point-in-time yes/no. pqinv aims at the layer above: inventory, classification, urgency, and workflow, with the identity plane (which neither touches) as its home turf.

## Limitations (v1, on purpose)

- Go's stdlib refuses to offer truly legacy junk (SSLv3, RC4, export ciphers), so those are invisible to the TLS probe. The tool's job is PQ readiness, not an ssllabs clone.
- The repo probe is regex, not AST: it can't tell a comment from code (pqinv flags its own `rules.yaml` — an honest artifact of pattern scanning). Doc/markup files are excluded; config formats are scanned on purpose.
- `.gitignore` is not parsed; well-known junk directories are skipped instead.

## Roadmap

SSH probe (credit: pqcscan does this), a FIDO2/WebAuthn probe (COSE algorithms your passkey deployment accepts), SAML metadata scanning, passive PCAP analysis (credit: pqcdump), AST-based Go analysis, finer CBOM asset typing — and v2: a Kubernetes operator that watches Ingress/TLS Secrets and exports per-target readiness as Prometheus metrics ([sketch](docs/architecture.md#v2-sketch-the-kubernetes-operator)).

## References

FIPS 203 (ML-KEM) · FIPS 204 (ML-DSA) · FIPS 205 (SLH-DSA) · NIST IR 8547 (migration timeline) · RFC 8996 (TLS 1.0/1.1 deprecation) · RFC 8446 (TLS 1.3) · CycloneDX 1.6 CBOM

## License

[MIT](LICENSE)
