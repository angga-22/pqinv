# pqinv — post-quantum crypto inventory

[![Go Reference](https://pkg.go.dev/badge/github.com/angga-22/pqinv.svg)](https://pkg.go.dev/github.com/angga-22/pqinv)
[![Go Report Card](https://goreportcard.com/badge/github.com/angga-22/pqinv)](https://goreportcard.com/report/github.com/angga-22/pqinv)
[![Release](https://img.shields.io/github/v/release/angga-22/pqinv)](https://github.com/angga-22/pqinv/releases)
[![Go Version](https://img.shields.io/github/go-mod/go-version/angga-22/pqinv)](go.mod)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**The PQ readiness scanner for identity infrastructure.** pqinv inventories the cryptography a system *actually uses* — OIDC/JWKS keys, SAML metadata, TLS handshakes, certificate chains, source code — classifies every finding against the NIST post-quantum migration timeline, and tells you what to do about it. Point it at a Keycloak realm and learn whether your identity platform is quantum-ready.

```
pqinv scan oidc https://id.example.com/realms/main   # discovery doc + JWKS + the issuer's TLS — the headline
pqinv scan saml https://idp.example.org/idp/shibboleth  # SAML metadata: certs + XML signature/encryption algs
pqinv scan tls  id.example.com:443                   # handshake enumeration + cert chain
pqinv scan repo ./my-service                         # static crypto-usage scan
pqinv scan all  --config targets.yaml                # many targets, one report
pqinv scan all  --config targets.yaml --fail-on high --baseline last.json   # CI: fail only on regressions
pqinv serve     --config targets.yaml --interval 1h  # continuous: Prometheus metrics on :9465
```

![pqinv demo: TLS, OIDC, repo scans and the CI gate](docs/img/demo.gif)

## Why

Two deadlines drive the post-quantum migration ([NIST IR 8547](https://csrc.nist.gov/pubs/ir/8547/ipd)): classical public-key crypto is **deprecated after 2030** and **disallowed after 2035**. But the urgent problem is earlier than any quantum computer: **harvest-now-decrypt-later**. TLS traffic and encrypted tokens recorded today can be decrypted retroactively once a cryptographically relevant quantum computer exists — so quantum-vulnerable *key exchange* is a today-problem, while quantum-vulnerable *signatures* (which can't be forged retroactively) are a plan-now problem. pqinv's classifier encodes exactly that distinction: urgency is a function of **usage**, not just algorithm.

Identity infrastructure sits at the sharp end. Every ID token your IdP issues is signed with RS256 or ES256, both broken by Shor's algorithm, and no standardized post-quantum JOSE algorithm exists yet (ML-DSA for JOSE/COSE is an IETF draft). You can't fix that today — but you can't manage what you haven't inventoried.

## What it does

Everything is a pipeline — probes collect evidence, a data-driven classifier (`rules/rules.yaml`, embedded in the binary) turns it into verdicts with rationale and migration advice, and reporters render pretty terminal output, stable JSON, or a CycloneDX 1.6 CBOM. How each stage works, and why it's shaped that way, lives in **[docs/architecture.md](docs/architecture.md)**.

- **TLS probe** — detects hybrid post-quantum key exchange (`X25519MLKEM768`), supported classical groups, RSA key transport (no forward secrecy — invisible to a default Go handshake, so it gets its own pass), protocol versions TLS 1.0→1.3, and every certificate in the presented chain, including the hash it was signed with.
- **OIDC probe** — points at any OIDC issuer (Keycloak, Auth0, Entra, Okta) and classifies the *published* JWKS keys, every *advertised* signing and encryption algorithm across all discovery lists, and the TLS endpoint the issuer and JWKS are served from — the channel tokens are harvested on. One scan, the whole IdP.
- **SAML probe** — reads IdP, SP, or federation metadata (URL or file) and classifies the signing and encryption certificates plus every `SignatureMethod`, `DigestMethod`, `SigningMethod` and `EncryptionMethod` named. This is where `rsa-sha1` and RSA key transport still live in 2026.
- **Repo probe** — finds crypto imports, JOSE algorithm literals, and committed private keys (PEM, PKCS#8, OpenSSH — flagged High: a key in git is compromised today) in source, with `file.go:42` locations.
- **Verdicts that understand context** — a classical key-exchange group offered *alongside* a hybrid PQ one is flagged as a fallback, not screamed about as an exposure.
- **A readiness score** — 0–100 with a letter grade per target (see [Reading the score](#reading-the-score)).
- **CI gate** — `--fail-on high` exits 1 on findings at or above the threshold; unreachable targets always fail, because "couldn't check" must never read as "all clear". Add `--baseline last.json` and only findings *new since that report* count — a gate you can turn on today, on endpoints that are not PQ-ready yet, and that catches regressions.
- **Continuous monitoring** — `pqinv serve` rescans a targets file on an interval and exposes per-target score, findings, unreachability, new-findings counters and certificate expiry as Prometheus metrics. Identity infrastructure changes without a commit — an IdP upgrade, a cert rotation, a console click — and this is what notices.

Real scans, October 2026:

| Target | Grade | The story |
|---|---|---|
| cloudflare.com | **C 50** | Hybrid ML-KEM live — but TLS 1.0/1.1 and RSA key transport still accepted |
| github.com | **D 31** | No PQ key exchange at all: classical ECDHE and RSA key transport only |
| accounts.google.com (OIDC) | **C 50** | Tokens signed RS256 over classical TLS; no hybrid key exchange on the issuer |
| a Keycloak realm | **C 60** | Every token signature quantum-vulnerable; RSA-OAEP enc key is HNDL-urgent (v0.2 scan, before the issuer's TLS counted) |

## Install

```bash
go install github.com/angga-22/pqinv/cmd/pqinv@latest
```

Requires Go ≥ 1.26 to build — the floor is set by the dependency set, kept current because govulncheck runs in CI (X25519MLKEM768 itself has been in the standard library since 1.24). Or grab a release binary.

Changes between versions are in [CHANGELOG.md](CHANGELOG.md).

## Internal issuers

Most identity infrastructure lives behind a private CA. `--ca-file ca.pem` adds a PEM bundle to the trust store the OIDC and SAML probes fetch with; `--insecure` skips verification entirely (lab realms only). The TLS probe is unaffected either way — it never verifies, because it inventories what a server *presents*, trusted or not.

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
      "status": "ok",
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

An unreachable target is reported as `"status": "unreachable"` with an `error` and **no** `score` or `grade` — "couldn't check" is never a number.

`--format cbom` emits a [CycloneDX 1.6 Cryptography Bill of Materials](https://cyclonedx.org/capabilities/cbom/): one `cryptographic-asset` component per finding, pqinv's classification carried in `pqinv:*` properties.

## CI gate

```yaml
# .github/workflows/pq-readiness.yml
- name: PQ readiness gate
  run: pqinv scan all --config targets.yaml --fail-on high --format json --out pq-report.json
```

That gate is red on day one for any endpoint without hybrid key exchange — which in 2026 is most of them — so nobody keeps it. Use a **baseline** instead: commit a known report, and fail only on findings that are new since it.

```bash
pqinv scan all --config targets.yaml --format json --out pq-baseline.json   # once; commit it
pqinv scan all --config targets.yaml --fail-on high --baseline pq-baseline.json   # in CI
```

A finding is "new" when its (target, source, location, usage, algorithm, class, urgency) was not in the baseline: a Low that becomes High counts, a repo finding that moved to another line does not, and unreachable targets always fail. When the gate trips it names the new findings. Re-generate the baseline when you have *fixed* things, not when you have accepted them.

## Continuous monitoring

```bash
pqinv serve --config targets.yaml --interval 1h --listen :9465 [--baseline last.json]
```

| Path | What |
|---|---|
| `/metrics` | Prometheus exposition (below) |
| `/report.json` | latest report in the `--format json` schema — a valid `--baseline` input |
| `/healthz` | 200 once the first scan has completed |

| Metric | Labels | Meaning |
|---|---|---|
| `pqinv_score` | probe, target | 0–100; **absent** while the target is unreachable, never zero |
| `pqinv_findings` | probe, target, urgency | findings by urgency (every urgency always present) |
| `pqinv_findings_by_class` | probe, target, class | findings by classification |
| `pqinv_target_unreachable` | probe, target | 1 when the last scan could not reach it — alert on this, "couldn't check" is not "all clear" |
| `pqinv_new_findings_total` | probe, target | counter: findings that were not in the previous scan (or `--baseline` for the first) — alert on `increase()` |
| `pqinv_new_findings_last_scan` | probe, target | the same, for the latest scan only |
| `pqinv_certificate_expiry_timestamp_seconds` | probe, target, location, subject | NotAfter of every certificate seen |
| `pqinv_scans_total`, `pqinv_last_scan_timestamp_seconds`, `pqinv_last_scan_duration_seconds`, `pqinv_targets`, `pqinv_build_info` | | exporter health |

Every scan is compared with the one before it; new findings are logged to stderr and counted. Two alert rules cover most of it:

```yaml
groups:
  - name: pq-readiness
    rules:
      - alert: PQReadinessRegression
        expr: increase(pqinv_new_findings_total[2h]) > 0
        labels: {severity: warning}
        annotations: {summary: "new crypto finding on {{ $labels.target }}"}
      - alert: PQReadinessTargetUnreachable
        expr: pqinv_target_unreachable == 1
        for: 2h
        labels: {severity: warning}
        annotations: {summary: "pqinv cannot scan {{ $labels.target }}"}
```

No Prometheus client library: the exposition format is written by hand, and the binary stays dependency-light. `serve` reuses every probe flag (`--timeout`, `--concurrency`, `--ca-file`, `--insecure`); the minimum interval is 10s so a typo cannot hammer an IdP.

## Reading the score

Grades: **A ≥90 · B ≥75 · C ≥50 · D ≥30 · else F.** Findings deduct points by urgency, capped per usage category, so many findings restating one fact (a realm advertising ten classical JOSE algorithms, say) count as one capped fact — and classical certificate signatures, unavoidable in 2026, can't drag an otherwise well-configured system to F. Roughly: **B** means hybrid PQ key exchange is live and hygiene is good, **C** means either no PQ yet or legacy protocol debt, **D/F** means harvest-now-decrypt-later exposure with nothing mitigating it.

**A is not reachable in 2026.** Every public certificate is still signed with a classical algorithm, no CA issues ML-DSA certificates, and no PQ JOSE algorithm is standardized — so even a perfectly configured endpoint loses the signature points and tops out around B 75–79. Treat B as today's ceiling; A exists so the scale does not have to change when the ecosystem catches up. The exact formula, caps, and real-site calibration are in the [architecture doc](docs/architecture.md#scoring).

## Related work

| Capability | [pqcscan](https://github.com/anvilsecure/pqcutils) (Anvil) | [pqready](https://github.com/degan/pqready) | pqinv |
|---|:-:|:-:|:-:|
| TLS PQC key-exchange check | ✓ | ✓ | ✓ |
| SSH check | ✓ | — | roadmap |
| Certificate chain analysis | — | — | ✓ |
| OIDC / JWKS / token signing | — | — | ✓ |
| Issuer TLS in the same scan | — | — | ✓ |
| SAML metadata (certs + XML algorithms) | — | — | ✓ |
| Source-code crypto scanning | — | — | ✓ |
| Classification + urgency model (HNDL) | — | — | ✓ |
| Migration advice per finding | — | — | ✓ |
| CBOM (CycloneDX 1.6) output | — | — | ✓ |
| CI gate (`--fail-on`, `--baseline` regressions) | — | — | ✓ |
| Continuous monitoring (`pqinv serve`, Prometheus) | — | — | ✓ |
| Kubernetes operator (target discovery) | — | — | v2 |

Both tools answer "does this endpoint advertise PQC key exchange?" — a point-in-time yes/no. pqinv aims at the layer above: inventory, classification, urgency, and workflow, with the identity plane (which neither touches) as its home turf.

## Limitations (v1, on purpose)

- Go's stdlib refuses to offer truly legacy junk (SSLv3, RC4, export ciphers), so those are invisible to the TLS probe. The tool's job is PQ readiness, not an ssllabs clone.
- The repo probe is regex, not AST: it can't tell a comment from code. A `.pqinvignore` in the scanned root (one glob per line) excludes paths — pqinv's own excludes its rule and pattern files, which name every algorithm they detect. Doc/markup files are excluded; config formats are scanned on purpose.
- `.gitignore` is not parsed; well-known junk directories are skipped instead, and `.pqinvignore` covers the rest.
- The SAML probe reads *metadata* — what an entity declares — not live assertions. An IdP that declares rsa-sha256 but signs with rsa-sha1 is a live-traffic question (PCAP analysis is on the roadmap).
- Finite-field DHE key exchange cannot be probed: Go's TLS client does not implement it.

## Roadmap

SARIF output so repo findings land as pull-request annotations, a container image for `serve`, an SSH probe (credit: pqcscan does this), passive PCAP analysis (credit: pqcdump), AST-based Go analysis, finer CBOM asset typing — and v2: a Kubernetes operator that discovers targets from Ingress/TLS Secrets and feeds them to the `serve` loop ([sketch](docs/architecture.md#v2-sketch-the-kubernetes-operator)).

## References

FIPS 203 (ML-KEM) · FIPS 204 (ML-DSA) · FIPS 205 (SLH-DSA) · NIST IR 8547 (migration timeline) · RFC 8996 (TLS 1.0/1.1 deprecation) · RFC 8446 (TLS 1.3) · CycloneDX 1.6 CBOM

## License

[MIT](LICENSE)
