# Changelog

All notable changes to pqinv are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versions follow
[Semantic Versioning](https://semver.org/); before 1.0 a breaking change bumps
the minor version. The release workflow uses the matching section of this
file as the GitHub release notes.

## [Unreleased]

## [0.4.0] - 2026-10-12

The continuous half: what the CI gate does for code, `serve` does for the
infrastructure that changes without a commit.

### Added
- `pqinv serve --config targets.yaml --interval 1h --listen :9465`: rescans
  on a schedule and serves `/metrics` (Prometheus text exposition, written
  by hand — no client library), `/report.json` (the public JSON schema, a
  valid `--baseline` input) and `/healthz`.
- Metrics: `pqinv_score` (absent while unreachable, never zero),
  `pqinv_findings` by urgency and `pqinv_findings_by_class` (every series
  always present), `pqinv_target_unreachable`, `pqinv_new_findings_total`
  and `pqinv_new_findings_last_scan` (each scan diffed against the previous
  one, or against `--baseline` for the first),
  `pqinv_certificate_expiry_timestamp_seconds`, plus scan/exporter health.
- New findings and unreachable targets are logged to stderr on every scan.
- Clean shutdown on SIGINT/SIGTERM: in-flight handshakes and scrapes finish,
  the listener closes.
- `internal/pipeline`: the sort → classify → correlate → score path, now one
  function shared by `scan` and `serve`.
- README: metrics table and two Alertmanager rules (regression,
  unreachable target).

### Changed
- `--timeout`, `--concurrency`, `--ca-file` and `--insecure` are shared
  between `scan` and `serve`. Minimum `--interval` is 10s.
- `.pqinvignore` now also lists the SAML algorithm-URI table and the x509
  signature-hash table, which name every algorithm they map; the self-scan
  is back to the three code-comment hits that regex cannot avoid.

## [0.3.0] - 2026-10-11

A gate you can turn on today, and the whole identity plane in one scan.

### Added
- `--baseline previous.json`: with `--fail-on`, only findings new since that
  JSON report trip the gate. Matching is a multiset difference on (target,
  source, location, usage, algorithm, class, urgency); an escalation counts
  as new, a repo finding that moved lines does not, unreachable targets still
  always fail, and the error names the new findings.
- `scan saml <metadata-url|file>`: SAML 2.0 metadata probe. Inventories every
  entity's signing and encryption certificates (IdP, SP, or federation
  aggregate) and every `SignatureMethod`, `DigestMethod`, `SigningMethod` and
  `EncryptionMethod` URI, mapped to the rules vocabulary — `rsa-sha1`,
  `rsa-1_5`, `tripledes-cbc` all classify as the problems they are.
- `scan oidc` now inventories the TLS endpoint(s) the issuer and JWKS are
  served from, in the same report: tokens are harvested on the wire. An
  `http://` issuer is reported as a High finding of its own.
- `scan oidc` reads every advertised algorithm list in the discovery document
  (ID token, userinfo, request object, token-endpoint auth and JARM signing
  and encryption lists), deduplicated per (usage, algorithm) with
  `advertised_in` naming each list.
- TLS probe: a dedicated RSA key-transport pass (`TLS_RSA_*` suites, TLS ≤1.2).
  Go's defaults dropped these suites in 1.22, so no default handshake could see
  them; cloudflare.com and github.com both still accept them. A TLS 1.2 +
  RSA-only server is now inventoried instead of reported unreachable.
- Every certificate (TLS chain, SAML KeyDescriptor) now also yields the hash
  it was signed with as a `Hash` asset, so a SHA-1 signature is a finding
  regardless of key size.
- Rules: plaintext issuer (`HTTP`), RSA encryption key without `alg`,
  ECDH-ES/DH key agreement for encryption, JOSE `dir` and `PBES2*`, JOSE
  content-encryption names (`A128*`, `A256*`), AES-192, XML composite
  signature names (`RSA-SHA1` → broken hash, `RSA-SHA256`/`RSA-PSS-*` →
  classical signature), `3DES`/`RC4` inside TLS suite names, and a
  `strong-hash` rule so SHA-256/384/512 digests read as Acceptable.
- `internal/probe/certs`: shared x509 → asset helper used by the TLS and
  SAML probes.
- `internal/baseline` package, `report.TargetReport.UnmarshalJSON`, and a
  `User-Agent` of `pqinv/<version>` on every HTTP fetch.

### Changed
- Scores: an OIDC target's score now includes its issuer's TLS. Calibration
  (October 2026): cloudflare.com C 50 (was 52 — RSA key transport is a new
  Low fallback finding), github.com D 31, accounts.google.com C 50.
- The README now says plainly that grade A is unreachable in 2026 and B is
  today's ceiling.
- `.pqinvignore` and `--ca-file`/`--insecure` apply to the SAML probe too.

### Fixed
- The `classical-rsa-dh-key-exchange` rule could never fire because no probe
  emitted RSA key exchange. It fires now.
- An encryption JWK without an `alg` field classified as Unknown; it is now
  RSA/Encryption (High) or `ECDH <curve>`/Encryption (High).
- Removed a dangling reference to a non-existent `architecture.html` from the
  architecture doc.

## [0.2.0] - 2026-10-10

### Added
- `--ca-file` adds a PEM bundle to the trust store the OIDC probe uses, and
  `--insecure` skips verification — identity infrastructure usually sits
  behind a private CA. The TLS probe is unaffected: it never verifies.
- `.pqinvignore` in a scanned repo excludes paths from the repo probe: one
  Go `path.Match` glob per line, no slash matches the base name at any depth,
  trailing slash means directories only. A malformed pattern is an error.
- Committed private keys are now a dedicated High finding. PEM, PKCS#8 (plain
  and encrypted) and OpenSSH key blocks get their own algorithm label
  (`RSA private key`, not `RSA`) and a `committed-private-key` rule with
  rotate-and-purge advice.
- Explicit `status` field (`ok` | `unreachable`) on every JSON result.
- GitHub Actions: `ci.yml` (gofmt, vet, race tests on the go.mod floor and
  stable Go, govulncheck, and a dogfood job that runs every output format and
  asserts the gate fails on an unreachable target) and `release.yml`
  (goreleaser on `v*` tags).
- Tests for the CI gate, port defaulting, config loading and the HTTP client
  builder in `cmd/pqinv`.

### Changed
- **JSON schema:** an unreachable target now carries `status: "unreachable"`
  and `error`, and no longer carries `score` or `grade`. Previously it
  serialized as `score: 0, grade: ""`, which a consumer could read as an F.
- Minimum Go to build is now 1.26 (was 1.24). The floor is set by the
  dependency set: pinning to 1.24 forces `golang.org/x/crypto` back to a
  version with 17 published advisories, and govulncheck now runs in CI to
  keep the set clean. X25519MLKEM768 itself has been in the standard library
  since 1.24.
- Dependencies updated: `golang.org/x/crypto` 0.57.0, `x/sys` 0.48.0,
  `x/sync` 0.23.0, `x/net` 0.59.0, `x/text` 0.42.0, `x/term` 0.46.0.
- pqinv's own tree ships a `.pqinvignore` for its rule and pattern files and
  test tables; a self-scan drops from 34 High findings to 2 (both code
  comments that mention MD5 — the documented regex limitation).

## [0.1.0] - 2026-09-13

Initial release.

### Added
- TLS probe: hybrid PQ key exchange detection (`X25519MLKEM768`), classical
  group enumeration by constrained handshake, protocol versions TLS 1.0–1.3,
  full certificate chain inventory.
- OIDC probe: discovery document plus JWKS, classifying both published keys
  and advertised signing algorithms, including `alg: none`.
- Repo probe: regex scan for crypto imports, JOSE algorithm literals and
  committed PEM keys with `file.go:42` locations.
- Data-driven classifier (`rules/rules.yaml`, embedded) with usage-aware
  urgency: key exchange is harvest-now-decrypt-later urgent, signatures are
  plan-now.
- Correlation pass: classical key-exchange groups offered alongside a hybrid
  PQ group are downgraded to fallbacks.
- Readiness score 0–100 with letter grade, deductions capped per usage.
- Output formats: pretty terminal, deterministic JSON, CycloneDX 1.6 CBOM.
- `scan all --config targets.yaml` with bounded concurrency, and the
  `--fail-on high|medium|low` CI gate; unreachable targets always fail it.

[Unreleased]: https://github.com/angga-22/pqinv/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/angga-22/pqinv/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/angga-22/pqinv/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/angga-22/pqinv/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/angga-22/pqinv/releases/tag/v0.1.0
