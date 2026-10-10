# Changelog

All notable changes to pqinv are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versions follow
[Semantic Versioning](https://semver.org/); before 1.0 a breaking change bumps
the minor version. The release workflow uses the matching section of this
file as the GitHub release notes.

## [Unreleased]

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

[Unreleased]: https://github.com/angga-22/pqinv/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/angga-22/pqinv/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/angga-22/pqinv/releases/tag/v0.1.0
