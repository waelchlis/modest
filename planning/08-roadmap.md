# Roadmap

Phased so that each milestone leaves the project in a genuinely working, tested state — no phase depends on a later phase's code existing to be testable.

## Phase 0 — Scaffolding

- Solution/project structure per [07-project-structure.md](07-project-structure.md), `global.json`, `Directory.Build.props`/`Directory.Packages.props`, CI pipeline skeleton (build + test on push).
- `Modest.Core` contracts (`ICertificateIssuer` and friends) — code, no behavior yet.
- `Modest.TestSupport` fixture: a script/helper that generates a throwaway test CA + server cert + client cert set, used by every later test project.
- **Exit criteria**: solution builds, empty test suite runs green in CI.

## Phase 1 — Codec

- `Modest.Codec`: PKCS#10 parse + verify, certs-only PKCS#7 build, base64 helpers, empty `CsrAttrs` DER encoding.
- Full unit test suite per [06-testing-strategy.md](06-testing-strategy.md) §1, including the OpenSSL interop cross-check (§7).
- **Exit criteria**: codec round-trips against real `openssl`-generated CSRs and its own output is `openssl`-parseable. This is the highest-risk correctness surface, worth nailing before building the server around it.

## Phase 2 — Internal CA issuer

- `Modest.Tooling`: minimal CLI to generate a self-signed dev/test CA keypair (PFX out).
- `Modest.Issuance.InternalCa`: load CA key, sign CSRs, policy checks (key size/algorithm allow-list), `GetCaChainAsync`.
- Unit tests per [06-testing-strategy.md](06-testing-strategy.md) §2.
- **Exit criteria**: given a CSR and a test CA, produces a valid, policy-correct leaf certificate — provable without any HTTP layer yet.

## Phase 3 — Server: `/cacerts`, `/csrattrs`, auth middleware

- `Modest.Server` skeleton, Kestrel TLS config, `EstAuthenticationMiddleware` (client cert + Basic), the two unauthenticated GET endpoints wired to the internal-CA issuer from Phase 2.
- Integration tests: real TLS handshake, `/cacerts` end-to-end, `/csrattrs` → `204`, auth middleware branch coverage.
- **Exit criteria**: a real `openssl s_client`/`curl --cacert` against a running instance can fetch and validate the CA chain over TLS.

## Phase 4 — Server: `/simpleenroll`, `/simplereenroll`

- Enrollment endpoint handlers, status-code mapping table from [03-api-design.md](03-api-design.md), full request pipeline wired to internal CA.
- Integration tests: happy path (cert auth and Basic auth), all documented error branches, oversized body, wrong content type.
- RFC-compliance tagged tests per [06-testing-strategy.md](06-testing-strategy.md) §6 for everything covered so far.
- **Exit criteria**: a real EST client (e.g. `openssl` scripted through the raw HTTP calls, or a known EST client tool if available) can enroll end-to-end against Modest running in internal-CA mode.

## Phase 5 — HTTP delegated issuer

- `Modest.Issuance.HttpDelegate`: outbound contract, resilience policy, `GetCaChainAsync` (static-config mode).
- Full WireMock-backed unit test suite per [06-testing-strategy.md](06-testing-strategy.md) §3.
- Wire into `Modest.Server` as the second selectable `Issuance:Mode`; re-run the full Phase 3/4 integration + compliance test suites against this mode too (shared test base, per [06-testing-strategy.md](06-testing-strategy.md) §5).
- **Exit criteria**: identical external EST behavior under both issuer modes, proven by the shared test suite passing for both; delegated mode independently verified against a WireMock stand-in of the user's actual upstream contract shape.

## Phase 6 — Hardening & ops

- `/healthz`/`/readyz`, structured audit logging finalized, Dockerfile + container smoke test.
- Security pass against the threat model in [05-security.md](05-security.md): confirm no secret material appears in logs, confirm fail-closed startup behavior, confirm file-permission warnings work.
- Documentation: README with quickstart for both modes, config reference.
- **Exit criteria**: project is deployable and operable, not just protocol-correct.

## Post-v1 backlog (explicitly deferred, not scheduled)

- `/fullcmc` support.
- `/serverkeygen` support.
- Multi-CA `[label]` routing.
- HTTP Digest authentication.
- `tls-unique` channel-binding enforcement.
- Genuine asynchronous issuance (an issuer that really returns `Pending` and correlates retries — the wire protocol support ships in v1, the behavior doesn't).
- CRL/OCSP revocation checking for client cert auth.
- Rate limiting / brute-force protection on Basic auth.
- HSM/cloud KMS-backed internal CA key (Azure Key Vault, AWS KMS, PKCS#11).
- Configurable subject/SAN transformation policy engine (beyond simple allow-listing).
- Fuzz testing of the ASN.1 parsing surface.
- Load/performance benchmarking.

This backlog exists so scope cuts made for v1 are visible decisions with a place to land, not silently forgotten requirements.
