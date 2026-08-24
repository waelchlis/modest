# Epic 4 — Server Core: TLS, Dual Listeners, Auth Middleware, Bootstrap Endpoints

**Depends on**: 1, 2, and at least one of 3/6 (an issuer to wire against — internal CA is assumed available first per the epic ordering, but this epic's own code doesn't care which). **Blocks**: 5 (enrollment endpoints build on the auth middleware and routing this epic sets up).

## Objective

Stand up `Modest.Server` itself: Kestrel configuration with **two listeners** (per [../09-open-questions.md](../09-open-questions.md) #9 — this changes the single-listener assumption in the original [../07-project-structure.md](../07-project-structure.md)), the custom EST auth middleware, and the two unauthenticated bootstrap endpoints (`/cacerts`, `/csrattrs`).

## Deliverables

In `src/Modest.Server`:

- `Program.cs` — two Kestrel endpoints configured explicitly:
  - **EST listener**: HTTPS, TLS 1.2/1.3 only, `ClientCertificateMode.AllowCertificate`, serves everything under `/.well-known/est`. Port configurable (`Kestrel:Est:Port` or similar), default e.g. `8443`.
  - **Ops listener**: plain HTTP, no TLS, no client cert negotiation, serves only `/healthz` and `/readyz`. Port configurable, default e.g. `8080`. Bound so that (in the Kubernetes deployment target confirmed in [../09-open-questions.md](../09-open-questions.md) #10) it's the target of the Helm chart's liveness/readiness probes without the kubelet needing to do a TLS/mTLS handshake — this is the whole reason for the split, worth a code comment referencing this decision since a future reader might otherwise "simplify" it back to one listener.
  - Route registration split accordingly: EST routes only ever registered against the EST listener's endpoint (`Map...` calls scoped correctly — ASP.NET Core supports per-endpoint routing via `WebApplication` `MapWhen`/multiple `IHost` port bindings; confirm the exact API shape during implementation, since ASP.NET Core's typical model is "one app, N listening addresses, same route table" — if strict route isolation per-listener turns out to need `IHostedService`-per-listener or a reverse-proxy-style split instead, treat that as an implementation detail to resolve here, not a reason to abandon the two-listener requirement).
- `EstAuthenticationMiddleware` per [../05-security.md](../05-security.md): client-cert-then-Basic-then-none flow, populates `HttpContext.Items["EstClientIdentity"]` with a `ClientIdentity` (from `Modest.Core`).
- `IBasicCredentialValidator` + a v1 `StaticConfigBasicCredentialValidator` implementation (username/PBKDF2-hash pairs from config), per [../05-security.md](../05-security.md).
- `RequireEstClientAuth()` minimal-API endpoint filter/extension, short-circuiting to `401` + `WWW-Authenticate: Basic realm="modest"` when `ClientIdentity.Method == None`.
- `CaCertsEndpoint`, `CsrAttrsEndpoint` handlers wired to `ICertificateIssuer.GetCaChainAsync` and `Modest.Codec` per [../03-api-design.md](../03-api-design.md).
- `HealthEndpoints` — `/healthz` (always 200 once the process is up) and `/readyz` (200 once the configured issuer reports ready — for internal CA, "CA key loaded"; for HTTP delegate, this epic only needs the internal-CA case to be functional, but the interface hook (`ICertificateIssuer` doesn't currently expose a readiness check — **add one**: `Task<bool> IsReadyAsync(CancellationToken)` to the interface, a small addition to the `Modest.Core` contract from epic 1/2 that should be made here since this is where the need becomes concrete) is used generically.
- Startup wiring: config-driven issuer selection (`Issuance:Mode`) per [../02-architecture.md](../02-architecture.md), fail-closed on issuer construction failure (catching `CaKeyLoadException` from epic 3 specifically, logging a clear message, `Environment.Exit(1)`).

## Tasks

1. Add `ICertificateIssuer.IsReadyAsync` to `Modest.Core` (small interface addition — update both epic 3's and (once built) epic 6's implementations; trivial for internal CA — "is the CA cert loaded," always true once construction succeeded — slightly more involved for HTTP delegate, deferred to epic 6 but the interface shape is decided here).
2. Kestrel dual-listener configuration; integration test confirming the ops listener answers plain HTTP with no TLS and the EST listener requires TLS.
3. `EstAuthenticationMiddleware` unit tests per [../06-testing-strategy.md](../06-testing-strategy.md) §4: every branch (valid cert, invalid cert falls through to Basic, valid Basic, both cert+Basic present — pin precedence with a test, missing/malformed `Authorization` header, wrong scheme).
4. `StaticConfigBasicCredentialValidator`: PBKDF2 hash verification, config schema for username/hash pairs, unit tests including a timing-safe comparison check (use `CryptographicOperations.FixedTimeEquals`, not `==`, on the derived hash — call this out explicitly since it's an easy security regression to introduce later without noticing).
5. `RequireEstClientAuth()` filter, tested against a minimal fake endpoint.
6. `/cacerts` handler + integration test: real TLS client (no client cert required) fetches and gets a codec-valid certs-only response containing the internal CA's chain.
7. `/csrattrs` handler + integration test: `204`, empty body.
8. `/healthz`/`/readyz` + integration tests on the ops listener specifically (confirming it's reachable without TLS).
9. Startup failure-path integration test: deliberately broken CA config → process exits non-zero with the expected log line (test this by invoking `Program`'s composition logic in a way that's testable — e.g. factor startup into a `BuildApp(IConfiguration)` function separate from `Main`, specifically so this path is unit-testable without spawning a real subprocess).

## Definition of Done

- Both listeners work as specified and are covered by integration tests distinguishing their behavior (TLS required on one, not the other; EST routes reachable only on the EST listener).
- `EstAuthenticationMiddleware` has full branch coverage per task 3.
- `/cacerts` and `/csrattrs` integration tests pass against a running internal-CA-mode instance.
- A real `curl`/`openssl s_client` against a locally run instance can retrieve `/cacerts` and validate the returned chain — a manual smoke check worth doing once at the end of this epic even though it's not automated, to catch anything the in-process `WebApplicationFactory` tests might not (e.g. actual socket-level TLS config issues).
