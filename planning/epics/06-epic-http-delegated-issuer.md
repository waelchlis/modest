# Epic 6 — HTTP Delegated Issuer

**Depends on**: 1, 2 (scaffolding, codec). **Blocks**: full cross-mode validation of epics 4/5 (not a hard blocker, but the point of "modular issuance" isn't proven until this exists and passes the same test suite as internal-CA mode).

## Objective

Implement `Modest.Issuance.HttpDelegate`, the `ICertificateIssuer` that forwards CSRs to an external HTTP API, per [../04-issuance-providers.md](../04-issuance-providers.md) and the confirmed answers in [../09-open-questions.md](../09-open-questions.md).

## Confirmed contract (final, per open-questions answers — supersedes the "assumed" language in [../04-issuance-providers.md](../04-issuance-providers.md))

- **Outbound auth**: HTTP Basic authentication (username/password) against the upstream, **not** a bearer token or API-key header as originally hedged. Credentials configured the same way as other secrets in this project — file-path-indirected, per [../05-security.md](../05-security.md).
- **CSR encoding**: the **PEM-encoded** PKCS#10 request itself, sent directly — not base64 of it, and not the raw DER. ✅ **Resolved 2026-08-25** (was flagged here as contradictory, then briefly landed on base64-of-PEM before real-upstream testing corrected it — see [../09-open-questions.md](../09-open-questions.md) #1 for the full history). `HttpDelegateIssuer.IssueAsync` builds the field as `PemEncoding.WriteString("CERTIFICATE REQUEST", der)` with no further encoding, sent as a buffered request body with an explicit `Content-Length` (real-upstream testing also surfaced that the previous chunked-transfer-encoded request silently bound to `null` on a classic `System.Web.Http` service).
- **`issuer` response field**: one or more concatenated PEM certificates, **guaranteed order** (intermediate(s) then root, no leaf).
- **Synchronicity**: upstream always responds synchronously — no `Pending`/async handling needs to be implemented for this issuer.
- **`/cacerts` chain source**: static configuration (operator-supplied PEM chain in config), not derived from issuance responses.

## Deliverables

In `src/Modest.Issuance.HttpDelegate`, namespace `Modest.Issuance.HttpDelegate`:

- `HttpDelegateOptions` — bound from config (`Issuance:HttpDelegate:*`): `BaseAddress`, `IssuePath`, `TimeoutSeconds` (default 30), `BasicAuthUsername`, `BasicAuthPasswordFile`, `StaticCaChainPath` (PEM file with the configured `/cacerts` chain), `MaxCsrSizeBytes` (cheap pre-flight guard before the outbound call, per [../04-issuance-providers.md](../04-issuance-providers.md)).
- `HttpDelegateIssuer : ICertificateIssuer` — `IssueAsync`: builds `{"CSR": "<base64>"}`, POSTs via a named `HttpClient` (registered through `IHttpClientFactory`, `AuthenticationHeaderValue("Basic", ...)` attached via a `DelegatingHandler` so the credential is never string-concatenated ad hoc at each call site and never logged — see the security task below) to `BaseAddress + IssuePath`; parses the JSON response; on success builds `X509Certificate2` for `certificate` and an ordered `X509Certificate2Collection` for `issuer` (via `ImportFromPem`, which supports multi-cert PEM blobs); maps outcomes per [../04-issuance-providers.md](../04-issuance-providers.md)'s behavior list (2xx+parseable→`Issued`, 2xx+unparseable→`Rejected(InvalidCsr)`, 4xx→`Rejected(PolicyDenied)`, 5xx/timeout/connection failure→`Rejected(UpstreamUnavailable)`).
- `HttpDelegateIssuer.GetCaChainAsync` — reads/parses `StaticCaChainPath` once at startup (cached in memory, not re-read per request).
- `HttpDelegateIssuer.IsReadyAsync` — (interface member added in epic 4) — for this provider, a meaningful readiness check is harder than internal CA's "is the key loaded": options are (a) always `true` once constructed (config/chain loaded successfully), or (b) an actual upstream health probe. **This plan adopts (a)** for v1 — probing the upstream on every `/readyz` call risks making Modest's own readiness flap on transient upstream blips, which is exactly the kind of thing that causes unnecessary pod restarts in the Kubernetes deployment target confirmed in [../09-open-questions.md](../09-open-questions.md) #10. A configurable upstream health-probe mode is a reasonable post-v1 addition, not built here.
- Resilience: `Microsoft.Extensions.Http.Resilience` pipeline — retry (bounded, e.g. 3 attempts, exponential backoff with jitter) on transient failures only (connection errors, `5xx`, timeout), explicitly **not** retrying `4xx`, per [../04-issuance-providers.md](../04-issuance-providers.md).
- DI registration extension: `IServiceCollection.AddHttpDelegateIssuer(IConfiguration)`.

## Tasks

1. `HttpDelegateOptions` + config binding + validation.
2. Outbound request building: unit test (via WireMock.Net) asserting the exact JSON body shape `{"CSR": "..."}` and that the `Authorization` header is `Basic <base64(username:password)>` with the configured credentials — byte-for-byte assertions, not just "a request was made."
3. Response parsing happy path: valid `{"certificate": ..., "issuer": ...}` → `Issued` with correctly ordered chain (root/intermediate order preserved from the response, no leaf duplication).
4. Response parsing failure modes: malformed JSON, missing fields, invalid PEM in either field → `Rejected(InvalidCsr)`.
5. Upstream status mapping: `4xx` → `Rejected(PolicyDenied)` (and specifically **not retried** — assert WireMock saw exactly 1 request); `5xx`/timeout/connection-refused → `Rejected(UpstreamUnavailable)` **with retry** (assert WireMock saw the configured number of attempts).
6. `GetCaChainAsync` from static config: unit test loading a multi-cert PEM file, correct count/order.
7. Credential handling security test: assert the configured Basic auth password never appears in any log output produced during a request (string-search the captured log sink in the test).
8. `AddHttpDelegateIssuer` DI extension + smoke test.
9. Once epic 4/5 exist: wire this issuer into `Modest.Server`'s config-driven selection and re-run the full enrollment integration suite from epic 5 against `HttpDelegate` mode backed by WireMock, per [../06-testing-strategy.md](../06-testing-strategy.md) §5 — this is the test that actually proves the "modular issuance" architectural goal, not just this epic's own unit tests.
10. Confirm the CSR-encoding wrinkle (flagged above) against the real upstream once available; adjust the single encoding call site if needed — no broader impact expected given the codec/issuer boundary this project maintains.

## Definition of Done

- All tasks 1–8 pass as isolated unit tests (no dependency on epics 4/5 being complete — this issuer is fully testable standalone against WireMock, which is the point of the interface boundary from [../02-architecture.md](../02-architecture.md)).
- Task 9's cross-mode integration suite passes once epic 5 exists.
- Task 10 tracked to closure (either confirmed correct as-implemented, or corrected) before this epic is considered fully done — but does not block the rest of the project from proceeding in parallel.
