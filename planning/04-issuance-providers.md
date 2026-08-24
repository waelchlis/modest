# Issuance Providers

Both providers implement `ICertificateIssuer` (see [02-architecture.md](02-architecture.md)). This document covers their internals.

## `Modest.Issuance.InternalCa`

### Key/cert loading

- CA keypair + certificate loaded at startup from a PFX (PKCS#12) file, path + password given via config (password itself read from a **separate file path**, not inline in `appsettings.json`/env var, to avoid it landing in process-list dumps or config-management logs — see [05-security.md](05-security.md)).
- Loaded once into an `X509Certificate2` held for the process lifetime; the private key handle is wrapped so it's never exposed outside this project (`ICertificateIssuer` callers never see the CA private key, only the resulting signed certs).
- On load failure (missing file, wrong password, key usage doesn't include cert signing), the process fails startup fast (fail-closed) rather than starting in a degraded state — an EST server that can't sign shouldn't pretend to be healthy.

### Signing (`IssueAsync`)

1. Parse the incoming `Pkcs10Der` bytes into a `CertificateRequest`-compatible structure. .NET's `CertificateRequest` class is built for *creating* CSRs/certs, not parsing an arbitrary incoming CSR into a signable request — so parsing uses `System.Formats.Asn1`/`CertificateRequest.LoadSigningRequest` (available since .NET 7+, confirmed present in .NET 10 — see [Microsoft's `CertificateRequest` docs](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.certificaterequest?view=net-10.0)), which parses a DER PKCS#10 blob directly into a `CertificateRequest` plus verifies the embedded signature as part of loading (`CertificateRequestLoadOptions`). This gives protocol-layer proof-of-possession verification (see [03-api-design.md](03-api-design.md)) "for free" from the BCL rather than hand-rolled ASN.1 signature checking.
2. Apply issuance policy to the parsed request: enforce configured minimum key sizes/allowed algorithms (RSA ≥ 2048, or configured EC curves), validate/rewrite the subject per configured policy (v1: pass through subject and SANs from the CSR verbatim if they pass allow-list checks; reject otherwise — no server-side subject *transformation* logic in v1, that's a policy-engine feature for later, see [08-roadmap.md](08-roadmap.md)).
3. Build the leaf certificate: `CertificateRequest.Create(issuerName, generator, notBefore, notAfter, serialNumber)` where `generator` is an `X509SignatureGenerator` built from the CA's private key (`X509SignatureGenerator.CreateForRSA`/`CreateForECDsa`). Validity period, serial number generation (random 20-byte per RFC 5280 recommendation, not sequential — avoids leaking issuance volume/order), and default extensions (Basic Constraints CA:false, Key Usage, EKU `clientAuth`/`serverAuth` per config, Subject Key Identifier, Authority Key Identifier) are all config-driven with sane defaults.
4. Return `IssuanceResult.Issued(leafCert, chain: [CA cert, ...configured intermediates])`.

### `GetCaChainAsync`

Returns the configured chain: the CA cert itself plus any configured intermediate/root certs the operator wants distributed via `/cacerts` (v1: static list loaded at startup alongside the CA keypair).

### Failure modes → `IssuanceResult`

- CSR fails policy (bad key size/algorithm/subject) → `Rejected(..., InvalidCsr)`.
- Everything else that can go wrong here (bad CA key, I/O) is a startup-time failure, not a per-request one — so `IssueAsync` for this provider essentially can't return `UpstreamUnavailable`/`PolicyDenied` in v1 (no external policy engine yet); `PolicyDenied` is reserved for a future authorization-policy hook.

## `Modest.Issuance.HttpDelegate`

### Contract with the external issuance API

Request (`POST {BaseAddress}{IssuePath}`):
```json
{ "CSR": "<base64 of the raw DER PKCS#10 bytes>" }
```

This is **the exact same base64 string EST clients send** in the `/simpleenroll` body is *not* reused verbatim (that body may contain whitespace/line-wraps and uses `Content-Transfer-Encoding: base64` framing) — Modest re-encodes the already-decoded raw DER bytes into a clean, unwrapped base64 string for this outgoing request. This is called out explicitly because it's a place a naive implementation could pass through the wrong bytes; see [09-open-questions.md](09-open-questions.md) for confirming this interpretation of "base64 CSR string" against the user's actual upstream API if it turns out to expect PEM-wrapped-then-base64'd or something else.

Expected response (`200 OK`, `application/json`):
```json
{ "certificate": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n",
  "issuer": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n" }
```

- `certificate`: single PEM-encoded leaf certificate.
- `issuer`: one or more concatenated PEM certificates forming the chain (intermediate(s) [+ root]), parsed by splitting on `-----BEGIN CERTIFICATE-----`/`-----END CERTIFICATE-----` boundaries (PEM allows concatenation this way; .NET's `X509Certificate2Collection.ImportFromPem` handles a multi-cert PEM blob natively as of .NET 7+, confirmed present in .NET 10).

### Behavior

1. Take `Pkcs10Der` from the `IssuanceRequest` (already protocol-layer verified for well-formedness + self-signature, per [03-api-design.md](03-api-design.md) — the delegated issuer does not re-verify signature, but does still enforce its own configured policy checks that are cheap and don't require parsing, e.g. a max CSR byte size, before making the outbound call).
2. POST the JSON body to the configured endpoint via a named `HttpClient` (registered through `IHttpClientFactory` for connection pooling + `Polly`-based retry/circuit-breaker — see below).
3. On `200` with a well-formed JSON body: parse `certificate` and `issuer` as PEM, build `X509Certificate2` objects, return `Issued(leaf, chain)`.
4. On `200` with malformed/unparseable JSON or invalid PEM: return `Rejected("upstream returned an unparseable response", InvalidCsr)` — treated as a protocol contract violation by the upstream, logged loudly (this indicates a config/compat problem, not a normal rejection) but still surfaced to the EST client as a 400-class problem since retrying the same CSR won't help without an operator fixing the upstream.
5. On non-2xx from upstream (e.g. `4xx` = upstream rejected the CSR on its own policy grounds, `5xx`/timeout/connection failure = upstream is down): `4xx` → `Rejected(reason, PolicyDenied)`; `5xx`/network failure/timeout → `Rejected(reason, UpstreamUnavailable)` (maps to `502` at the API layer per [03-api-design.md](03-api-design.md)).
6. Configurable request timeout (default 30s) and a small bounded retry (via `Microsoft.Extensions.Http.Resilience`, the .NET-idiomatic successor to manual Polly wiring, ships in .NET 8+ and is current in .NET 10) for transient failures only (connection errors, `5xx`, timeout) — **not** for `4xx` (those are the upstream deliberately rejecting the CSR; retrying won't change that and could duplicate issuance side effects if the upstream isn't idempotent).
7. Outbound authentication to the upstream API: configurable static header (API key) or bearer token in v1 (see config sketch in [02-architecture.md](02-architecture.md)); mTLS-to-upstream is a documented extension point (`HttpClientHandler`/`SocketsHttpHandler.ClientCertificates`) but not required for v1 since the exact upstream auth scheme is one of the open questions for the user (see [09-open-questions.md](09-open-questions.md)).

### `GetCaChainAsync`

Two options, config-selectable:
- **Static config** — operator supplies the expected CA chain PEM(s) directly in Modest's config (works if the upstream's issuing CA is known/stable ahead of time and doesn't rotate without the operator updating Modest's config too).
- **Derived from issuance responses** — cache the `issuer` chain most recently returned by the upstream on a successful `IssueAsync` call, and serve that from `/cacerts` (self-updating, but means `/cacerts` is empty/stale until at least one enrollment has happened — undesirable for bootstrap). 

v1 default is **static config**, since `/cacerts` needs to work for a brand-new client before any enrollment has ever happened (bootstrap use case), and that's only reliable if the chain is known upfront. This is flagged for user confirmation in [09-open-questions.md](09-open-questions.md) since it depends on how the user's upstream issuance API is actually operated.

### Testability

This provider is the one most worth investing in contract/integration tests for, since it's an HTTP boundary to an external system Modest doesn't control. `WireMock.Net` stands in for the upstream API in tests, covering: happy path, malformed JSON, invalid PEM, non-2xx statuses, timeout, connection refused, and slow responses (to exercise the timeout config). See [06-testing-strategy.md](06-testing-strategy.md).
