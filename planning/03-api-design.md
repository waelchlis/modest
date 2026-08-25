# API Design (ASP.NET Core surface)

## Hosting model

ASP.NET Core 10 **Minimal APIs** (not MVC controllers) — the EST surface is four small endpoints; minimal APIs keep routing/handlers colocated and are easy to unit-test via `WebApplicationFactory` or direct delegate invocation. `AddValidation()` (new in .NET 10) is used for the small amount of request validation that isn't content-type/codec-level (e.g. header presence).

## Routing

```csharp
var est = app.MapGroup("/.well-known/est");

est.MapGet("/cacerts", CaCertsEndpoint.Handle);
est.MapGet("/csrattrs", CsrAttrsEndpoint.Handle);
est.MapPost("/simpleenroll", EnrollEndpoint.HandleEnroll)
   .RequireEstClientAuth();
est.MapPost("/simplereenroll", EnrollEndpoint.HandleReenroll)
   .RequireEstClientAuth();
```

`RequireEstClientAuth()` is a small extension method (not ASP.NET Core's cookie/JWT `[Authorize]`, which doesn't fit this model) that reads the `ClientIdentity` the auth middleware attached to `HttpContext.Items`, and short-circuits to `401` if `Method == ClientAuthMethod.None`. Kept custom rather than shoehorned into `Microsoft.AspNetCore.Authentication` because EST's auth model (cert OR Basic, evaluated together, no challenge redirect flows) doesn't map cleanly onto the standard scheme-based authentication handler pattern — see [05-security.md](05-security.md) for the reasoning.

## Content negotiation

EST does not use `Accept`-header negotiation — each operation has exactly one fixed response content type. Handlers set `Content-Type` explicitly rather than relying on ASP.NET Core's formatter selection. Request `Content-Type` is validated strictly:

- `/simpleenroll`, `/simplereenroll`: must be `application/pkcs10`. Missing/incorrect → `415 Unsupported Media Type`.
- `Content-Transfer-Encoding: base64` is accepted if present but not required to be present for the request to be treated as base64 text (some clients omit it); the body is always parsed as base64 text per RFC 7030 §3.2.1's mandate that binary content is base64-encoded end-to-end over EST regardless of header presence.

## Endpoint contracts

### `GET /cacerts`

- No auth.
- Calls `ICertificateIssuer.GetCaChainAsync`.
- Builds a certs-only CMS `SignedData` from the returned chain.
- `200 OK`, `Content-Type: application/pkcs7-mime; smime-type=certs-only`, `Content-Transfer-Encoding: base64`, body = base64 text.
- `500` only on unexpected issuer failure (e.g. delegated issuer's upstream is unreachable when asked for its chain) — logged with detail, response body is a generic plain-text message (no upstream error detail leaked to an unauthenticated caller).

### `GET /csrattrs`

- No auth.
- v1 always returns `204 No Content` (empty `CsrAttrs`, see [01-rfc7030-reference.md](01-rfc7030-reference.md#3-content-types-and-wire-encoding-3221-334)). No issuer call — this is static per the v1 scope decision.

### `POST /simpleenroll`, `POST /simplereenroll`

Request:
- Headers: `Content-Type: application/pkcs10`, optional `Authorization: Basic ...`.
- Body: base64 text of a DER `CertificationRequest`.

Response on success:
- `200 OK`, `Content-Type: application/pkcs7-mime; smime-type=certs-only`, body = base64 CMS `SignedData` containing the issued leaf cert + any intermediate chain certs the issuer returned (root is included only if the issuer explicitly returns it as part of the chain — see [04-issuance-providers.md](04-issuance-providers.md) for the internal-CA and delegated-issuer specifics).

Response on pending:
- `202 Accepted`, `Retry-After: <seconds>`, empty body.

Response on error — status mapping from `IssuanceRejectionKind` and from protocol-layer failures:

| Condition | Status | Notes |
|---|---|---|
| No/invalid auth | `401` | `WWW-Authenticate: Basic realm="modest"` header included |
| Wrong `Content-Type` | `415` | |
| Body not valid base64 | `400` | |
| Base64 decodes but isn't a well-formed PKCS#10 `CertificationRequest` | `400` | |
| CSR signature does not verify against its own embedded public key (proof-of-possession check) | `400` | this is a protocol-layer check, always performed regardless of issuer, see below |
| `IssuanceRejectionKind.InvalidCsr` (issuer-level, e.g. disallowed key type/size/subject per policy) | `400` | |
| `IssuanceRejectionKind.Unauthorized` (issuer says this identity isn't allowed to enroll) | `403` | not `401` — the caller *is* authenticated, just not authorized for this action |
| `IssuanceRejectionKind.PolicyDenied` | `403` | |
| `IssuanceRejectionKind.UpstreamUnavailable` | `502` | delegated issuer's upstream HTTP API failed/timed out |
| Unhandled exception anywhere in the pipeline | `500` | logged with full detail server-side; generic body to the client |

**CSR self-signature verification is a protocol-layer responsibility**, performed by `Modest.Codec` before the request ever reaches `ICertificateIssuer`. This isn't optional per-issuer behavior — RFC 7030's proof-of-possession model relies on the CSR's own signature proving the requester holds the private key, and both v1 issuers (and any future one) should get this check for free rather than each having to remember to do it.

## DTOs used only by `Modest.Issuance.HttpDelegate`

These are internal to that project (not part of the public EST wire contract) — documented fully in [04-issuance-providers.md](04-issuance-providers.md).

```json
// Request body Modest sends to the external issuance API
{ "CSR": "<PEM-encoded CSR, i.e. the literal -----BEGIN CERTIFICATE REQUEST----- text>" }
```
```json
// Response body Modest expects back
{ "certificate": "-----BEGIN CERTIFICATE-----...", "issuer": "-----BEGIN CERTIFICATE-----...\n-----BEGIN CERTIFICATE-----..." }
```

## Error body format

Plain text (`Content-Type: text/plain; charset=utf-8`), one line, no stack traces, no internal exception messages for 5xx (mapped to a generic "internal error, see server logs" + a correlation/trace id the operator can grep for). 4xx bodies can be more specific since they describe a client-fixable problem (e.g. `"CSR public key type RSA-1024 is below the configured minimum of RSA-2048"`).

## Health/ops endpoints (not part of EST, but needed operationally)

- `GET /healthz` — liveness (process is up), no auth, no dependency checks.
- `GET /readyz` — readiness; for `HttpDelegate` mode, optionally pings the upstream issuance API's health if configured; for `InternalCa` mode, confirms the CA key is loaded and usable.
- These live outside `/.well-known/est` and are excluded from the RFC-compliance test suite (they're operational, not protocol, surface) — see [06-testing-strategy.md](06-testing-strategy.md).
