# Architecture

## Layering

```
┌─────────────────────────────────────────────────────────────────┐
│  Modest.Server  (ASP.NET Core host)                              │
│                                                                   │
│   Kestrel (TLS, mTLS negotiation)                                │
│     → Auth middleware (client cert / HTTP Basic → ClientIdentity)│
│     → EST endpoint handlers (/cacerts, /simpleenroll, ...)       │
│     → Codec layer (PKCS#10 parse, PKCS#7 build, base64 wrap)     │
│     → maps to ─────────────────────────────────────┐             │
└──────────────────────────────────────────────────────┼───────────┘
                                                         │
                                            ICertificateIssuer (Modest.Core)
                                                         │
                     ┌───────────────────────────────────┴───────────────────────┐
                     │                                                           │
        Modest.Issuance.InternalCa                          Modest.Issuance.HttpDelegate
        (loads CA keypair, signs with                        (POSTs CSR to external HTTP
         CertificateRequest.Create)                           API, parses PEM response)
```

`Modest.Core` defines the contracts and has no dependency on ASP.NET Core or on either issuer implementation. `Modest.Server` depends on `Modest.Core` and, via DI registration chosen at startup (config-driven), on **exactly one** issuer implementation package. The issuer implementations depend only on `Modest.Core` — they know nothing about HTTP/EST wire formats.

This split is the whole point of "modular": swapping internal-CA for delegated-HTTP (or, later, a third implementation) is a configuration change plus a package reference, not a code change in the server or codec layer.

## The `ICertificateIssuer` contract

```csharp
namespace Modest.Core.Issuance;

public interface ICertificateIssuer
{
    /// <summary>
    /// Returns the current CA certificate chain this issuer signs with
    /// (or, for a delegated issuer, the chain it reports as authoritative).
    /// Used to serve /cacerts and to build the certs-only PKCS#7 response.
    /// </summary>
    Task<CaChainResult> GetCaChainAsync(CancellationToken cancellationToken);

    /// <summary>
    /// Issues (or re-issues) a certificate for the given CSR.
    /// </summary>
    Task<IssuanceResult> IssueAsync(IssuanceRequest request, CancellationToken cancellationToken);
}
```

```csharp
public sealed record IssuanceRequest(
    ReadOnlyMemory<byte> Pkcs10Der,     // the raw, already-decoded CSR bytes
    EstOperation Operation,             // Enroll | Reenroll
    ClientIdentity Identity,            // parsed auth context — see below
    string CorrelationKey);             // stable hash of (Pkcs10Der + Identity) for 202/retry correlation

public enum EstOperation { Enroll, Reenroll }

public sealed record ClientIdentity(
    ClientAuthMethod Method,            // ClientCertificate | HttpBasic | None
    string? Subject,                    // cert subject DN or Basic auth username
    X509Certificate2? ClientCertificate);

public enum ClientAuthMethod { None, ClientCertificate, HttpBasic }
```

```csharp
public abstract record IssuanceResult
{
    public sealed record Issued(X509Certificate2 Certificate, IReadOnlyList<X509Certificate2> Chain) : IssuanceResult;
    public sealed record Pending(TimeSpan RetryAfter) : IssuanceResult;
    public sealed record Rejected(string Reason, IssuanceRejectionKind Kind) : IssuanceResult;
}

public enum IssuanceRejectionKind { PolicyDenied, InvalidCsr, UpstreamUnavailable, Unauthorized }
```

```csharp
public sealed record CaChainResult(IReadOnlyList<X509Certificate2> Chain);
```

Design notes:

- `IssuanceResult` is a closed discriminated union (C# records + `sealed`, exhaustively pattern-matched at the call site) rather than an exception-based flow, because "CSR rejected by policy" and "upstream CA temporarily down" are both *expected, everyday* outcomes for an EST server, not exceptional ones. Exceptions are reserved for genuine bugs/infra failures (DI misconfiguration, unhandled upstream exceptions bubble up and get turned into a 500 + logged, not silently swallowed).
- `Pkcs10Der` is passed as raw bytes, not a parsed `.NET` CSR object, into the issuer boundary. The internal CA issuer parses it as needed (it must, to sign it); the HTTP delegated issuer never needs to parse it at all — it just base64-encodes the same bytes into the outgoing JSON. This avoids forcing a parse step that one of the two implementations doesn't need, and avoids information loss/re-encoding drift (the delegated issuer forwards *exactly* the bytes the client sent, byte-for-byte).
- `CorrelationKey` exists purely to support future asynchronous issuers implementing the 202/Retry-After flow correctly (§7 of [01-rfc7030-reference.md](01-rfc7030-reference.md)); neither v1 issuer uses it to go async, but the EST endpoint handler always computes and passes it so an issuer *can* opt into async behavior later without an interface change.

## Request pipeline (concrete walk-through: `/simpleenroll`)

1. Kestrel terminates TLS, optionally negotiates a client certificate (`ClientCertificateMode.AllowCertificate`).
2. `EstAuthenticationMiddleware` inspects the connection: if a client cert was presented, validate it against the configured trust policy ([05-security.md](05-security.md)) and build `ClientIdentity(ClientCertificate, ...)`. Else, look for an `Authorization: Basic` header and validate against the configured identity provider, building `ClientIdentity(HttpBasic, ...)`. Else `ClientIdentity(None, ...)`.
3. The `/simpleenroll` minimal-API handler runs an `[Authorize]`-equivalent check requiring `Method != None`; unauthenticated requests get `401` with `WWW-Authenticate: Basic realm="modest"`.
4. Body is read, `Content-Type` validated as `application/pkcs10`, base64-decoded (tolerant of whitespace/line-wraps) into raw DER bytes. A cheap structural sanity check (ASN.1 SEQUENCE parse via `CertificateRequest`-adjacent APIs, see [04-issuance-providers.md](04-issuance-providers.md)) rejects garbage early as `400`.
5. Handler builds an `IssuanceRequest` and calls `ICertificateIssuer.IssueAsync`.
6. On `Issued`: build a certs-only CMS `SignedData` (leaf + any chain certs the issuer returned), base64-wrap, respond `200` with `application/pkcs7-mime; smime-type=certs-only`.
7. On `Pending`: respond `202` with `Retry-After: <seconds>` and an empty body.
8. On `Rejected`: map `IssuanceRejectionKind` → HTTP status (`PolicyDenied`→403, `InvalidCsr`→400, `Unauthorized`→401, `UpstreamUnavailable`→502) with a plain-text reason body.
9. Structured log emitted at each terminal branch (identity, operation, outcome, correlation key, timing) — see [05-security.md](05-security.md) for what must *not* be logged (raw private-key material, full Basic-auth passwords).

`/simplereenroll` is the same pipeline with `EstOperation.Reenroll`; `/cacerts` and `/csrattrs` are simpler GETs that skip steps 3–5 (no auth required, no issuance) and call `GetCaChainAsync` / return the static empty `CsrAttrs` respectively.

## Configuration-driven issuer selection

`Modest.Server`'s `Program.cs` reads an `Issuance:Mode` config value (`InternalCa` | `HttpDelegate`) and registers the corresponding `ICertificateIssuer` implementation plus its options, e.g.:

```json
{
  "Issuance": {
    "Mode": "HttpDelegate",
    "InternalCa": {
      "CertificatePath": "/etc/modest/ca.pfx",
      "CertificatePasswordFile": "/etc/modest/ca.pfx.pass",
      "SignatureAlgorithm": "Sha256"
    },
    "HttpDelegate": {
      "BaseAddress": "https://ca.internal.example.com/",
      "IssuePath": "/api/v1/issue",
      "TimeoutSeconds": 30,
      "AuthHeader": { "Name": "X-Api-Key", "ValueFile": "/etc/modest/ca-api-key" }
    }
  }
}
```

Only one issuer is active per running instance in v1 — no per-request routing between issuers (that would be a multi-CA/`[label]` feature, explicitly deferred, see [00-overview.md](00-overview.md)). This keeps DI registration a single `services.AddSingleton<ICertificateIssuer, X>()` call chosen once at startup, which is simple to test (see [06-testing-strategy.md](06-testing-strategy.md)).

## Module/project mapping

See [07-project-structure.md](07-project-structure.md) for the full solution layout; in brief:

- `Modest.Core` — contracts above, EST domain types, no external I/O.
- `Modest.Codec` — PKCS#10 parsing, PKCS#7 certs-only building, base64/DER helpers. Depends only on `System.Security.Cryptography.Pkcs`/`.X509Certificates`. Kept separate from `Modest.Server` so it's unit-testable without spinning up ASP.NET Core, and separate from `Modest.Core` because it's an implementation detail (wire encoding), not a domain contract.
- `Modest.Issuance.InternalCa` — implements `ICertificateIssuer` over a local keypair.
- `Modest.Issuance.HttpDelegate` — implements `ICertificateIssuer` over `HttpClient` + the JSON contract.
- `Modest.Server` — ASP.NET Core host: routing, auth middleware, DI wiring, configuration binding.
- `Modest.Tooling` — small CLI for operational tasks (generate a self-signed CA keypair for internal mode, inspect a CSR, etc.) — see [08-roadmap.md](08-roadmap.md); not required for the server to function.
