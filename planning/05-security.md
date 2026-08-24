# Security

## TLS configuration

- Kestrel `HttpsConnectionAdapterOptions`: `SslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13` explicitly (never rely on OS defaults, which can drift); `ClientCertificateMode = ClientCertificateMode.AllowCertificate` (request but don't hard-require at the transport level — `/cacerts`/`/csrattrs` must remain usable without a client cert, and `/simpleenroll`/`/simplereenroll` allow Basic-auth-only clients too, so requiring a cert at the TLS handshake level would break both).
- Server's own TLS certificate: operator-supplied (config path to a PFX or PEM+key pair), **not** the CA keypair used for issuance — these should be different certificates in any real deployment (the EST server's TLS identity and its issuing CA identity are different roles), though nothing technically prevents the same cert being used in a lab/dev setup. Document this recommendation; don't enforce it in code.
- `ClientCertificateValidation` callback: in v1, delegate *trust chain* validation to whatever the OS/`.NET` default chain-building does against a configured trust store (a dedicated "client cert trust anchors" cert bundle path in config — kept separate from the EST server's own TLS trust and from the CA's own root, since a client's authentication cert may come from an entirely different, pre-existing PKI, per RFC 7030's "Explicit vs Implicit trust anchor" model, §2). Revocation checking (CRL/OCSP) is **not implemented in v1** — flagged as a real gap for production use, tracked in [08-roadmap.md](08-roadmap.md).

## Authentication (inbound, EST clients)

Implemented as a small custom middleware (`EstAuthenticationMiddleware`) rather than `Microsoft.AspNetCore.Authentication` schemes, because:
- EST's model is "try client cert, else try Basic, else anonymous-but-restricted-to-bootstrap-ops" evaluated inline per request, not a challenge/redirect flow ASP.NET Core's authentication handlers are built around.
- Keeping it custom and small (~50-100 lines) is easier to unit test exhaustively than fighting the authentication handler abstraction for a shape it wasn't designed for.

Flow:
1. If `HttpContext.Connection.ClientCertificate` is set (Kestrel already did the TLS-level negotiation), validate it against the configured client-trust store; on success, `ClientIdentity(ClientCertificate, subject, cert)`. On chain-validation failure, treat as if no cert was presented (fall through to Basic) rather than hard-failing — a client presenting an *invalid* cert but valid Basic credentials should still be able to authenticate (mirrors how most real EST/mTLS gateways behave, and keeps the two auth mechanisms genuinely independent as the RFC intends).
2. Else if `Authorization: Basic <base64>` header present, decode, validate against the configured identity provider (v1: a simple static username/password-hash list from config — pluggable interface `IBasicCredentialValidator` so a real backend, LDAP/etc., can be swapped in later without touching the middleware). On success, `ClientIdentity(HttpBasic, username, null)`.
3. Else `ClientIdentity(None, null, null)`.
4. Attach to `HttpContext.Items["EstClientIdentity"]`, consumed by `RequireEstClientAuth()` and by the endpoint handlers when building `IssuanceRequest.Identity`.

Passwords: only ever handled as `ReadOnlySpan<char>`/short-lived strings during comparison; stored config-side as salted hashes (PBKDF2 via `Rfc2898DeriveBytes`, no plaintext passwords in config), never logged.

## Key material handling

- **CA private key** (internal CA mode): loaded once at startup, held as an `X509Certificate2`'s private key handle for the process lifetime. Never serialized, logged, or exposed via any API/endpoint. PFX password read from a file path (not an env var/inline config value) specifically so it doesn't show up in `ps`, container inspect output, or config-management diffs; file permissions should be `0600`, owned by the service account — documented as a deployment requirement, and startup should warn (not necessarily fail — filesystem permission checks are OS-specific and brittle to hard-fail on) if the key file is group/world-readable on POSIX.
- **Server TLS private key**: same handling pattern as the CA key, loaded via Kestrel's standard cert-loading config.
- **HTTP delegate mode has no CA private key on this host at all** — that's the point of the mode. The only secret is the outbound API credential (API key/bearer token), read the same way (file path, not inline).
- No key material of any kind appears in structured logs. Log statements around issuance log the *identity* (subject DN, serial, thumbprint of issued cert) never the key.

## Logging & audit

Every terminal outcome of `/simpleenroll`/`/simplereenroll` is logged (structured, e.g. Serilog or `Microsoft.Extensions.Logging` with structured properties) with: timestamp, operation, client identity (auth method + subject/username — never the raw Basic password), CSR subject (parsed, informational only — not trusted for authz), outcome (issued/pending/rejected + reason), issued certificate's serial + thumbprint (on success), correlation/trace id, and latency. This is the audit trail an operator needs to answer "who got a certificate and when" without needing to correlate against the CA's own records (useful in delegated mode where Modest is the only place that saw both the requester's identity *and* the issuance decision together).

## Threat model summary

| Threat | Mitigation |
|---|---|
| Unauthenticated party obtains a certificate | `/simpleenroll`/`/simplereenroll` require cert-or-Basic auth; enforced server-side before any issuer call |
| Weak/forged CSR proof-of-possession | Protocol-layer CSR self-signature verification via `CertificateRequest.LoadSigningRequest`, before issuer is invoked (see [04-issuance-providers.md](04-issuance-providers.md)) |
| CA private key exfiltration | Key never leaves the internal-CA process's memory in plaintext form beyond the loaded `X509Certificate2`; not logged, not returned by any API; file permissions guidance for the PFX at rest |
| Credential stuffing against Basic auth | Out of scope for v1 (no rate limiting/lockout) — flagged as a roadmap gap; recommend fronting with a reverse proxy/WAF for production, or preferring client-cert auth which isn't guessable |
| MITM / weak TLS | TLS 1.2 minimum, 1.3 default, no NULL/anonymous suites (Kestrel defaults already exclude these) |
| Malicious/oversized request bodies (DoS) | Kestrel's default request body size limits apply; additionally enforce a small explicit max CSR size (e.g. 16 KB) before attempting to parse, rejecting oversized bodies at `413` before any expensive parsing/crypto work |
| Delegated issuer upstream compromise/spoofing | Outbound call is itself over TLS with the upstream's server cert validated normally; upstream API credential is a secret Modest holds, not something a client can influence |
| Replay of a captured enrollment request | Each successful issuance produces a new cert with a fresh serial; replaying the same CSR to `/simpleenroll` again just re-issues (not inherently harmful, but see revocation gap above) — not treated as a security bug for v1 since EST itself doesn't define replay protection beyond TLS + auth |

## Known v1 gaps (explicitly not addressed, tracked in [08-roadmap.md](08-roadmap.md))

- No CRL/OCSP checking of client certificates during auth.
- No rate limiting/brute-force protection on Basic auth.
- No `tls-unique` channel-binding enforcement (see [01-rfc7030-reference.md](01-rfc7030-reference.md)).
- No HSM/KMS-backed CA key option (file-based PFX only).
