# Testing Strategy

"Extensive testing to cover all relevant functionality" is a stated project goal, not an afterthought — testability is a first-class input to the architecture in [02-architecture.md](02-architecture.md) (small pure `Modest.Codec`, an issuance boundary that's a plain interface, custom auth middleware kept deliberately small). This document lays out the test pyramid and, specifically, an RFC-compliance test matrix so "did we implement the spec correctly" is a checkable artifact, not a feeling.

## Tooling

- **xUnit** — test framework (the .NET-idiomatic default, first-class `dotnet test`/CI support).
- **FluentAssertions** (or `Shouldly` — pick one, FluentAssertions is more common) — readable assertions, especially useful for asserting on X.509/ASN.1 structure.
- **WireMock.Net** — stands in for the external HTTP issuance API in `Modest.Issuance.HttpDelegate` tests, without needing a real upstream.
- **Microsoft.AspNetCore.Mvc.Testing** (`WebApplicationFactory<T>`) — in-process test host for `Modest.Server` integration tests, including ones that drive real TLS (via `WebApplicationFactory`'s `ClientOptions` + a custom `HttpClientHandler` presenting a client cert) to exercise mTLS end-to-end.
- **coverlet** + a coverage report step in CI — track coverage, but treat it as a signal not a target (see note at the end of this document).
- **BenchmarkDotNet** — optional, not for CI gating, useful once for sanity-checking that CSR parsing/signing isn't pathologically slow (out of scope for initial delivery, roadmap item).

## Test pyramid

### 1. Unit tests — `Modest.Codec`

Pure, fast, no I/O. This is the highest-value test surface because getting binary encoding subtly wrong is the easiest way to break interop with real EST clients while every "does it compile and run" check still passes.

- Base64 decode tolerant of line-wraps/whitespace/missing trailing newline; rejects invalid base64 with a clear error.
- PKCS#10 parse: valid RSA CSR, valid ECDSA CSR (P-256/P-384), CSR with SANs, CSR with a `challengePassword` attribute (must not fail — just ignored per [01-rfc7030-reference.md](01-rfc7030-reference.md)), CSR with an invalid self-signature (must be rejected), truncated/corrupt DER (must be rejected, not throw an unhandled exception).
- Certs-only PKCS#7 `SignedData` build: single cert, multi-cert chain, empty chain (edge case — should this even be allowed? decide and test the decision); round-trip test — build a certs-only blob and verify `SignedCms.Decode` (or OpenSSL, see interop tests below) can read back exactly the certs put in, in the order expected.
- `CsrAttrs` empty-sequence DER encoding matches the exact bytes a real EST client's ASN.1 parser expects (compare against a hand-verified fixture, not just "it parses back to empty" — a truly empty `SEQUENCE` is `30 00`, worth asserting the literal bytes at least once).

### 2. Unit tests — `Modest.Issuance.InternalCa`

- Signs a valid CSR, resulting leaf cert has correct issuer DN, validity window, extensions (Basic Constraints, Key Usage, EKU, SKI/AKI) per configured policy.
- Rejects CSR with disallowed key size/algorithm (`Rejected(..., InvalidCsr)`).
- Serial numbers are random and non-repeating across many issuances (statistical sanity check, not a proof).
- Startup fails fast on bad PFX path/password/missing key-usage-for-signing — tested via a small harness that constructs the provider directly (not full `WebApplicationFactory`) so this is fast.

### 3. Unit tests — `Modest.Issuance.HttpDelegate`

Using WireMock.Net for the upstream:

- Happy path: valid JSON response → `Issued` with correctly parsed leaf + chain.
- Malformed JSON, missing `certificate`/`issuer` fields, invalid PEM in either field → `Rejected(..., InvalidCsr)`.
- Upstream `4xx` → `Rejected(..., PolicyDenied)`.
- Upstream `5xx`, connection refused, timeout (WireMock delay past configured timeout) → `Rejected(..., UpstreamUnavailable)`.
- Outbound request body shape asserted byte-for-byte against the documented `{"CSR": "..."}` contract (guards against accidental re-encoding bugs called out in [04-issuance-providers.md](04-issuance-providers.md)).
- Retry policy: transient failure followed by success is retried and succeeds; non-transient (4xx) is not retried (assert WireMock saw exactly one request, not N).
- Outbound auth header (API key/bearer) is attached correctly and is *not* logged anywhere (log-output assertion).

### 4. Unit tests — `Modest.Server` auth middleware

Testing `EstAuthenticationMiddleware` in isolation (constructed directly with a fake `HttpContext`, not through a full host) for every branch: valid client cert only, invalid client cert + valid Basic (falls through correctly), valid client cert + valid Basic (cert wins/whichever precedence is decided — pin the behavior with a test either way), no credentials at all, malformed `Authorization` header, wrong auth scheme (e.g. `Bearer` instead of `Basic`).

### 5. Integration tests — `Modest.Server` (in-process host, real HTTP + TLS)

Using `WebApplicationFactory` with a real Kestrel TLS binding (not the in-memory `TestServer` transport, since mTLS negotiation needs an actual TLS handshake) and a test-generated CA + server cert + client certs (built once per test run via `Modest.Codec`'s own cert-building helpers — "the codec tests its own tooling" is fine here, it's test infrastructure, not the thing under test).

- Full `/cacerts` → parse response → correct certs.
- Full `/simpleenroll` happy path end-to-end: generate a real CSR (using .NET's own `CertificateRequest.CreateSigningRequest` client-side, as a stand-in EST client would), POST it with client-cert auth, get back a parseable certs-only response, verify the returned leaf chains up to the CA cert from `/cacerts`.
- Same with Basic auth instead of client cert.
- Unauthenticated `/simpleenroll` → `401` with correct `WWW-Authenticate` header.
- Oversized body → `413`.
- Wrong `Content-Type` → `415`.
- `/simplereenroll` happy path.
- `/csrattrs` → `204`.
- Each test parameterized/duplicated across **both issuer modes** (internal CA, and HTTP-delegate backed by WireMock) via a shared test base/fixture, so the whole HTTP surface is proven correct under both configurations, not just one.

### 6. RFC-compliance test matrix (traceability)

A dedicated test project/trait category (`[Trait("Rfc7030Section", "4.2.1")]` or similar, queryable via `dotnet test --filter`) where each test is explicitly tied back to a specific requirement from [01-rfc7030-reference.md](01-rfc7030-reference.md), so "are we compliant" is answerable by listing which requirements have a passing test versus which are explicitly out-of-scope deviations (cross-referenced against the deviations table in that document). This is largely the same tests as §5 above, re-tagged, plus a few compliance-specific ones that don't fit naturally as "integration tests":

- Response `Content-Transfer-Encoding` header exactly `base64` on all binary responses.
- `202`/`Retry-After` shape is correct *if* an issuer ever returns `Pending` (test this against a deliberately-async fake issuer, since neither shipped issuer goes async in v1 — this proves the *protocol* supports it even though nothing exercises it in production yet).
- Content-type strings match exactly, including the `smime-type=certs-only` parameter (case, spacing).

### 7. Interop / wire-format sanity checks (OpenSSL cross-check)

A small set of tests (or a documented manual/CI script step) that shell out to `openssl` to independently verify Modest's wire output is genuinely standard, not just self-consistent:

- `openssl req` generates a CSR → fed to Modest's `/simpleenroll` → `openssl pkcs7 -print_certs` can parse the response.
- Modest's `/cacerts` output round-trips through `openssl pkcs7 -print_certs`.

This matters because a codec that only ever talks to itself can accumulate matching bugs on both ends (encode and the in-process test's decode) that a genuinely independent implementation would catch immediately. Marked as a separate CI job/category since it depends on `openssl` being present in the CI image (reasonable to require, but worth isolating so unit tests don't have an external tool dependency).

### 8. What's explicitly *not* covered in v1

- Load/performance testing (noted, not built — a future roadmap item if the user needs throughput numbers).
- Fuzz testing of the ASN.1 parser (valuable given it's parsing untrusted input, but scoped out of initial delivery — flagged in [08-roadmap.md](08-roadmap.md) as a good `SharpFuzz`/`AFL`-style follow-up given `Modest.Codec`'s narrow, pure surface is an easy fuzz target later).

## Coverage expectations

Aim for high (>90%) line/branch coverage on `Modest.Codec` and both issuance providers specifically — these are the correctness-critical, low-branching-complexity modules where high coverage is cheap and meaningful. Don't chase a specific number on `Modest.Server`'s DI/startup wiring glue, where coverage is a poor proxy for value; instead judge that layer by whether the integration test list in §5 is actually complete.
