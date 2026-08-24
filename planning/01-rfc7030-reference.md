# RFC 7030 Reference (distilled for implementers)

This is the working reference the implementation is checked against. It condenses [RFC 7030](https://www.rfc-editor.org/rfc/rfc7030) down to what Modest needs to get right. Section numbers below refer to the RFC.

## 1. URI structure (§3.2.2)

```
https://<server>/.well-known/est/[<label>/]<operation>
```

- The well-known prefix is fixed: `/.well-known/est` (per RFC 5785).
- `<label>` is an optional path segment identifying a specific CA when a server fronts more than one. **v1 does not implement labels** — everything hangs off the unlabelled root, e.g. `/.well-known/est/simpleenroll`. The routing layer should still be written so a label segment can be inserted later without a redesign (see [02-architecture.md](02-architecture.md)).

## 2. Operations Modest implements in v1

| Operation | Path | Method | Auth required | Request type | Response type |
|---|---|---|---|---|---|
| Get CA certificates | `/cacerts` | GET | No (bootstrap-safe) | — | `application/pkcs7-mime; smime-type=certs-only` |
| Simple enroll | `/simpleenroll` | POST | Yes | `application/pkcs10` (base64 DER) | `application/pkcs7-mime; smime-type=certs-only` |
| Simple re-enroll | `/simplereenroll` | POST | Yes (existing cert or equivalent) | `application/pkcs10` (base64 DER) | `application/pkcs7-mime; smime-type=certs-only` |
| CSR attributes | `/csrattrs` | GET | No (server's choice; typically none) | — | `application/csrattrs` (base64 DER) |

Deferred: `/fullcmc`, `/serverkeygen` — see [00-overview.md](00-overview.md#non-goals-for-v1) and [08-roadmap.md](08-roadmap.md).

## 3. Content types and wire encoding (§3.2.1, §3.3–§3.4)

- **Request bodies for `/simpleenroll` and `/simplereenroll`**: a raw PKCS#10 `CertificationRequest` (RFC 2986), DER-encoded, then **base64-encoded as text** (not binary), with `Content-Type: application/pkcs10` and `Content-Transfer-Encoding: base64`. Line length of the base64 body is not mandated strictly by EST (unlike classic PEM's 64-char wrapping) but implementations commonly wrap at 76 chars; Modest's parser must accept base64 with or without line wraps/whitespace.
- **Response bodies for enroll/reenroll and `/cacerts`**: a PKCS#7 (CMS) `SignedData` structure containing **no signature and no signed content** — just a bag of certificates (the "degenerate certs-only" / "certs-only" CMS message, historically `.p7c`). This is also base64-text-encoded over the wire, `Content-Type: application/pkcs7-mime; smime-type=certs-only`, `Content-Transfer-Encoding: base64`.
- **`/csrattrs` response**: DER-encoded `CsrAttrs` ASN.1 sequence (defined below), base64-encoded, `Content-Type: application/csrattrs`. An empty/absent response is signalled with `HTTP 204 No Content` (RFC 7030 also mentions 404 as acceptable for "operation not implemented"; Modest uses 204 for "implemented, nothing required").

```asn1
CsrAttrs ::= SEQUENCE SIZE (0..MAX) OF AttrOrOID
AttrOrOID ::= CHOICE {
    oid         OBJECT IDENTIFIER,
    attribute   Attribute }
Attribute { ATTRIBUTE:IOSet } ::= SEQUENCE {
    type   ATTRIBUTE.&id({IOSet}),
    values SET SIZE(1..MAX) OF ATTRIBUTE.&Type({IOSet}{@type}) }
```

For v1, `/csrattrs` returns an empty `CsrAttrs` sequence (equivalent to "no specific attributes required") — this is valid per the RFC and keeps CSR content negotiation out of scope for the first release. See [09-open-questions.md](09-open-questions.md).

## 4. TLS requirements (§3.1, §3.2)

- TLS 1.1 minimum per the RFC text; **Modest requires TLS 1.2 minimum in practice** (TLS 1.1 is deprecated/removed from modern .NET's `SslProtocols` defaults and from Kestrel — this is a deliberate, documented deviation that stays within the spirit of the RFC's "at least" wording). TLS 1.3 is the target default.
- NULL and anonymous cipher suites are prohibited — not reachable via Kestrel defaults anyway.
- The server must present a valid server certificate for standard TLS server-auth on every endpoint.
- Mutual TLS (client certificate request) is supported at the Kestrel level and is one of two supported client authentication mechanisms (the other being HTTP Basic auth over TLS). See §5 below and [05-security.md](05-security.md).

## 5. Client authentication model Modest supports (§3.2.3, §3.3.2)

RFC 7030 allows several client authentication mechanisms; Modest v1 supports:

1. **TLS client certificate authentication** (RECOMMENDED by the RFC). Kestrel is configured with `ClientCertificateMode.AllowCertificate` (not `RequireCertificate`, because HTTP Basic auth must remain usable when no client cert is presented, and `/cacerts`/`/csrattrs` must work with no client cert at all). The EST layer decides per-operation whether a client cert is mandatory.
2. **HTTP Basic authentication over TLS** (§3.2.3: "HTTP Basic and Digest ... MUST only be performed over TLS"). Digest auth is **not implemented in v1** — Basic auth over TLS 1.2+ gives equivalent confidentiality for the credential and is far simpler to implement/test correctly; Digest is legacy and rarely used by modern EST clients. Documented as a deviation, see [09-open-questions.md](09-open-questions.md).
3. **Unauthenticated bootstrap** for `/cacerts` and `/csrattrs`, as the RFC allows — these two operations exist specifically so a client with no trust material yet can retrieve the CA certs (and validate them out-of-band via fingerprint) before attempting an authenticated enrollment.

`/simpleenroll` and `/simplereenroll` **require** at least one authenticated identity (client cert **or** HTTP Basic credentials validated against a configurable identity/authorization provider). Which credential was used, and its parsed identity, is threaded into the `ICertificateIssuer` call so issuance policy/logging can see it (see [02-architecture.md](02-architecture.md)).

**Re-enrollment specifically** (§3.3.2): the RFC's intent is that a client with an existing valid certificate re-authenticates using that certificate over TLS client auth. Modest v1 treats `/simplereenroll` identically to `/simpleenroll` at the HTTP layer (same auth options accepted) — enforcing "must present the certificate being renewed" is a policy decision left to the configured issuer/authorization layer, not hard-coded into the protocol layer, since with a delegated external issuer that check may live server-side anyway. This is called out explicitly in [09-open-questions.md](09-open-questions.md).

## 6. Proof-of-possession / channel binding (§3.4)

The RFC describes an optional mechanism where the client embeds the TLS `tls-unique` channel-binding value into the CSR's `challengePassword` attribute, letting the server cryptographically bind the CSR to the specific TLS session it arrived on. This requires reading the TLS session's `tls-unique` value from the transport (`SslStream` in .NET does not expose `tls-unique` directly as of .NET 10 — this would need a custom P/Invoke or OpenSSL-level extraction). **v1 does not implement or enforce channel-binding validation.** If a CSR contains a `challengePassword` with this data, Modest ignores it (does not fail the request because of it). This is a deliberate scope cut, documented in [09-open-questions.md](09-open-questions.md) and [08-roadmap.md](08-roadmap.md).

## 7. Asynchronous enrollment (§4.2.3)

If issuance cannot complete synchronously (e.g. the internal CA policy requires manual approval, or the delegated HTTP issuer returns "pending"), the server responds `HTTP 202 Accepted` with a `Retry-After` header (integer seconds). "The server is responsible for maintaining all states necessary to recognize and handle retry operations as the client is stateless in this regard" — i.e. **the retry request is byte-for-byte identical** to the original (same CSR), so the server must correlate retries by request content (e.g. hash of the CSR + client identity), not by any session/ticket the client carries. This shapes the `ICertificateIssuer` contract to support a `Pending` result and a correlation key. See [02-architecture.md](02-architecture.md) and [04-issuance-providers.md](04-issuance-providers.md).

v1 scope: the **protocol support** for 202/Retry-After is built in from the start (it's cheap and part of the contract), but neither shipped issuer implementation actually returns `Pending` in v1 — internal CA signs synchronously, and the HTTP delegated issuer treats the upstream API as synchronous too (a non-2xx or malformed response is an error, not a "come back later"). Genuine async issuer support is a roadmap item.

## 8. Error handling (§4.4)

- 4xx/5xx responses carry a human-readable plain-text body (`Content-Type: text/plain`) by default. Modest does not implement CMC-formatted error responses in v1 (that's tied to `/fullcmc`, which is out of scope).
- Malformed CSR, unparseable base64, unsupported key type/size, failed auth, and issuer-side rejection all map to distinct 4xx codes (mapping table in [03-api-design.md](03-api-design.md)).

## 9. HTTP redirects (§4.4.3)

The RFC allows 3xx redirects to the same origin without re-authentication. **Not implemented in v1** — Modest is a single origin per deployment; no internal redirect logic is needed. Noted only so nobody adds accidental redirect middleware in front of the EST endpoints without re-reading this section.

## 10. Summary of deliberate deviations from strict RFC 7030

| RFC allows/requires | Modest v1 does | Rationale |
|---|---|---|
| TLS 1.1 minimum | TLS 1.2 minimum, 1.3 default | TLS 1.1 unsupported/deprecated in modern .NET & Kestrel |
| TLS-SRP certificate-less bootstrap | Not supported | .NET's `SslStream` has no SRP cipher suite support |
| HTTP Digest auth | Not implemented (Basic only) | Digest is legacy; Basic-over-TLS gives equivalent protection |
| `tls-unique` channel binding in CSR `challengePassword` | Ignored if present, never enforced | `SslStream` doesn't expose `tls-unique`; would need custom TLS-layer work |
| `/fullcmc`, `/serverkeygen` | Not implemented | Optional per RFC; `/simpleenroll`+`/simplereenroll` are the mandatory "Simple EST" subset |
| Multi-CA `[label]` routing | Not implemented, but not precluded | v1 targets single-CA/issuer deployments |
| Full async enrollment semantics (202 + correlated retry) | Wire-format supported; no shipped issuer actually goes async | Keeps v1 issuers simple; contract is future-proofed |

These deviations keep Modest interoperable with the mandatory-to-implement "Simple EST" client profile that most real-world EST clients (network devices, `openssl` scripts, IoT provisioning agents) actually use, while deferring the rarer/harder corners of the spec to a clearly scoped roadmap.
