# Open Questions / Assumptions to Confirm

This plan makes a number of reasonable default decisions so a concrete design could be produced without stalling on every ambiguity. Before or during implementation, the following should be confirmed with the user — each notes the default assumed elsewhere in this plan and what changes if the answer differs.

## About the HTTP delegated issuance API contract

1. **CSR encoding in the outbound `{"CSR": "..."}` field**: assumed to be base64 of the *raw DER* PKCS#10 bytes (re-encoded cleanly from what the EST client sent, not passed through verbatim with its original line-wraps). Is this correct, or does the upstream API expect base64-of-PEM (i.e. base64 the ASCII `-----BEGIN CERTIFICATE REQUEST-----...` text itself)? This changes one encoding step in `Modest.Issuance.HttpDelegate` — worth nailing down against the actual upstream API's expectations before Phase 5.

Answer: yes that's correct, raw DER PKCS#10 bytes encoded in base64 with the corresponding --- BEGIN... headers

**Resolved 2026-08-25**: that answer was self-contradictory as written — "raw DER... base64" (no PEM markers) versus "with the corresponding BEGIN headers" (PEM) describe two different encodings. First reconfirmation landed on **base64 of PEM text**; testing against the real upstream (a classic `System.Web.Http` service — `[FromBody] CertificateRequestDTO`) then showed that reading was still wrong: the field is the **PEM text itself**, sent directly, not base64 of it and not the raw DER. `HttpDelegateIssuer.IssueAsync` builds the field via `PemEncoding.WriteString("CERTIFICATE REQUEST", ...)` with no further encoding. Updated everywhere this contract is documented: [03-api-design.md](03-api-design.md), [04-issuance-providers.md](04-issuance-providers.md), [README.md](../README.md).

Testing against that same real upstream also surfaced an unrelated transport-level issue, fixed alongside this: Modest's outbound request previously had no `Content-Length` header (sent via chunked transfer-encoding, an artifact of `HttpClient.PostAsJsonAsync`'s streaming `JsonContent`). IIS logs showed the full request arriving byte-for-byte, but the classic Web API model binder still bound `null` — a known weak spot for chunked bodies without a declared length. `HttpDelegateIssuer` now sends a buffered `ByteArrayContent`, which always sets `Content-Length`.

2. **`issuer` field ordering**: assumed to be one or more concatenated PEM certs, intermediate(s) first then root (or intermediate-only, root distributed separately) — does the actual upstream API guarantee an order, and does it ever include the leaf certificate itself in this field (some APIs redundantly do)?

Anwer: order is guaranteed, the leaf certificate is not included, only intermediate + root

3. **Outbound authentication scheme**: v1 plan supports a static header (API key) or bearer token, configured via a file-path-indirected secret. Does the real upstream use one of these, or something else (mTLS, HMAC-signed requests, OAuth client-credentials flow)? This affects `Modest.Issuance.HttpDelegate`'s HTTP client configuration in Phase 5.

Answer: the example http based issuer will have to use basic authentication to communicate with the external issuer component

4. **Synchronous vs asynchronous upstream**: assumed the upstream always responds synchronously (2xx with the cert, or an error) within the configured timeout. If the real upstream can return "pending, check back later," that upgrades the delegated issuer from "wire protocol supports async, but doesn't use it" to "actually implements Phase-approved async," which is currently deferred — worth knowing early since it changes Phase 5's scope non-trivially.

Answer: correct, upstream will always respond synchronously

5. **`/cacerts` chain source for delegated mode**: v1 defaults to a statically configured chain (see [04-issuance-providers.md](04-issuance-providers.md)) rather than deriving it from issuance responses, specifically so bootstrap works before any enrollment has happened. Confirm the upstream's issuing chain is in fact stable/known ahead of time so static config is workable, or whether chain rotation is a real concern that needs the alternative (derived/cached) approach instead.

Answer: static config is alright

## About RFC 7030 scope

6. **Digest auth**: v1 skips it in favor of Basic-over-TLS only. Confirm no target EST client actually requires Digest specifically (uncommon, but some legacy network gear might).

Answer: not required

7. **`/csrattrs` content**: v1 always returns empty (`204`). If there's a known need to hint clients toward specific key types/algorithms via this endpoint, that's a small addition worth pulling forward rather than leaving fully deferred.

Answer: good, we can keep this in mind for later (e.g. add to readme)

8. **Re-enrollment identity check**: v1 does not hard-enforce "must present the certificate being renewed" at the protocol layer (left to issuer/policy). Confirm this is acceptable, or whether the protocol layer should reject re-enrollment attempts where the authenticated client cert's subject doesn't match the CSR subject, as a built-in check.

Answer: protocol should check the client certs subject to match the csr subject, including all SANs, this is a needed built-in check. Make this check configurable (on/off) via a settings parameter.


## About operations/deployment

9. **Ops endpoint exposure**: should `/healthz`/`/readyz` be reachable on the same TLS+mTLS-negotiating listener as the EST endpoints, or on a separate plain-HTTP internal-only listener (simpler for k8s/LB health checks that don't want to do TLS/client-cert handshakes)? Currently left as a Phase 6 decision.

Answer: seperate plain-HTTP listener

10. **Deployment target**: this plan assumes a container/Linux deployment (informing the "no Windows cert store" and file-path-secret decisions). Confirm this matches actual deployment plans (bare-metal Linux service, Kubernetes, etc.) so Phase 6's Dockerfile/ops work is aimed correctly.

Answer: deployment target is a k8s deployment via helm chart

## Lower-priority, revisit only if needed during implementation

11. Whether BouncyCastle is ever needed as a fallback if a specific ASN.1 structure proves awkward in `System.Formats.Asn1`/`System.Security.Cryptography.Pkcs` — current plan assumes BCL-only is sufficient (this was validated at a high level during research but not against every edge case, e.g. unusual CSR attributes).

Answer: BouncyCastle should not be necessary

12. Exact serial number generation scheme for the internal CA (random 20-byte assumed, per RFC 5280 guidance) — no known constraint against this, just noting it's a policy knob some organizations have opinions about.

Answer: no specific opinion