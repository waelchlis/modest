# Epic 2 — Codec (PKCS#10 / PKCS#7 / CsrAttrs)

**Depends on**: 1 (scaffolding). **Blocks**: 3, 4, 5, 6 (everything that touches wire bytes or signs/parses certs).

## Objective

Implement `Modest.Codec`: the pure, dependency-light library that turns EST wire bytes into structured .NET crypto types and back. This is called out in [../06-testing-strategy.md](../06-testing-strategy.md) as the highest-value test surface — get this epic solid before building the HTTP layer on top of it.

## Deliverables (types/classes)

All in `src/Modest.Codec`, namespace `Modest.Codec`:

- `Base64Wire` (static class) — `DecodeTolerant(string)` (strips whitespace/newlines before decoding, throws a codec-specific `EstCodecException` with a clear message on invalid input, not a raw `FormatException`), `Encode(ReadOnlySpan<byte>)` (produces base64 text; line-wrap width is a parameter, default unwrapped — most consumers, including the delegated-issuer contract, want unwrapped).
- `Pkcs10CsrReader` — `Parse(ReadOnlyMemory<byte> der)` → returns a `ParsedCsr` record (`CertificateRequest`-derived subject, public key, extension requests/SANs, raw bytes) using `CertificateRequest.LoadSigningRequest` per [../04-issuance-providers.md](../04-issuance-providers.md); this call already verifies the CSR's self-signature as part of loading, so `Pkcs10CsrReader.Parse` is *the* place proof-of-possession is enforced — throws `EstCodecException` (mapped to `400` at the API layer, see epic 5) on: invalid base64, invalid DER, signature verification failure, unsupported key algorithm.
- `Pkcs7CertsOnlyWriter` — `Build(X509Certificate2 leaf, IReadOnlyList<X509Certificate2> chain)` → DER bytes of a degenerate CMS `SignedData` (no signer, no content) containing `leaf` + `chain` in that order, via `System.Security.Cryptography.Pkcs.SignedCms` (`ContentInfo` with empty content, `SignedCms.Certificates` populated, no `SignerInfo` added — confirm the exact BCL incantation that produces a genuinely detached, signerless `SignedData`, since `SignedCms` is more naturally built around having at least one signer; this needs a spike/verification step within this epic, not assumed to just work — see the risk note below).
- `Pkcs7CertsOnlyWriter.BuildForCaChain(...)` — same builder, used specifically for `/cacerts` (kept as a separate named entry point even though it may share the same implementation as the enrollment-response builder, since the two call sites are conceptually distinct and this makes the code at each call site self-documenting).
- `CsrAttrsWriter` — `EmptySequence()` → the literal DER bytes `30 00` (empty `SEQUENCE`), base64-encoded, for the v1 static `/csrattrs` response. A structured builder for non-empty `CsrAttrs` (OIDs/Attributes) is **not built in this epic** — out of scope per [../09-open-questions.md](../09-open-questions.md) #7, but note in code (a short comment, not a doc block) that this is the extension point, matching what the README will say (epic 8).
- `EstCodecException` — the one exception type this library throws for any input-shaped failure; anything else (e.g. a genuine BCL/OS crypto provider failure) is allowed to propagate as whatever the BCL throws, since that's an infra problem, not a codec-input problem, and callers should treat it differently (500 vs 400 at the API layer).

### Risk note: building a signerless `SignedData` with `System.Security.Cryptography.Pkcs`

.NET's `SignedCms` API is oriented around "sign some content," and a certs-only PKCS#7 has no signer and no content — this is a well-known but slightly awkward corner of the BCL. The known-working approach (used by e.g. OpenSSL's `PKCS7_set_type(p7, NID_pkcs7_signed)` equivalent) is to construct a `SignedCms` over an empty `ContentInfo`, add certificates via the `Certificates` collection, and call `Encode()` **without** calling `ComputeSignature` — this needs to be spiked and verified against `openssl pkcs7 -print_certs` early in this epic (it's exactly the kind of "looks fine in isolation, breaks real interop" risk called out in [../06-testing-strategy.md](../06-testing-strategy.md) §7). If the direct `SignedCms` approach doesn't produce a spec-correct structure, the fallback is hand-building the ASN.1 via `System.Formats.Asn1.AsnWriter` directly against the CMS `SignedData` grammar (RFC 5652 §5.1) — more code, but full control. **This spike must happen before the rest of the epic's tasks are considered "on track"**; if it forces the fallback, budget extra time in this epic specifically for the `AsnWriter` path plus a matching set of extra unit tests for the hand-rolled structure.

## Tasks

1. Spike the `SignedCms` certs-only construction (risk note above); lock in the approach.
2. Implement `Base64Wire`, unit test tolerant decode against whitespace/newline variants and invalid input.
3. Implement `Pkcs10CsrReader`, unit test against: valid RSA-2048/3072/4096 CSR, valid ECDSA P-256/P-384 CSR, CSR with SANs, CSR with a `challengePassword` attribute present (must parse successfully — not enforced/used, per [../01-rfc7030-reference.md](../01-rfc7030-reference.md)), CSR with a tampered/invalid signature (must throw), truncated DER (must throw, not crash).
4. Implement `Pkcs7CertsOnlyWriter`, unit test: single-cert output, multi-cert chain output (order preserved), round-trip via `SignedCms.Decode` reading back exactly the input certs in order.
5. Implement `CsrAttrsWriter.EmptySequence()`, assert literal byte output `30-00` then base64.
6. **Interop test**: generate a CSR with real `openssl req -new`, feed its DER through `Pkcs10CsrReader` successfully; take `Pkcs7CertsOnlyWriter` output and confirm `openssl pkcs7 -inform DER -print_certs` (or the base64/PEM-wrapped variant) parses it and lists the expected certs. Wire this as the CI interop job from epic 1's pipeline setup.
7. Wrap up: confirm every public codec method's failure modes are covered by a test that asserts the *specific* exception/result, not just "throws something."

## Definition of Done

- All tasks above have passing tests; coverage on `Modest.Codec` is high (>90% line, per [../06-testing-strategy.md](../06-testing-strategy.md)) and, more importantly, every documented failure mode in [../03-api-design.md](../03-api-design.md)'s error table that originates at the codec layer (bad base64, malformed CSR, bad signature) has a corresponding test.
- The `SignedCms` risk item is resolved one way or the other (not left as a TODO) — this is the epic's single biggest technical risk and should not leak into epic 4/5 unresolved.
- Interop CI job passes using real `openssl` output on both sides (input generation and output verification).
