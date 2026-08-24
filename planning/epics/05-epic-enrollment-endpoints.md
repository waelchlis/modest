# Epic 5 — Enrollment Endpoints + Re-enrollment Identity Check

**Depends on**: 4 (server core: auth middleware, routing, at least one working issuer). **Blocks**: 7 (hardening/Helm assumes the full protocol surface exists).

## Objective

Implement `/simpleenroll` and `/simplereenroll`, including the **built-in, configurable re-enrollment identity check** confirmed in [../09-open-questions.md](../09-open-questions.md) #8 — this is new scope versus the original plan, which had left this entirely to issuer/policy. The check now lives in the protocol layer and is on by default.

## Deliverables

In `src/Modest.Server`:

- `EnrollEndpoint` — `HandleEnroll` and `HandleReenroll`, per the pipeline in [../02-architecture.md](../02-architecture.md) and status mapping in [../03-api-design.md](../03-api-design.md): content-type validation (`415`), body size cap (`413`), base64/CSR parse via `Modest.Codec.Pkcs10CsrReader` (`400` on failure — this also covers CSR self-signature/proof-of-possession per epic 2), `IssuanceRequest` construction, `ICertificateIssuer.IssueAsync` call, result mapping (`Issued`→`200` certs-only via `Pkcs7CertsOnlyWriter`, `Pending`→`202`+`Retry-After`, `Rejected`→ status per `IssuanceRejectionKind`).
- `ReenrollmentIdentityChecker` — new component, used only by `HandleReenroll`: given the authenticated `ClientIdentity` (must be `ClientCertificate` for this check to apply — see open question below) and the parsed CSR, compares the client certificate's Subject DN **and full SAN set** against the CSR's requested Subject DN and SAN set; mismatch → `Rejected(..., Unauthorized)` (maps to `403` — the caller authenticated fine, they're just not authorized to re-enroll *for this identity*). Comparison must be a genuine set-equality on SANs (order-independent, type-aware — a DNS SAN and an IP SAN with the same string value are not the same thing), not a naive string comparison.
- `ReenrollmentOptions` — `RequireMatchingIdentity: bool` (default `true`), bound from `Issuance:Reenrollment:RequireMatchingIdentity` config, per the "configurable on/off" requirement in the confirmed answer.
- Status-code mapping table implemented as a small pure function (`IssuanceRejectionKind → (int statusCode, bool includeWwwAuthenticate)`), unit-testable independent of the full HTTP pipeline.

## Design note: what happens on `/simplereenroll` when the client authenticated via Basic, not a client cert?

The confirmed answer says the check compares "the client cert's subject" against the CSR — which presupposes a client certificate was presented. If `RequireMatchingIdentity` is on and the client authenticated via HTTP Basic instead (no certificate to compare against), the check **cannot evaluate** in the way the answer describes. Two reasonable behaviors: (a) treat "no client cert" as an automatic failure of the check when it's enabled (Basic-auth-only re-enrollment simply isn't allowed while the toggle is on), or (b) skip the check when there's no cert to compare (toggle only constrains cert-authenticated re-enrollment). **This plan adopts (a)** — the check is a *re-enrollment* identity guarantee, and re-enrollment's whole premise (per RFC 7030 §3.3.2, see [../01-rfc7030-reference.md](../01-rfc7030-reference.md)) is "you're proving continuity by presenting your existing cert," so a Basic-authenticated re-enrollment attempt has nothing to prove continuity with and should be rejected when the toggle is on. This is called out here as a judgment call worth a one-line confirmation from the user during implementation review, not blocking the build.

## Tasks

1. `EnrollEndpoint.HandleEnroll` happy path + every documented error branch from [../03-api-design.md](../03-api-design.md)'s status table, integration-tested against internal-CA mode (per [../06-testing-strategy.md](../06-testing-strategy.md) §5).
2. `ReenrollmentIdentityChecker`: unit tests — matching subject+SANs passes, mismatched subject fails, matching subject but mismatched/extra/missing SAN fails, SAN order-independence (same sets, different order, passes), SAN type-awareness (DNS `"1.2.3.4"` vs IP SAN `1.2.3.4` do not match).
3. `HandleReenroll`: wires the checker in when `RequireMatchingIdentity` is true; integration tests for match/mismatch/toggle-off, and the Basic-auth-during-reenroll case per the design note above.
4. Full status-code mapping unit tests (pure function from task list in Deliverables).
5. RFC-compliance-tagged tests for this epic's surface, per [../06-testing-strategy.md](../06-testing-strategy.md) §6.
6. Re-run this epic's whole integration suite a second time once epic 6 (HTTP delegated issuer) exists, against delegate mode, via the shared test base described in [../06-testing-strategy.md](../06-testing-strategy.md) §5 — noted here as a forward-looking task even though it can only be completed once epic 6 lands; track it as a follow-up item at the end of epic 6/7 rather than leaving it silently undone.

## Definition of Done

- Every row of the status-code table in [../03-api-design.md](../03-api-design.md) has a passing integration test.
- `ReenrollmentIdentityChecker` behavior is fully pinned by unit tests including the edge cases above.
- The Basic-auth-during-reenroll judgment call (design note) is implemented consistently and documented in the README (epic 8), so operators aren't surprised by it.
- A real end-to-end run (openssl-generated CSR through `/simpleenroll`, then a second CSR through `/simplereenroll` using the just-issued cert as the client cert) succeeds manually once, in addition to automated tests.
