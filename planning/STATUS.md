# Status — 2026-08-25

Updated after resuming from the [2026-08-24 handoff](#progress-on-2026-08-25) below. Everything described here is committed unless noted otherwise.

## Where things stand

The server is **built, running, and verified against real EST clients**. 438 automated tests pass, and every row of the status-code table in [03-api-design.md](03-api-design.md) is covered both by an automated test and by hand against a live instance with `curl` and `openssl`.

| Epic | State |
|---|---|
| 1 — Scaffolding | done |
| 2 — Codec | done, 146 tests |
| 3 — Internal CA issuer | done, 121 tests |
| 4 — Server core, dual listeners, bootstrap endpoints | done, covered by the 86 integration tests |
| 5 — Enrollment + re-enrollment identity check | done, re-enrollment matrix pinned by test |
| 6 — HTTP delegated issuer | done, 79 tests |
| 7 — Docker + Helm | chart done and linting; image build blocked, see below |
| 8 — README | done |
| RFC 7030 compliance test project | done, 6 tests + traits on 38 existing tests, see below |

```
git log --oneline
6fa9792 Correct a stale next step in the status note
bbf8009 Update status: server integration tests landed, 432 passing
663dd9a Add HTTP integration tests for the EST server
c99feaf Add status handoff note
04f83e7 Add README, Dockerfile and Helm chart
45cede5 Implement Modest EST server: codec, both issuers, and HTTP surface
```

## What is verified, and how

`dotnet test` — 438 passing across five projects. The 86 server tests drive the real HTTP API over a real Kestrel, and run the enrollment surface against both issuance modes, which is what substantiates the modular-issuance claim. Beyond that, a real instance was run on two listeners and driven with `openssl`-generated CSRs:

- `/cacerts` and enrollment responses parse in real `openssl pkcs7`, and the certs-only writer's output is **byte-identical** to `openssl crl2pkcs7 -nocrl`.
- Issued certificates chain and validate under `openssl verify`.
- Every documented failure mode returns its documented status: 415, 400, 401, 403, 413, 502.
- Re-enrollment identity checking blocks subject impersonation and SAN escalation, and refuses Basic-authenticated re-enrollment.
- ECDSA enrollment works on P-256 and P-384.
- Listener isolation holds: EST routes 404 on the ops port, health routes 404 on the EST port.

## Defects found by testing and fixed

Recorded because several were silent, and the same traps are easy to reintroduce.

1. **Certificate reordering.** The certs-only writer used DER, whose SET OF ordering rules sort members — so the issued leaf was not reliably first. Simple EST clients take the first certificate as their own. Switched to BER for that one field, which also restored byte-identity with OpenSSL.
2. **Every EC enrollment rejected under default config.** `Oid.FriendlyName` reports `ECDSA_P256` on Linux but `nistP256` on Windows; the default allow-list used the latter. Now normalised through `EllipticCurveNames`, matching on OID.
3. **Configuration collections append to their defaults.** .NET's binder appends rather than replaces, for `List<T>` *and* arrays. Narrowing `AllowedEllipticCurves` silently widened nothing; the EKU appeared twice on every issued certificate. Collection options are now nullable with defaults applied in code.
4. **No authorityKeyIdentifier**, and leaves could outlive the signing CA. Both fixed in `CertificateBuilder`.
5. **Four unhandled-exception paths** that reported client input as a server fault (500 instead of 400/502): Ed25519 CSRs, resilience timeouts, malformed SAN URIs, and `MaxRetryAttempts: 0`.
6. **Garbage in the delegated issuer's `issuer` field** silently produced a certificate with no chain, because `ImportFromPem` ignores unparseable input rather than failing.

## Progress on 2026-08-25

1. **Port-reservation race closed.** `ModestServerHarness.StartAsync` now retries the whole
   reserve-ports → build → `app.StartAsync()` sequence (up to 5 attempts) on `IOException`/
   `SocketException`, disposing the half-started `WebApplication` between attempts. The window
   between releasing a probe port and Kestrel claiming it still exists — nothing can close it without
   either holding the socket (which just moves the failure to Kestrel) or serialising the whole
   suite — but a collision now self-heals instead of failing the run. `Modest.Server.Tests` re-run
   three times clean after the change; full solution run also clean at 438 total tests.

2. **RFC 7030 compliance test project populated.** `tests/Modest.Rfc7030.ComplianceTests` now
   references `Modest.Server.Tests` (reusing `ModestServerHarness`/`TestPki`/`EstResponse` rather than
   standing up a second real-Kestrel test host) and contributes 6 tests that were genuine coverage
   gaps: URI-structure enforcement (`/.well-known/est` prefix required, unknown/unimplemented
   operations 404 rather than 500), and wire-contract exactness that nothing else exercised —
   `/simplereenroll`'s success response had never been checked against
   `EstResponse.ShouldBeCertsOnlyResponse`, and `/csrattrs`'s 204 had never had its headers inspected
   at all.

   The bulk of the traceability the plan asks for — "largely the same tests as §5, re-tagged" — comes
   from adding `[Trait("Rfc7030Section", "N")]` (N = the numbered section of
   [01-rfc7030-reference.md](01-rfc7030-reference.md), e.g. "5" = client authentication model) directly
   onto the existing tests in `Modest.Server.Tests` (`EstEndpointTestsBase`, `PipelineOutcomeTests`,
   `ReenrollmentIdentityTests`, `ReenrollmentCheckDisabledTests`) rather than duplicating ~340 lines of
   endpoint-behaviour tests into a second project. `dotnet test --filter Rfc7030Section=5` runs just
   the 38 tests substantiating the client-auth section, across both issuer modes. Not tagged: the 413
   body-limit test (Modest's own DoS protection, not an RFC requirement) and TLS-version enforcement
   (`ModestHost.cs` pins `SslProtocols.Tls12 | Tls13` explicitly — visible by inspection; a negative
   test forcing a TLS 1.1 handshake was considered and dropped as platform-dependent/flaky, since
   modern OpenSSL on Linux won't offer 1.1 regardless of what the server would accept).

3. **CI workflow added.** `.github/workflows/build-and-test.yml`, two jobs per epic 1's spec:
   `build-and-test` (restore → Release build → `dotnet format --verify-no-changes` →
   `dotnet test --filter "Category!=OpenSslInterop"` with `coverlet.collector` coverage uploaded as an
   artifact) and `openssl-interop` (asserts `openssl version` succeeds before running just
   `Modest.Codec.Tests` filtered to `Category=OpenSslInterop`, so a runner silently missing openssl
   fails loudly instead of quietly skipping the coverage this suite is supposed to give — see
   `OpenSslInteropTests.cs`'s own remark about that risk). Both jobs' exact command lines were run
   locally first (`dotnet restore/build/format/test` with the same flags) and pass. No remote is
   configured for this repo yet, so the workflow has not actually executed on GitHub — that's the
   condition on "CI is green" in epic 1's Definition of Done that remains unconfirmed.

## Open items

**Docker image does not build here.** `dotnet restore` inside the container fails with `NU1301 … UntrustedRoot`. This environment intercepts TLS, and the corporate root is trusted on the host but not inside the image. The Dockerfile is structurally fine; it needs the CA certificate injected into the build stage, or a build on a network without interception. Nothing has confirmed the image runs.

**CI has never actually run.** The workflow file is written and its steps are individually verified locally, but with no GitHub remote configured, nothing has triggered it — "CI is green" is unconfirmed.

**Not started.**
- No `helm install` against a real cluster; only `lint` and `template`.

## Next steps, in order

1. Push to a GitHub remote (none is configured yet) and confirm the workflow actually goes green there.
2. Resolve the container build (inject the proxy root, or build elsewhere) and smoke-test the image.
3. Confirm the one outstanding contract question in [09-open-questions.md](09-open-questions.md) #1 — the answer said "raw DER base64" but also mentioned `-----BEGIN` headers, which are contradictory. Built to the raw-DER reading, which matches the JSON contract as originally specified. If the real upstream wants PEM, it is a one-line change in `HttpDelegateIssuer.IssueAsync`.

## Running it locally

```bash
dotnet run --project src/Modest.Tooling -- init-ca --out ./ca --subject "CN=My EST CA"
```

Then follow the [README](../README.md) quickstart. A working smoke configuration — TLS certificate, Basic credential, both listeners — was assembled under the scratchpad during this session; it is not committed, but `init-ca` plus `hash-password` reproduce it in under a minute.
