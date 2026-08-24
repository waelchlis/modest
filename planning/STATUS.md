# Status — 2026-08-24

Handoff note written before a scheduled machine shutdown. Everything described here is committed.

## Where things stand

The server is **built, running, and verified against real EST clients**. 346 automated tests pass, and every row of the status-code table in [03-api-design.md](03-api-design.md) has been exercised by hand against a live instance with `curl` and `openssl`.

| Epic | State |
|---|---|
| 1 — Scaffolding | done |
| 2 — Codec | done, 146 tests |
| 3 — Internal CA issuer | done, 121 tests |
| 4 — Server core, dual listeners, bootstrap endpoints | done |
| 5 — Enrollment + re-enrollment identity check | done |
| 6 — HTTP delegated issuer | done, 79 tests |
| 7 — Docker + Helm | chart done and linting; image build blocked, see below |
| 8 — README | done |

```
git log --oneline
04f83e7 Add README, Dockerfile and Helm chart
45cede5 Implement Modest EST server: codec, both issuers, and HTTP surface
```

## What is verified, and how

`dotnet test` — 346 passing across three projects. Beyond that, a real instance was run on two listeners and driven with `openssl`-generated CSRs:

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

## Open items

**In flight.** A background agent was writing `tests/Modest.Server.Tests` — HTTP-level integration tests covering both issuance modes, the full status-code table, and the re-enrollment matrix. It had not reported back before shutdown. **Check whether that directory contains work; if it is empty or the tests do not pass, that suite still needs writing.** This is the one real gap: the server's HTTP layer is verified by hand but not yet by automated tests.

**Docker image does not build here.** `dotnet restore` inside the container fails with `NU1301 … UntrustedRoot`. This environment intercepts TLS, and the corporate root is trusted on the host but not inside the image. The Dockerfile is structurally fine; it needs the CA certificate injected into the build stage, or a build on a network without interception. Nothing has confirmed the image runs.

**Not started.**
- `tests/Modest.Rfc7030.ComplianceTests` is an empty project. The plan calls for RFC-tagged tests giving traceability from requirement to test ([06-testing-strategy.md](06-testing-strategy.md) §6).
- CI pipeline (`.github/workflows`) from epic 1 was never written.
- No `helm install` against a real cluster; only `lint` and `template`.

## Next steps, in order

1. Check the state of `tests/Modest.Server.Tests`; finish it if incomplete. This is the highest-value remaining work.
2. Add the RFC 7030 compliance test project with `[Trait("Rfc7030Section", …)]` traceability.
3. Add the CI workflow: build, format check, test, and the `openssl` interop job.
4. Resolve the container build (inject the proxy root, or build elsewhere) and smoke-test the image.
5. Confirm the one outstanding contract question in [09-open-questions.md](09-open-questions.md) #1 — the answer said "raw DER base64" but also mentioned `-----BEGIN` headers, which are contradictory. Built to the raw-DER reading, which matches the JSON contract as originally specified. If the real upstream wants PEM, it is a one-line change in `HttpDelegateIssuer.IssueAsync`.

## Running it locally

```bash
dotnet run --project src/Modest.Tooling -- init-ca --out ./ca --subject "CN=My EST CA"
```

Then follow the [README](../README.md) quickstart. A working smoke configuration — TLS certificate, Basic credential, both listeners — was assembled under the scratchpad during this session; it is not committed, but `init-ca` plus `hash-password` reproduce it in under a minute.
