# Status — 2026-08-25

Updated after resuming from the [2026-08-24 handoff](#progress-on-2026-08-25) below. Everything described here is committed unless noted otherwise.

## Where things stand

The server is **built, running, and verified against real EST clients, a real Docker image, and a real Kubernetes deployment**. 438 automated tests pass, and every row of the status-code table in [03-api-design.md](03-api-design.md) is covered both by an automated test and by hand against a live instance with `curl` and `openssl`.

| Epic | State |
|---|---|
| 1 — Scaffolding | done |
| 2 — Codec | done, 146 tests |
| 3 — Internal CA issuer | done, 121 tests |
| 4 — Server core, dual listeners, bootstrap endpoints | done, covered by the 86 integration tests |
| 5 — Enrollment + re-enrollment identity check | done, re-enrollment matrix pinned by test |
| 6 — HTTP delegated issuer | done, 79 tests |
| 7 — Docker + Helm | done — image builds and runs, chart installs and serves on a real cluster, see below |
| 8 — README | done |
| RFC 7030 compliance test project | done, 6 tests + traits on 38 existing tests, see below |

```
git log --oneline
b99df25 Allow a configurable loadBalancerIP for the EST Service, pin pod UID/GID
3651669 Fix Docker build, fix Helm secret permissions, resolve CSR PEM contract
8439723 Close the harness port race, add RFC 7030 traceability, wire up CI
6fa9792 Correct a stale next step in the status note
bbf8009 Update status: server integration tests landed, 432 passing
663dd9a Add HTTP integration tests for the EST server
c99feaf Add status handoff note
04f83e7 Add README, Dockerfile and Helm chart
45cede5 Implement Modest EST server: codec, both issuers, and HTTP surface
```

Pushed to `main` on https://github.com/waelchlis/modest (public); CI is green there — see item 8 under
[Progress](#progress-on-2026-08-25).

## What is verified, and how

`dotnet test` — 438 passing across five projects. The 86 server tests drive the real HTTP API over a real Kestrel, and run the enrollment surface against both issuance modes, which is what substantiates the modular-issuance claim. Beyond that, a real instance was run on two listeners and driven with `openssl`-generated CSRs:

- `/cacerts` and enrollment responses parse in real `openssl pkcs7`, and the certs-only writer's output is **byte-identical** to `openssl crl2pkcs7 -nocrl`.
- Issued certificates chain and validate under `openssl verify`.
- Every documented failure mode returns its documented status: 415, 400, 401, 403, 413, 502.
- Re-enrollment identity checking blocks subject impersonation and SAN escalation, and refuses Basic-authenticated re-enrollment.
- ECDSA enrollment works on P-256 and P-384.
- Listener isolation holds: EST routes 404 on the ops port, health routes 404 on the EST port.

The same checks were repeated against the actual Docker image and a real `helm install` on a local cluster (minikube) — see items 4 and 5 under [Progress](#progress-on-2026-08-25): `/healthz`/`/readyz` 200, `/cacerts` parses and chains, a full `openssl`-CSR enrollment round-trip issues a certificate for the submitted key, and listener isolation holds through the cluster Service too.

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

4. **Docker build fixed — two separate bugs, both real.** `docker build` reproduced the `NU1301 …
   UntrustedRoot` failure from the previous session, but that turned out not to be the only problem:

   - **No `.dockerignore` existed.** `COPY src/ src/` was copying the *host's* already-restored
     `src/**/obj/` directories (with `project.assets.json` pointing at the host's NuGet cache paths)
     straight over the build stage's freshly-restored ones, so `dotnet publish --no-restore`
     immediately failed with `NETSDK1064: Package ... was not found` even once the TLS trust was
     fixed — a package that genuinely was in the container's NuGet cache, just shadowed by the
     clobbered assets file. Root-caused by exec'ing into the intermediate build-stage image and
     diffing what `dotnet restore` actually wrote against what `COPY src/ src/` left behind. Added
     [.dockerignore](../.dockerignore) (`**/bin/`, `**/obj/`, plus `tests/`/`planning/`/etc., which the
     Dockerfile never references and don't belong in the build context regardless).
   - **The TLS-interception problem was real too.** Added [docker/ca-certificates/](../docker/ca-certificates/)
     (empty except `.gitkeep`/`README.md`, gitignored otherwise — never a repo default, since baking
     one network's interception CA into the image would silently make every build trust it) and a
     `COPY` + `update-ca-certificates` step in the build stage before `dotnet restore`, per that
     directory's README.

   With both fixed, `docker build` succeeds, and the image was smoke-tested end to end: generated a
   CA + TLS cert + Basic credential with the tooling image, ran the container, and drove it with real
   `openssl`/`curl` — `/healthz`/`/readyz` 200, `/cacerts` parses in `openssl pkcs7`, a full
   enrollment round-trip issues a certificate for the submitted key, and listener isolation holds.
   Image built and torn down; nothing persists from this beyond the Dockerfile/`.dockerignore`
   changes.

5. **`helm install` run against a real cluster — found and fixed a genuine deploy-breaking bug.**
   `minikube` (docker driver), image loaded with `minikube image load`, chart installed with
   `values-internalca.yaml` plus real `modest-tls`/`modest-ca` Secrets. Both replicas
   **crash-looped**: `UnauthorizedAccessException: Access to the path '/etc/modest/tls/tls.pass' is
   denied`. Cause: Kubernetes Secret volumes are owned by root regardless of the container's runtime
   user; the chart's pod never set `fsGroup`, so the non-root process the image runs as (`uid 1654`,
   the chiselled base image's `USER $APP_UID`) had no path to read them — `defaultMode: 0400` was also
   owner-only, so even a matching group wouldn't have helped. Fixed in
   [helm/modest/values.yaml](../helm/modest/values.yaml) (`podSecurityContext.fsGroup: 1654`, documented
   as needing to match the base image if that ever changes) and
   [helm/modest/templates/deployment.yaml](../helm/modest/templates/deployment.yaml) (all four Secret
   volumes `0400` → `0440`). Re-templated, re-installed: both replicas ready, and the same `openssl`
   enroll-and-verify smoke test that ran against the bare Docker image was repeated through the
   cluster's `Service` (port-forwarded) with identical results, plus listener isolation confirmed
   through the two separate `Service` objects (`modest-modest` for EST, `modest-modest-ops` for
   health). `helm lint`/`template` alone never had a way to catch this — it's a runtime permissions
   fault, not a templating one. Cluster and image deleted afterward (`minikube delete`); nothing
   persists beyond the two chart files.

6. **Open contract question #1 resolved.** The contradictory answer in
   [09-open-questions.md](09-open-questions.md) #1 ("raw DER... base64" vs. "with the corresponding
   BEGIN headers") was put back to the user rather than guessed at, since it governs wire
   compatibility with a real external system nothing here can verify against. Reconfirmed: the
   upstream expects **base64 of PEM text**, not base64 of the raw DER. Changed in
   `HttpDelegateIssuer.IssueAsync` (`PemEncoding.WriteString("CERTIFICATE REQUEST", ...)` before the
   outer base64), with matching updates to the outbound-contract tests, `FakeUpstreamCa` (the
   server-level stub upstream, which was decoding the field as raw DER and would otherwise have
   started failing every delegated-mode integration test), and the contract's documentation in
   [03-api-design.md](03-api-design.md), [04-issuance-providers.md](04-issuance-providers.md), and the
   [README](../README.md). One incidental finding worth recording: base64-of-PEM-text can *never*
   contain `+` or `/` in its output, for any input — every byte in PEM's character set has its
   high bit(s) constrained in a way that makes it mathematically impossible for any of the four
   base64 output symbols per input triplet to land on 62/63. That made the existing "JSON encoder
   doesn't escape `+`" regression test unwinnable through real CSR content under the new contract; it
   was rewritten to explain why rather than deleted outright.

7. **Helm: configurable `loadBalancerIP`, explicit `runAsUser`/`runAsGroup`.** `service.est.loadBalancerIP`
   added to [values.yaml](../helm/modest/values.yaml), templated into the EST `Service` only when set
   (`{{- with }}`, so `type: ClusterIP` deployments render unchanged). `podSecurityContext` now also
   pins `runAsUser`/`runAsGroup: 1654` alongside the existing `fsGroup` — same UID the image already
   defaults to, just enforced by the API server rather than only trusted from the image. Verified with
   `helm lint`/`helm template` (both value files, and `--set service.est.type=LoadBalancer
   --set service.est.loadBalancerIP=...`); not re-run against a live cluster since it reuses the
   `fsGroup` mechanism already proven in item 5 and doesn't change the effective runtime identity.

8. **Pushed to GitHub, CI confirmed green.** Created `waelchlis/modest` (public) with `gh repo create`,
   pushed as `main` (the workflow triggers on `main`; the local default was still `master` from `git
   init`, renamed and the old branch deleted from the remote), and watched the run —
   `Build, format, test` and `OpenSSL interop` both passed. Epic 1's Definition of Done ("CI is green")
   is now actually confirmed, not just locally simulated: https://github.com/waelchlis/modest/actions

## Open items

None outstanding from this handoff. Everything in "Not started" and "Next steps" as of 2026-08-24 has
been implemented and verified above.

## Next steps

Nothing blocking. Natural follow-ups if picked back up: a branch-protection rule requiring the CI
checks before merge, and eventually resolving the roadmap items already tracked in
[08-roadmap.md](08-roadmap.md) (channel binding, `/csrattrs` content, multi-CA labels, etc.) rather
than anything left over from this handoff.

## Running it locally

```bash
dotnet run --project src/Modest.Tooling -- init-ca --out ./ca --subject "CN=My EST CA"
```

Then follow the [README](../README.md) quickstart. A working smoke configuration — TLS certificate, Basic credential, both listeners — was assembled under the scratchpad during this session; it is not committed, but `init-ca` plus `hash-password` reproduce it in under a minute.
