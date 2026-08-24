# Epic 3 — Internal CA Issuer

**Depends on**: 1 (scaffolding), 2 (codec). **Blocks**: 4 (server core needs at least one working issuer to be end-to-end testable).

## Objective

Implement `Modest.Issuance.InternalCa`, the `ICertificateIssuer` implementation that signs CSRs with a locally held CA keypair, per [../04-issuance-providers.md](../04-issuance-providers.md).

## Deliverables

In `src/Modest.Issuance.InternalCa`, namespace `Modest.Issuance.InternalCa`:

- `InternalCaOptions` — bound from config (`Issuance:InternalCa:*`): `CertificatePath` (PFX), `CertificatePasswordFile`, `SignatureAlgorithm` (default SHA-256), `AllowedKeyAlgorithms` (RSA-2048+/EC P-256/P-384 default allow-list), `ValidityPeriod` (leaf cert lifetime), `AdditionalChainCertificatePaths` (intermediates to include in `/cacerts` and enrollment responses beyond the CA cert itself).
- `InternalCaIssuer : ICertificateIssuer` — loads the CA `X509Certificate2` + chain at construction (via a small `CaKeyLoader` helper, see below); implements `IssueAsync` and `GetCaChainAsync` per the behavior in [../04-issuance-providers.md](../04-issuance-providers.md): parse (via `Modest.Codec.Pkcs10CsrReader`, reusing epic 2's proof-of-possession-verifying parse — **not** re-implemented here), policy-check key algorithm/size, build the leaf via `CertificateRequest.Create` + `X509SignatureGenerator`, set extensions (Basic Constraints CA:false, Key Usage, EKU per config — default `clientAuth`, SKI, AKI), random 20-byte serial per [../09-open-questions.md](../09-open-questions.md) #12.
- `CaKeyLoader` — loads the PFX from `CertificatePath` using the password read from `CertificatePasswordFile`; throws a distinct `CaKeyLoadException` on any failure (missing file, bad password, key doesn't support signing) so `Program.cs` (epic 4) can catch this specifically and fail startup with a clear operator-facing message rather than a generic crash trace. Also checks (POSIX-only, best-effort) the key file's permission bits and logs a warning if group/world-readable, per [../05-security.md](../05-security.md) — does not fail startup on this, only warns.
- DI registration extension: `IServiceCollection.AddInternalCaIssuer(IConfiguration)`.

## Tasks

1. `InternalCaOptions` + config binding + validation (e.g. `AllowedKeyAlgorithms` non-empty, `ValidityPeriod` positive) via `AddValidation()`/`IValidateOptions`.
2. `CaKeyLoader`: load PFX+password, unit tests for success, missing file, wrong password, and (where feasible in a cross-platform test) the permission-warning path.
3. `InternalCaIssuer.GetCaChainAsync`: returns CA cert + configured additional chain certs, unit tested.
4. `InternalCaIssuer.IssueAsync` happy path: valid CSR in → `Issued` out with correct issuer DN, validity window, extensions; test both RSA and ECDSA input CSRs (reuses `Modest.TestSupport` for generating input CSRs, and/or `Modest.Codec` helpers).
5. `InternalCaIssuer.IssueAsync` policy rejection: CSR with a disallowed key size/algorithm → `Rejected(..., InvalidCsr)`, tested for at least one below-minimum RSA case and one disallowed-curve case.
6. Serial number test: issue N certs, assert all serials distinct and each is a random-looking 20-byte value (not sequential), per [../06-testing-strategy.md](../06-testing-strategy.md) §2.
7. `AddInternalCaIssuer` DI extension + a small "can construct via DI from config" smoke test.

## Definition of Done

- All tasks tested per [../06-testing-strategy.md](../06-testing-strategy.md) §2.
- Startup-time failure behavior (fail-closed, per [../05-security.md](../05-security.md)) is verified: a deliberately broken PFX config causes `CaKeyLoader`/DI registration to throw in a way `Program.cs` can catch and exit non-zero with a clear message — this contract is what epic 4 will build its startup error handling against, so it should be a stable, tested exception type/message shape by the end of this epic.
- No test or code path anywhere logs the CA private key or the PFX password.
