# Modest

A modular EST server (RFC 7030) in .NET 10. See [README.md](README.md) for what it does and how to run it.

## Architecture rule

The HTTP layer never touches a CA key. It talks to `ICertificateIssuer` in `Modest.Core`. Two
implementations exist: `Modest.Issuance.InternalCa` (holds a CA key) and
`Modest.Issuance.HttpDelegate` (forwards CSRs to an external PKI, holds no key). Keep this boundary
intact — don't let `Modest.Server` or `Modest.Core` depend on crypto/HTTP specifics of either
provider.

## Project layout

- `Modest.Core` — contracts and domain types. No ASP.NET Core, no I/O, no third-party deps beyond BCL.
- `Modest.Codec` — PKCS#10/PKCS#7/CsrAttrs wire format encode/decode.
- `Modest.Issuance.InternalCa` / `Modest.Issuance.HttpDelegate` — the two issuer implementations.
- `Modest.Server` — ASP.NET Core host, the deployable app.
- `Modest.Tooling` — CLI (init-ca, hash-password, etc.), kept out of the server image.
- `tests/` mirrors `src/` one-to-one, plus `Modest.TestSupport` (shared fixtures) and
  `Modest.Rfc7030.ComplianceTests` (traceability matrix back to RFC sections).
- `planning/` — design docs and `STATUS.md`, a dated handoff log. Check `STATUS.md` for the latest
  known state before assuming something is or isn't done.

Details and rationale: [planning/07-project-structure.md](planning/07-project-structure.md).

## Conventions

- Nullable reference types enabled everywhere. Keep new code nullable-clean.
- File-scoped namespaces, `using` directives outside the namespace (enforced by `.editorconfig`).
- Central Package Management: add package versions to `Directory.Packages.props`, not individual `.csproj` files.
- Security/reliability analyzer categories (CA23xx, CA53xx) are errors, not warnings — this is a PKI codebase. Don't suppress them without a documented reason.
- Secret material flows through config as file paths, never inline values. Follow this pattern for any new secret/key config.

## Testing

```bash
dotnet test
```

Some tests shell out to `openssl` for independent cross-checking and skip cleanly if it's missing.
When adding codec or protocol tests, prefer checking against real `openssl`/`curl` behavior over
only round-tripping through Modest's own encoder — a self-consistent bug is invisible otherwise.

## Docs

**Whenever you make a meaningful change (new feature, behavior change, new script/tool, status
change), update [README.md](README.md) to match.** Also update `planning/STATUS.md` for notable
implementation milestones, and the relevant `planning/0X-*.md` doc if the change affects architecture
or design decisions made there.
