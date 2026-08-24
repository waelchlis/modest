# Epic 1 — Repo Scaffolding & Tooling

**Depends on**: nothing. **Blocks**: everything else.

## Objective

Stand up the solution structure from [../07-project-structure.md](../07-project-structure.md) with a working build and CI pipeline, so every subsequent epic starts from a compiling, testable baseline instead of also having to invent plumbing.

## Tasks

1. **Git repo init.** The working directory is not currently a git repository — initialize it (`git init`), add a `.gitignore` for .NET (`bin/`, `obj/`, `*.user`, etc.), make an initial commit containing just `planning/` and the gitignore.
2. **`global.json`** at repo root pinning the installed .NET SDK's major version (`net10.0`, exact SDK version read from whatever `dotnet --version` reports in the build environment; `rollForward: latestFeature`).
3. **`Modest.sln`** created via `dotnet new sln`.
4. **Directory-level build config**:
   - `Directory.Build.props` — `<Nullable>enable</Nullable>`, `<ImplicitUsings>enable</ImplicitUsings>`, `<LangVersion>latest</LangVersion>`, `<TreatWarningsAsErrors>` scoped to the security/reliability analyzer categories per [../07-project-structure.md](../07-project-structure.md), `<GenerateDocumentationFile>` off (internal project, not a published library).
   - `Directory.Packages.props` — enable Central Package Management (`<ManagePackageVersionsCentrally>true</ManagePackageVersionsCentrally>`), pre-populate with the package list from [../07-project-structure.md](../07-project-structure.md) (versions resolved to latest stable compatible with `net10.0` at implementation time).
   - `.editorconfig` — standard .NET conventions (4-space indent, `file-scoped` namespaces, `var` preferences left permissive).
5. **Empty projects**, each created via `dotnet new classlib`/`dotnet new xunit`/`dotnet new web` as appropriate and added to the `.sln`, per the tree in [../07-project-structure.md](../07-project-structure.md):
   - `src/Modest.Core`
   - `src/Modest.Codec`
   - `src/Modest.Issuance.InternalCa`
   - `src/Modest.Issuance.HttpDelegate`
   - `src/Modest.Server` (ASP.NET Core web project)
   - `src/Modest.Tooling` (console app)
   - `tests/Modest.Codec.Tests`
   - `tests/Modest.Issuance.InternalCa.Tests`
   - `tests/Modest.Issuance.HttpDelegate.Tests`
   - `tests/Modest.Server.Tests`
   - `tests/Modest.Rfc7030.ComplianceTests`
   - `tests/Modest.TestSupport` (plain classlib, no test framework — shared fixtures referenced by other test projects)
   - Project references wired per the dependency diagram in [../02-architecture.md](../02-architecture.md): `Modest.Server` → `Modest.Core`, `Modest.Codec`, and (via DI, at runtime — but also a compile-time reference since v1 doesn't do plugin-style dynamic loading) both issuance projects; each issuance project → `Modest.Core` + `Modest.Codec`; test projects → their corresponding `src` project + `Modest.TestSupport`.
6. **CI pipeline** (GitHub Actions, assuming the repo will end up on GitHub — adjust if the user's actual git hosting differs): a single workflow, `build-and-test.yml`, running on push/PR: `dotnet restore`, `dotnet build --no-restore`, `dotnet format --verify-no-changes`, `dotnet test --no-build` with coverage collection (`coverlet.collector`), and a separate job (or step gated on an `openssl` availability check) for the interop tests from [../06-testing-strategy.md](../06-testing-strategy.md) §7.
7. **`Modest.TestSupport` fixture**: a `TestCertificateAuthority` helper class that generates, once per test run (or per test class via `IClassFixture`), a throwaway root CA cert + key, a server TLS cert signed by it, and one or more client certs signed by it (using `Modest.Codec`'s own building blocks once epic 2 exists — until then, a minimal standalone implementation using `CertificateRequest` directly is fine as a bootstrap, later refactored to reuse `Modest.Codec` once available). This is the single source of test PKI material for every later test project — building it once here avoids every later test project reinventing cert generation.

## Deliverables

- Buildable, empty solution: `dotnet build` succeeds, `dotnet test` runs (0 tests, green).
- CI pipeline green on the initial commit.
- `Modest.TestSupport.TestCertificateAuthority` available and unit-tested itself (it generates a valid self-signed CA, a valid leaf signed by it, chain validates).

## Definition of Done

- Fresh clone + `dotnet build` + `dotnet test` succeeds with zero manual setup steps beyond having the .NET 10 SDK installed.
- CI is green.
- No project in `src/` has a reference to a test project or to `Modest.TestSupport` (keeps the dependency direction clean going forward).
