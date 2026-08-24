# Project Structure

## Solution layout

```
modest/
├── planning/                          # this folder
├── Modest.sln
├── global.json                        # pins .NET SDK version (10.0.x)
├── Directory.Build.props              # shared props: nullable enable, langversion, analyzers
├── Directory.Packages.props           # central package version management (CPM)
├── .editorconfig
├── src/
│   ├── Modest.Core/                   # contracts, domain types — no ASP.NET Core, no I/O
│   │   └── Modest.Core.csproj
│   ├── Modest.Codec/                  # PKCS#10/PKCS#7/CsrAttrs encode-decode
│   │   └── Modest.Codec.csproj
│   ├── Modest.Issuance.InternalCa/
│   │   └── Modest.Issuance.InternalCa.csproj
│   ├── Modest.Issuance.HttpDelegate/
│   │   └── Modest.Issuance.HttpDelegate.csproj
│   ├── Modest.Server/                 # ASP.NET Core host — the deployable app
│   │   ├── Program.cs
│   │   ├── appsettings.json
│   │   ├── appsettings.Development.json
│   │   └── Modest.Server.csproj
│   └── Modest.Tooling/                # CLI: generate dev CA, inspect CSR, etc.
│       └── Modest.Tooling.csproj
├── tests/
│   ├── Modest.Codec.Tests/
│   ├── Modest.Issuance.InternalCa.Tests/
│   ├── Modest.Issuance.HttpDelegate.Tests/
│   ├── Modest.Server.Tests/            # integration tests, WebApplicationFactory
│   ├── Modest.Rfc7030.ComplianceTests/ # tagged compliance matrix, see 06-testing-strategy.md
│   └── Modest.TestSupport/             # shared fixtures: test CA, cert generation helpers
├── docker/
│   └── Dockerfile
└── README.md
```

## Why this split (recap, ties back to [02-architecture.md](02-architecture.md))

- `Modest.Core` has zero third-party or ASP.NET Core dependencies beyond the BCL — it's the stable contract both issuance providers and the server compile against. Keeping it dependency-free is what makes "swap the issuer" a real, enforced architectural property rather than an aspiration.
- `Modest.Codec` is separated from `Modest.Core` because it's a wire-format implementation detail (how bytes look on the HTTP surface), whereas `Modest.Core` is domain/contract shape. `Modest.Server` and both issuance test projects can depend on `Modest.Codec` for building test fixtures without needing a full server.
- Each issuance provider is its own project/package so that a deployment that only needs one mode doesn't have to ship (or trust) the dependencies of the other — e.g. an internal-CA-only deployment doesn't need `System.Net.Http`-heavy resilience packages pulled in by the HTTP delegate provider, and vice versa doesn't need the CA's crypto surface loaded.
- `Modest.Tooling` is separate from `Modest.Server` so the runtime server image doesn't carry CLI/dev-only tooling.

## Target framework & tooling

- **Target Framework**: `net10.0`, pinned via `global.json` (`"sdk": { "version": "10.0.100", "rollForward": "latestFeature" }` — exact version to be filled in once the environment's installed SDK is confirmed).
- **Nullable reference types**: enabled solution-wide (`Directory.Build.props`).
- **Central Package Management** (`Directory.Packages.props`): all package versions pinned in one place, `csproj` files reference packages without versions — reduces drift risk across ~10 projects.
- **Analyzers**: `Microsoft.CodeAnalysis.NetAnalyzers` (built into the SDK) at a `warning`-as-error level for the `Security` and `Reliability` rule categories at minimum, given this is a security-sensitive codebase.
- **Formatting**: `dotnet format` + `.editorconfig`, checked in CI (not auto-fixed silently).

## Key NuGet packages (indicative, finalize versions at implementation time)

| Package | Used by | Purpose |
|---|---|---|
| `System.Security.Cryptography.Pkcs` | `Modest.Codec` | CMS/PKCS#7 `SignedData` build & parse |
| `Microsoft.Extensions.Http.Resilience` | `Modest.Issuance.HttpDelegate` | Retry/timeout/circuit-breaker for the upstream HTTP call |
| `Serilog.AspNetCore` (or built-in `Microsoft.Extensions.Logging` + structured console) | `Modest.Server` | Structured audit logging, see [05-security.md](05-security.md) |
| `xunit`, `xunit.runner.visualstudio` | all `*.Tests` | test framework |
| `FluentAssertions` | all `*.Tests` | assertions |
| `WireMock.Net` | `Modest.Issuance.HttpDelegate.Tests` | mock upstream HTTP API |
| `Microsoft.AspNetCore.Mvc.Testing` | `Modest.Server.Tests` | in-process host + TLS integration tests |
| `coverlet.collector` | all `*.Tests` | coverage collection |

No third-party crypto libraries (e.g. BouncyCastle) planned for v1 — .NET 10's `System.Security.Cryptography` + `System.Security.Cryptography.Pkcs` + `System.Formats.Asn1` cover PKCS#10/PKCS#7/CMS needs natively and cross-platform (confirmed via research, see sources in the session). BouncyCastle stays a documented fallback option if a specific ASN.1 corner (e.g. some obscure attribute) turns out to be awkward in the BCL — noted in [09-open-questions.md](09-open-questions.md) as something to revisit only if it becomes a real blocker during implementation.

## Configuration & secrets

- `appsettings.json` for structure/defaults, `appsettings.{Environment}.json` for environment overrides, environment variables for deployment-time overrides (standard ASP.NET Core config layering) — but **secret file paths, not secret values**, flow through this layering (see [05-security.md](05-security.md) on why key/password material is file-path-indirected rather than inline).
- `dotnet user-secrets` for local development convenience only, never referenced in any deployment path.

## Container/deployment shape

- Multi-stage `Dockerfile`: SDK image builds, runtime image is `mcr.microsoft.com/dotnet/aspnet:10.0` (or the `chiseled`/distroless variant for a smaller attack surface, worth evaluating once the base functionality is solid).
- Config + key/cert material mounted as volumes, not baked into the image.
- Exposes the EST HTTPS port + the `/healthz`/`/readyz` ops port (can be the same port; kept as an open question for whether ops endpoints should be split onto a separate internal-only listener — see [09-open-questions.md](09-open-questions.md)).
