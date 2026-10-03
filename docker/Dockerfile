# syntax=docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e

FROM mcr.microsoft.com/dotnet/sdk:11.0@sha256:78559d13d8c810bfe87f329168739ae2ee31f402b1e2c66353d3ff9744d68520 AS build
WORKDIR /src

# Extra trust anchors for networks that intercept outbound TLS (see docker/ca-certificates/README.md
# and planning/STATUS.md) — empty by default, so this is a no-op everywhere else. Must run before
# `dotnet restore` reaches out to nuget.org, or an intercepting proxy's substituted certificate fails
# as NU1301 UntrustedRoot.
COPY docker/ca-certificates/ /usr/local/share/ca-certificates/extra/
RUN update-ca-certificates

# Restore against the manifests alone so the layer caches across source edits.
COPY global.json Directory.Build.props Directory.Packages.props Modest.slnx ./
COPY src/Modest.Core/Modest.Core.csproj                             src/Modest.Core/
COPY src/Modest.Codec/Modest.Codec.csproj                           src/Modest.Codec/
COPY src/Modest.Issuance.InternalCa/Modest.Issuance.InternalCa.csproj src/Modest.Issuance.InternalCa/
COPY src/Modest.Issuance.HttpDelegate/Modest.Issuance.HttpDelegate.csproj src/Modest.Issuance.HttpDelegate/
COPY src/Modest.Server/Modest.Server.csproj                         src/Modest.Server/
COPY src/Modest.Tooling/Modest.Tooling.csproj                       src/Modest.Tooling/
RUN dotnet restore src/Modest.Server/Modest.Server.csproj \
 && dotnet restore src/Modest.Tooling/Modest.Tooling.csproj

COPY src/ src/
RUN dotnet publish src/Modest.Server/Modest.Server.csproj -c Release -o /app/server --no-restore \
 && dotnet publish src/Modest.Tooling/Modest.Tooling.csproj -c Release -o /app/tooling --no-restore

# Chiselled runtime: no shell and no package manager, and it runs as a non-root user by default.
FROM mcr.microsoft.com/dotnet/aspnet:10.0-noble-chiseled@sha256:48e51f2f6798897be7ac4e775c049ed8fe60d3190f637e1f9c9dc7513efa659c AS runtime
WORKDIR /app

COPY --from=build /app/server ./
COPY --from=build /app/tooling ./tooling/

# EST over TLS, and health probes over plain HTTP. Kept on separate listeners so a Kubernetes
# kubelet can probe without a TLS or client-certificate handshake.
EXPOSE 8443
EXPOSE 8080

# No key material is baked in. The CA PFX, its password, the TLS certificate and any upstream
# credential are all mounted at runtime.
ENV DOTNET_EnableDiagnostics=0

USER $APP_UID

ENTRYPOINT ["./Modest.Server"]
