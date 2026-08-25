# Extra build-time trust anchors

Empty by default. On a network that intercepts outbound TLS (a corporate proxy doing MITM
inspection), `dotnet restore` inside the build stage fails with `NU1301 ... UntrustedRoot` because
the interception CA isn't in the SDK image's trust store.

To fix that for a local build, drop the intercepting proxy's root CA certificate(s) here as `.crt`
files (PEM-encoded) before running `docker build`. The Dockerfile copies whatever is in this
directory into the build stage and runs `update-ca-certificates` before `dotnet restore`. On a
network with no interception, leave this directory empty — the copy and the trust-store update are
both no-ops.

Nothing here is tracked by git except this file and `.gitkeep` (see `.gitignore`) — these are
environment-specific and not something the repository should ship a default for.
