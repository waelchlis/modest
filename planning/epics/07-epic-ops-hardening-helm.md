# Epic 7 — Hardening, Container Image & Helm Chart

**Depends on**: 4, 5, 6 (the full protocol surface and both issuers). **Blocks**: 8 (README documents the deployment artifacts this epic produces).

## Objective

Make Modest deployable and operable, targeting **Kubernetes via a Helm chart** specifically (per [../09-open-questions.md](../09-open-questions.md) #10 — this is more scope than the original roadmap's "Dockerfile + container smoke test," which assumed the deployment target was still open), and close out the security hardening pass from [../05-security.md](../05-security.md).

## Deliverables

- **`docker/Dockerfile`** — multi-stage build, SDK image → `mcr.microsoft.com/dotnet/aspnet:10.0` runtime (evaluate the chiseled/distroless variant per [../07-project-structure.md](../07-project-structure.md); adopt it if it doesn't complicate the file-permission-check logic from epic 3 — chiseled images run as non-root by default, which is a genuine benefit worth confirming compatibility with rather than assuming). Runs as non-root. No secrets baked in — CA key/cert, TLS cert, and any auth secrets are all expected to be mounted at runtime paths matching the config structure from earlier epics.
- **`helm/modest/`** chart:
  - `Chart.yaml`, `values.yaml` (defaults for image repo/tag, resource requests/limits, service ports matching the dual-listener design from epic 4, issuance mode + provider-specific config as Helm values with secret references rather than inline secret values).
  - `templates/deployment.yaml` — mounts CA/TLS/auth secrets as volumes (from `Secret` resources, referenced by name so operators bring their own secret rather than the chart generating/storing one), exposes both the EST port and the ops port as container ports.
  - `templates/service.yaml` — two `Service` objects (or one with two ports) matching the dual-listener split — EST service (TLS, likely `LoadBalancer`/`ClusterIP` depending on how the operator fronts it) and an ops-only service (`ClusterIP`, used by probes and optionally by an internal monitoring scrape).
  - `templates/deployment.yaml` liveness/readiness probes wired to `/healthz`/`/readyz` on the **ops port specifically** (plain HTTP, no TLS — this is the entire reason epic 4 built the split listener; get this wrong and the whole point of that design decision is lost).
  - `templates/secret.yaml` — **not** used to generate secrets from chart values in cleartext; if the chart needs to reference operator-provided secrets, do so via `existingSecret` value patterns (Helm best practice: the chart references a `Secret` name the operator creates out-of-band, rather than the chart templating secret *values* into rendered YAML that ends up in `helm template`/`helm get` output or a Git-committed values file).
  - `templates/configmap.yaml` — non-secret config (issuance mode, timeouts, allowed key algorithms, etc.) as a `ConfigMap`, mounted or projected as environment variables/config file per ASP.NET Core's standard config-layering.
  - `templates/NOTES.txt` — post-install guidance (how to fetch `/cacerts`, where logs go, how to check readiness).
  - `values-internalca.yaml` and `values-httpdelegate.yaml` — example values overlays for each issuance mode, since the two modes need genuinely different config shapes (CA PFX secret vs. upstream URL+Basic-auth secret) — having both as ready-to-adapt examples is worth the small duplication for an operator trying the project for the first time.
- **Security hardening pass** against [../05-security.md](../05-security.md)'s threat model table: verify each mitigation is actually implemented as described (not just planned) — CA key never logged, Basic auth password never logged, fail-closed startup, oversized-body rejection, TLS version floor — this is a checklist review task against existing code from prior epics, not new feature work, but budgeted as its own task here so it doesn't get silently skipped.
- **Container smoke test**: a CI step (or documented manual step if CI runtime constraints make a full k8s-in-CI setup impractical for v1 — e.g. via `kind`/`k3d` if budget allows, otherwise `docker run` + `curl`/`openssl s_client` against the running container is an acceptable minimum) confirming the built image actually starts and serves `/cacerts` and `/healthz`.

## Tasks

1. Write `Dockerfile`, build locally, confirm image size/non-root operation.
2. Container smoke test (local `docker run`, curl the ops port's `/healthz`, `openssl s_client`/`curl --cacert` against the EST port's `/cacerts`).
3. Helm chart authoring per the template list above, for **both** issuance modes (two values overlays).
4. `helm lint` and `helm template` clean runs in CI as a lightweight validation (doesn't require a real cluster, catches templating errors and, importantly, catches any accidental inline-secret-in-rendered-output regression via a grep step over `helm template` output for suspicious patterns).
5. If a `kind`/`k3d` CI job is in scope: a real `helm install` + rollout-wait + `kubectl exec`/port-forward smoke test against the running pod, both issuance modes. If out of scope for time, document the manual equivalent steps in the chart's `README.md` (chart-local readme, distinct from the project root README in epic 8) so a human can run it before a release.
6. Security hardening checklist pass against [../05-security.md](../05-security.md), one line per threat-model row confirming implemented/verified, with any gaps found fixed here rather than deferred silently.

## Definition of Done

- Docker image builds, runs, and passes the smoke test.
- `helm lint`/`helm template` pass in CI for both values overlays.
- No secret value ever appears in `helm template` rendered output (verified by the CI grep step in task 4) — only `existingSecret` references.
- Security hardening checklist fully reviewed with all gaps either closed or explicitly and consciously deferred to [../08-roadmap.md](../08-roadmap.md)'s post-v1 backlog (not silently dropped).
