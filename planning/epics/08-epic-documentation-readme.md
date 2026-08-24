# Epic 8 — Documentation & README

**Depends on**: all prior epics (documents the finished system — can be drafted incrementally alongside earlier epics rather than strictly held to the end, but finalized last).

## Objective

Produce the project root `README.md` (explicitly requested by the user) plus any small chart-local documentation from epic 7. The README is the first thing anyone (including future-you) reads to understand what Modest is, how to run it in either mode, and where its boundaries are.

## Deliverables

**`/README.md`** (repo root), sections:

1. **What is Modest** — one paragraph: modular RFC 7030 EST server, .NET 10, internal-CA or HTTP-delegated issuance. Link to `planning/` for the full design docs (this README is the practical quickstart/reference, not a restatement of the whole design — link out rather than duplicate).
2. **Status/scope** — which EST operations are implemented (`/cacerts`, `/simpleenroll`, `/simplereenroll`, `/csrattrs`) and which are explicitly not (`/fullcmc`, `/serverkeygen`), pointing at [planning/01-rfc7030-reference.md](../01-rfc7030-reference.md)'s deviation table for the full detail rather than re-deriving it.
3. **Quickstart — Internal CA mode**: generate a dev CA via `Modest.Tooling` (once it exists, epic 3), minimal `appsettings`/env config, run, `curl`/`openssl` example hitting `/cacerts` and `/simpleenroll`.
4. **Quickstart — HTTP Delegated mode**: minimal config pointing at an external issuance API, note on the exact JSON contract (`{"CSR": "<base64 DER, unwrapped>"}` request / `{"certificate": "<PEM>", "issuer": "<PEM chain, intermediate+root, no leaf>"}` response, HTTP Basic auth to the upstream) — this is the one section most likely to be read by someone integrating their *own* upstream issuance API, so it should state the contract precisely and reference [planning/06-epic-http-delegated-issuer.md](06-epic-http-delegated-issuer.md)'s confirmed-contract section as the source of truth.
5. **Configuration reference** — table of all config keys introduced across epics 3/4/5/6 (`Issuance:Mode`, `Issuance:InternalCa:*`, `Issuance:HttpDelegate:*`, `Issuance:Reenrollment:RequireMatchingIdentity`, Kestrel dual-listener ports, Basic-auth-inbound credential config), with a short description and default for each — generated/maintained by hand as each epic lands, not auto-generated, since keeping this accurate is part of each epic's "done" bar going forward (worth adding as a line item to the Definition of Done template for future epics, though not retroactively enforced on epics 1–7 above since they predate this note).
6. **Authentication** — summary of client-cert vs Basic auth support for EST clients (inbound), linking [planning/05-security.md](../05-security.md).
7. **Deployment** — Docker quickstart + Helm chart usage (`helm install` example with both values overlays from epic 7), linking the chart-local README for full detail.
8. **Testing** — how to run the test suite (`dotnet test`), what the RFC-compliance-tagged tests are and how to filter to them (`dotnet test --filter Rfc7030Section=...`), note on the `openssl`-dependent interop tests needing `openssl` on `PATH`.
9. **Roadmap / known limitations** — short list pulled from [planning/08-roadmap.md](../08-roadmap.md)'s post-v1 backlog, explicitly including the confirmed-but-deferred `/csrattrs` hinting extension point from [planning/09-open-questions.md](../09-open-questions.md) #7 (the user specifically asked for this to be kept in mind and noted in the README).
10. **Contributing / license** — placeholder sections (license choice is the user's call, not assumed here — leave a `TODO: choose a license` marker rather than picking one unilaterally).

**`helm/modest/README.md`** (chart-local, from epic 7): values reference specific to the chart, install/upgrade/uninstall commands, the two example overlays explained.

## Tasks

1. Draft root `README.md` structure (sections 1–2, 9–10) early — doesn't depend on implementation being finished, can happen right after the epics themselves are written, to serve as a living document updated as each epic lands.
2. Fill in sections 3–4 (quickstarts) once epics 3/4/5/6 land and their actual config shape/CLI commands are known — write these against the real, tested config schema, not the planning-doc sketch, since config field names are exactly the kind of detail that drifts between plan and implementation.
3. Fill in section 5 (config reference table) incrementally, one row per epic, as each epic's `*Options` classes are finalized.
4. Fill in sections 6–8 once epics 4/5/7 land.
5. Write `helm/modest/README.md` alongside epic 7.
6. Final pass: read the whole README fresh, as if new to the project, and confirm every command/example in it has actually been run against the real implementation (not just written to look plausible) — README examples that don't actually work are worse than no README.

## Definition of Done

- `README.md` exists at repo root, every section populated (no lingering "TBD" except the deliberate license placeholder).
- Every shell command/config snippet in the README has been manually verified to work against the actual built project.
- `helm/modest/README.md` exists and matches the chart as actually shipped in epic 7.
