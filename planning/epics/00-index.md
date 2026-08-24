# Implementation Epics — Index

This folder turns the design in `planning/*.md` into an ordered, actionable implementation plan. Each epic is a self-contained unit of work with concrete deliverables, tasks, and a Definition of Done. Epics are meant to be worked roughly in order — later epics depend on earlier ones being done, per the dependency graph below — but each one leaves the repo in a buildable, green-tests state on its own (same principle as the phases in [../08-roadmap.md](../08-roadmap.md), which this plan supersedes with concrete detail and the confirmed answers from [../09-open-questions.md](../09-open-questions.md)).

## How the confirmed answers changed the plan

[../09-open-questions.md](../09-open-questions.md) is now filled in by the user. A few answers are **not** just "confirm the default" — they change scope versus what [../08-roadmap.md](../08-roadmap.md) originally deferred. These are called out explicitly in their owning epic, but summarized here for visibility:

| Question | Answer | Effect |
|---|---|---|
| #1 CSR encoding to upstream | Raw DER, base64-encoded | Confirms the default in [04-issuance-providers.md](../04-issuance-providers.md); one wrinkle noted in [06-epic-http-delegated-issuer.md](06-epic-http-delegated-issuer.md) — the answer's phrasing also mentions PEM headers, which is contradictory for "raw DER"; flagged for a quick real-upstream check, doesn't block building against the documented contract |
| #2 `issuer` field content | Root+intermediates only, guaranteed order, **no leaf** | Confirms default; codec/parsing logic doesn't need to defensively strip a leaf |
| #3 Outbound auth to upstream | **HTTP Basic auth**, not API-key header | Changes `Modest.Issuance.HttpDelegate`'s HTTP client config from a generic header to a `Basic` `Authorization` header specifically — see epic 6 |
| #4 Upstream sync/async | Always synchronous | Confirms default; no async issuer work needed for delegated mode |
| #5 `/cacerts` chain source (delegate mode) | Static config | Confirms default |
| #6 Digest auth | Not required | Confirms default (skip) |
| #7 `/csrattrs` future hinting | Deferred, but **document the extension point in the README** | New README task, see epic 8 |
| #8 Re-enrollment identity check | **Required**, must match client cert subject *and all SANs* against the CSR, **configurable on/off** | Upgrades this from "left to policy" (original plan) to a **built-in, shipped v1 feature** with a settings toggle — new work in epic 5, not deferred |
| #9 Ops endpoint exposure | **Separate plain-HTTP listener** | Changes Kestrel endpoint config in epic 4 — two listeners, not one |
| #10 Deployment target | **Kubernetes via Helm chart** | Adds a Helm chart deliverable to epic 7, beyond the Dockerfile the original plan scoped |
| #11 BouncyCastle | Not needed | Confirms BCL-only approach |
| #12 Serial number scheme | No opinion | Confirms default (random 20-byte) |

## Epics

| # | Epic | Depends on | Maps to roadmap phase(s) |
|---|---|---|---|
| 1 | [Repo scaffolding & tooling](01-epic-scaffolding.md) | — | Phase 0 |
| 2 | [Codec (PKCS#10/PKCS#7/CsrAttrs)](02-epic-codec.md) | 1 | Phase 1 |
| 3 | [Internal CA issuer](03-epic-internal-ca-issuer.md) | 1, 2 | Phase 2 |
| 4 | [Server core: TLS, auth, dual listeners, bootstrap endpoints](04-epic-server-core-and-bootstrap-endpoints.md) | 1, 2, 3 | Phase 3 |
| 5 | [Enrollment endpoints + re-enrollment identity check](05-epic-enrollment-endpoints.md) | 4 | Phase 4 (+ new scope from Q8) |
| 6 | [HTTP delegated issuer](06-epic-http-delegated-issuer.md) | 1, 2 | Phase 5 |
| 7 | [Hardening, container image & Helm chart](07-epic-ops-hardening-helm.md) | 4, 5, 6 | Phase 6 (+ new scope from Q10) |
| 8 | [Documentation & README](08-epic-documentation-readme.md) | all | new (not in original roadmap as a discrete phase) |

## Dependency graph

```
1 (scaffolding)
 ├─→ 2 (codec)
 │    ├─→ 3 (internal CA issuer) ─┐
 │    └─→ 6 (HTTP delegated issuer) ─┤
 │                                   ├─→ 4 (server core) ─→ 5 (enrollment) ─┐
 │                                   │                                     ├─→ 7 (hardening/Helm) ─→ 8 (docs)
 └───────────────────────────────────┴─────────────────────────────────────┘
```

Epics 3 and 6 (the two issuers) have no dependency on each other and can be built in either order, or in parallel by different contributors — both only depend on epic 2 (codec) for shared CSR/cert handling helpers and on epic 1 for project scaffolding. Epic 4 (server core) needs *at least one* issuer to exist to be testable end-to-end, but its auth/TLS/routing work can start against a trivial fake `ICertificateIssuer` before either real issuer is finished, if parallelizing.

## Definition of Done, applied at every epic

Carried over from [../06-testing-strategy.md](../06-testing-strategy.md) and restated per-epic so it isn't missed: an epic is not done when the code compiles, it's done when its unit/integration tests (as listed in that epic) pass in CI, and — where the epic touches wire format — the relevant RFC-compliance-tagged tests pass too.
