# Modest — Project Overview

## What this is

**Modest** is a modular EST (Enrollment over Secure Transport, [RFC 7030](https://www.rfc-editor.org/rfc/rfc7030)) server written in .NET 10. It implements the standard EST HTTP endpoints under `/.well-known/est` and separates *protocol handling* from *certificate issuance*. Issuance is a pluggable concern: the server can sign certificates itself with a locally held CA keypair, or it can delegate signing to an external system over a simple HTTP/JSON API.

The name is a play on "EST" — a small, well-behaved, well-tested implementation, not a full-featured CA product.

## Goals

1. **Protocol-correct RFC 7030 server** — implement the mandatory operations (`/cacerts`, `/simpleenroll`, `/simplereenroll`, `/csrattrs`) correctly enough to interoperate with real EST clients (e.g. `openssl`, Cisco/network-device EST clients, `libest`-based clients, `estclient` tooling).
2. **Modular issuance** — the HTTP/EST layer never talks to key material directly. It talks to an `ICertificateIssuer` abstraction. Two implementations ship in v1:
   - **Internal CA** — Modest owns an RSA/ECDSA CA keypair and self-issues leaf certificates.
   - **HTTP Delegated Issuer** — Modest forwards the CSR (base64) to an external HTTP API and turns the JSON response (PEM cert + PEM chain) back into the CMS/PKCS#7 response EST requires.
3. **Testable by construction** — every layer (codec, auth, issuance, HTTP surface) is designed to be tested in isolation, plus end-to-end RFC-compliance tests that exercise the wire protocol exactly as a real EST client would.
4. **Runs on .NET 10 (LTS)**, cross-platform (Linux-first, since that's the deployment target for most EST server use cases — network device provisioning, IoT fleets), no Windows-only certificate store dependencies.

## Non-goals for v1

- **Full CMC** (`/fullcmc`) — out of scope. RFC 7030 makes this optional; `/simpleenroll` + `/simplereenroll` are the mandatory-to-implement operations for a "Simple" EST server profile.
- **Server-side key generation** (`/serverkeygen`) — out of scope for v1, documented as a future extension point (see [08-roadmap.md](08-roadmap.md)).
- **TLS-SRP / certificate-less bootstrap cipher suites** — not supported by .NET's TLS stack (SslStream does not expose SRP); bootstrap trust is instead handled via the standard "unauthenticated `/cacerts` + out-of-band fingerprint" flow, which RFC 7030 explicitly allows as an alternative (§4.1.1).
- **Multi-CA labelled endpoints** (`/.well-known/est/{label}/...`) — architecture should not preclude this later, but v1 ships a single default CA/issuer configuration.
- **HSM / cloud KMS integration** for the internal CA — v1 stores the CA key as a local PFX/PEM (password-protected); the signing operation is abstracted behind an interface so a KMS-backed implementation can be swapped in without touching the EST layer.

## Why "modular issuance" matters

Real deployments rarely want a bare EST server holding the only copy of a CA private key. Enterprises typically have an existing PKI (Microsoft ADCS, EJBCA, Venafi, HashiCorp Vault PKI secrets engine, a custom internal signing service) and want EST as a *front door protocol adapter* onto that PKI. By defining the issuance boundary as "send me a CSR, give me back a cert + chain," Modest can sit in front of virtually any CA that can expose (or be fronted by) an HTTP JSON endpoint, while still being usable standalone (internal CA mode) for labs, testing, and small deployments.

## Reading order for this plan

1. [01-rfc7030-reference.md](01-rfc7030-reference.md) — distilled protocol reference used as the implementation's source of truth.
2. [02-architecture.md](02-architecture.md) — module boundaries, the `ICertificateIssuer` contract, request/response pipeline.
3. [03-api-design.md](03-api-design.md) — concrete ASP.NET Core endpoint design, DTOs, content negotiation.
4. [04-issuance-providers.md](04-issuance-providers.md) — internal CA and HTTP delegated issuer, in detail.
5. [05-security.md](05-security.md) — TLS/mTLS, authN/authZ, key handling, threat model.
6. [06-testing-strategy.md](06-testing-strategy.md) — test pyramid and RFC-compliance test matrix.
7. [07-project-structure.md](07-project-structure.md) — solution layout, packages, tooling.
8. [08-roadmap.md](08-roadmap.md) — phased delivery plan.
9. [09-open-questions.md](09-open-questions.md) — decisions that need the user's input before/while building.
