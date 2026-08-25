# Modest

A modular EST server — [RFC 7030](https://www.rfc-editor.org/rfc/rfc7030), Enrollment over Secure Transport — written in .NET 10.

Modest separates the EST protocol from certificate issuance. The HTTP layer never touches a CA key; it talks to an `ICertificateIssuer`. Two implementations ship:

- **Internal CA** — Modest signs with a CA keypair it holds.
- **HTTP delegate** — Modest forwards the CSR to an existing PKI over a small JSON API and holds no key at all.

That second mode is the point of the project. Most organisations already have a CA — ADCS, EJBCA, Vault, something bespoke — and want EST as a protocol front door onto it rather than another place a private key lives.

## Status

| Operation | Path | Status |
|---|---|---|
| CA certificates | `GET /.well-known/est/cacerts` | implemented |
| Simple enroll | `POST /.well-known/est/simpleenroll` | implemented |
| Simple re-enroll | `POST /.well-known/est/simplereenroll` | implemented |
| CSR attributes | `GET /.well-known/est/csrattrs` | implemented (returns 204) |
| Full CMC | `/fullcmc` | not implemented |
| Server-side key generation | `/serverkeygen` | not implemented |

`/fullcmc` and `/serverkeygen` are optional in RFC 7030. The four implemented operations are the "Simple EST" subset that real clients — network devices, IoT provisioning agents, `openssl`-driven scripts — actually use.

Deliberate deviations from the RFC (TLS 1.2 floor rather than 1.1, no HTTP Digest, no TLS-SRP bootstrap, no `tls-unique` channel binding) are listed with their reasons in [planning/01-rfc7030-reference.md](planning/01-rfc7030-reference.md#10-summary-of-deliberate-deviations-from-strict-rfc-7030).

## Quickstart — internal CA

```bash
dotnet run --project src/Modest.Tooling -- init-ca --out ./ca --subject "CN=My EST CA"
```

That writes `ca.pfx`, `ca.pfx.pass` and `ca.crt`, restricted to the owner. Add a client credential:

```bash
dotnet run --project src/Modest.Tooling -- hash-password --username device --password 's3cret'
```

Put the printed block into `Authentication:BasicCredentials`, point `Issuance:InternalCa:*` at the CA files, give Kestrel a TLS certificate, and run the server. Then enroll with nothing but `openssl` and `curl`:

```bash
openssl req -new -newkey rsa:2048 -nodes -keyout dev.key -out dev.csr \
  -subj "/CN=device01.example.com" -addext "subjectAltName=DNS:device01.example.com,IP:10.0.0.5"
```

```bash
openssl req -in dev.csr -outform DER | base64 -w0 > dev.b64
```

```bash
curl -sk -u device:s3cret -X POST https://127.0.0.1:8443/.well-known/est/simpleenroll -H "Content-Type: application/pkcs10" --data-binary @dev.b64 | base64 -d | openssl pkcs7 -inform DER -print_certs
```

Fetching the CA chain needs no credentials at all — that is the bootstrap case RFC 7030 designs for:

```bash
curl -sk https://127.0.0.1:8443/.well-known/est/cacerts | base64 -d | openssl pkcs7 -inform DER -print_certs -noout
```

## Quickstart — HTTP delegated issuance

Set `Issuance:Mode` to `HttpDelegate` and point it at your API. Modest sends:

```json
{ "CSR": "<base64 of the PEM-encoded PKCS#10 request>" }
```

and expects back:

```json
{
  "certificate": "-----BEGIN CERTIFICATE-----\n...",
  "issuer": "-----BEGIN CERTIFICATE-----\n...\n-----BEGIN CERTIFICATE-----\n..."
}
```

- `certificate` is the issued leaf, PEM.
- `issuer` is the chain — intermediate(s) then root, in that order, **without** the leaf.
- Modest authenticates to the upstream with **HTTP Basic**; the password is read from a file, not an inline setting.
- The upstream is assumed synchronous. Non-2xx and unparseable bodies are errors, not "come back later".
- `/cacerts` is served from a **statically configured** PEM chain, because it has to answer a client that has never enrolled — a cache of past issuance responses would be empty at exactly that moment.

The EST surface is identical in both modes, and the integration suite runs against both to prove it.

## Configuration

Secrets are always referenced by **file path**, never inline. An inline password shows up in process listings, container inspection output and configuration-management diffs.

| Key | Default | Meaning |
|---|---|---|
| `Kestrel:Est:Port` | `8443` | EST listener (TLS) |
| `Kestrel:Est:CertificatePath` / `CertificatePasswordFile` | — | server TLS identity |
| `Kestrel:Ops:Port` | `8080` | health listener (plain HTTP) |
| `Est:MaxRequestBodyBytes` | `65536` | enrollment body cap, enforced before parsing |
| `Authentication:AllowClientCertificate` | `true` | accept TLS client certificates |
| `Authentication:AllowHttpBasic` | `true` | accept HTTP Basic |
| `Authentication:BasicRealm` | `modest` | realm in the 401 challenge |
| `Authentication:ClientCertificateTrustStorePath` | — | PEM trust anchors for client certs; platform store if unset |
| `Authentication:AllowUntrustedClientCertificates` | `false` | development only; logs a warning |
| `Authentication:BasicCredentials[]` | `[]` | `Username`, `PasswordHash`, `Salt`, `Iterations` (PBKDF2) |
| `Issuance:Mode` | `InternalCa` | `InternalCa` or `HttpDelegate` |
| `Issuance:Reenrollment:RequireMatchingIdentity` | `true` | see below |
| `Issuance:InternalCa:CertificatePath` / `CertificatePasswordFile` | — | CA PKCS#12 and its password file |
| `Issuance:InternalCa:AdditionalChainCertificatePaths` | `[]` | extra chain certs to publish |
| `Issuance:InternalCa:ValidityPeriod` | `90.00:00:00` | issued lifetime, clamped to the CA's own expiry |
| `Issuance:InternalCa:BackdateBy` | `00:05:00` | clock-skew allowance on `notBefore` |
| `Issuance:InternalCa:MinimumRsaKeySizeBits` | `2048` | smallest accepted RSA modulus |
| `Issuance:InternalCa:AllowedEllipticCurves` | `nistP256,nistP384,nistP521` | accepted curves; any spelling (`P-256`, `prime256v1`, an OID) matches |
| `Issuance:InternalCa:EnhancedKeyUsageOids` | `1.3.6.1.5.5.7.3.2` | EKUs on issued certs |
| `Issuance:InternalCa:KeyUsages` | `DigitalSignature,KeyEncipherment` | key usages on issued certs |
| `Issuance:InternalCa:CopySubjectAlternativeNames` | `true` | carry SANs from the CSR |
| `Issuance:HttpDelegate:BaseAddress` / `IssuePath` | — | upstream issuance API |
| `Issuance:HttpDelegate:BasicAuthUsername` / `BasicAuthPasswordFile` | — | upstream credentials |
| `Issuance:HttpDelegate:StaticCaChainPath` | — | PEM chain served from `/cacerts` |
| `Issuance:HttpDelegate:TimeoutSeconds` | `30` | per-attempt upstream timeout |
| `Issuance:HttpDelegate:MaxRetryAttempts` | `3` | transient-failure retries; `0` disables |
| `Issuance:HttpDelegate:MaxCsrSizeBytes` | `16384` | checked before any outbound call |

**A note on list settings.** .NET's configuration binder *appends* to collection defaults rather than replacing them. Modest therefore leaves every collection option unset by default and applies defaults in code, so that configuring `AllowedEllipticCurves` genuinely narrows the list instead of silently adding to it.

## Authentication

EST clients authenticate with a **TLS client certificate** (RFC 7030's recommendation) or **HTTP Basic over TLS**. Both are accepted; a client certificate that fails validation falls through to Basic rather than failing the request, since the two mechanisms are independent.

`/cacerts` and `/csrattrs` need no credentials. `/simpleenroll` and `/simplereenroll` do.

HTTP Digest is not implemented. Basic over TLS 1.2+ protects the credential equivalently and is far easier to implement correctly.

### Re-enrollment identity checking

With `Issuance:Reenrollment:RequireMatchingIdentity` on (the default), a re-enrollment must present the certificate being renewed, and the CSR must request **the same subject and exactly the same SAN set**. SAN comparison is order-independent and type-aware — a DNS name and an IP address that render as the same string are not the same identity.

Without this, any holder of any valid certificate could re-enroll under someone else's name, which turns a renewal endpoint into an impersonation endpoint.

Because the check is about proving continuity with an existing certificate, a **Basic-authenticated re-enrollment is refused while the check is on** — there is no certificate to establish continuity with. Turn the option off if credential-based re-enrollment is genuinely wanted.

## Deployment

```bash
docker build -f docker/Dockerfile -t modest:0.1.0 .
```

The image is chiselled, runs as non-root, and contains no key material — the CA PFX, TLS certificate and any upstream credential are mounted at runtime.

```bash
helm install modest ./helm/modest -f ./helm/modest/values-internalca.yaml
```

Use `values-httpdelegate.yaml` for delegated mode. The chart references Secrets you create yourself and never templates secret values into rendered manifests, so `helm template` output is safe to commit or share. See [helm/modest/README.md](helm/modest/README.md).

The server runs **two listeners**: EST over TLS, and health endpoints over plain HTTP on a separate port. That split exists so a Kubernetes kubelet can probe `/healthz` and `/readyz` without a TLS or client-certificate handshake. EST routes are not served on the ops port, and health routes are not served on the EST port.

## Testing

```bash
dotnet test
```

The suite covers the codec (including byte-for-byte comparison against `openssl crl2pkcs7` output), both issuers, and the HTTP surface end to end against both issuance modes.

Some tests shell out to `openssl` for independent verification and skip cleanly when it is absent. A codec that only ever talks to itself can grow matching bugs on both sides; a genuinely independent implementation catches those immediately.

## Known limitations

- No CRL or OCSP revocation checking of client certificates.
- No rate limiting or brute-force protection on Basic authentication — front it with a proxy, or prefer client certificates.
- No `tls-unique` channel binding (`SslStream` does not expose the value).
- CA keys are file-based; no HSM or cloud KMS support.
- `/csrattrs` always returns 204. Populating it — to steer clients onto a particular curve or key size — is a natural next step; `CsrAttrsWriter.BuildFromOids` is the hook.
- Single CA per instance; the optional `[label]` path segment for multi-CA deployments is not implemented.

## Design documents

Full design and rationale live in [planning/](planning/): protocol reference, architecture, security model, testing strategy, and the per-epic implementation plan in [planning/epics/](planning/epics/).

## License

TODO: choose a license.
