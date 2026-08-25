# Modest Helm chart

Deploys [Modest](../../README.md), a modular RFC 7030 EST server.

## Before installing

The chart never creates Secrets or templates secret values into rendered manifests — `helm template` output is safe to share. Create the Secrets it references yourself.

**Server TLS identity** (always required):

```bash
kubectl create secret generic modest-tls --from-file=tls.pfx=./tls.pfx --from-file=tls.pass=./tls.pass
```

If `tls.pfx` has no password, set `tls.passwordKey: ""` in values and create the Secret with just the
PFX — Modest's certificate loader accepts an unencrypted PKCS#12 file, and the chart then omits
`Kestrel:Est:CertificatePasswordFile` from the rendered config entirely instead of pointing it at a
file that doesn't exist:

```bash
kubectl create secret generic modest-tls --from-file=tls.pfx=./tls.pfx
```

**Internal CA mode** — the CA keypair:

```bash
kubectl create secret generic modest-ca --from-file=ca.pfx=./ca.pfx --from-file=ca.pfx.pass=./ca.pfx.pass
```

Generate that pair with `modest init-ca --out ./ca` if you do not already have one.

**HTTP delegate mode** — the upstream credential and the chain to publish from `/cacerts`:

```bash
kubectl create secret generic modest-upstream --from-file=password=./password
```

```bash
kubectl create configmap modest-upstream-chain --from-file=chain.pem=./chain.pem
```

The chain is a ConfigMap rather than a Secret because it holds only public certificates.

## Installing

```bash
helm install modest ./helm/modest -f ./helm/modest/values-internalca.yaml
```

```bash
helm install modest ./helm/modest -f ./helm/modest/values-httpdelegate.yaml
```

Upgrade with `helm upgrade`, remove with `helm uninstall modest`. The Deployment carries a checksum of the rendered config, so a values change rolls the pods rather than leaving them on stale settings.

## What gets created

- A **Deployment** running the server as non-root with a read-only root filesystem.
- Two **Services**: the EST service on 8443 (TLS), and a ClusterIP-only ops service on 8080.
- A **ConfigMap** holding non-secret configuration.

The ops service is plain HTTP by design so that probes need no TLS handshake. Keep it cluster-internal; never route external traffic to it.

## Values

See [values.yaml](values.yaml), which is commented throughout. The settings most worth checking before a real deployment:

| Value | Why it matters |
|---|---|
| `issuance.mode` | `InternalCa` or `HttpDelegate` |
| `issuance.reenrollment.requireMatchingIdentity` | leave `true`; turning it off allows re-enrollment under another party's identity |
| `authentication.basicCredentials` | PBKDF2 verifiers from `modest hash-password`, never plaintext |
| `authentication.clientCertificateTrustStore.existingSecret` | trust anchors for client certificates; falls back to the platform store |
| `issuance.internalCa.allowedEllipticCurves` | narrowing this genuinely narrows it |
| `service.est.type` | `ClusterIP` by default; set to `LoadBalancer` to expose EST outside the cluster |
| `service.est.loadBalancerIP` | only meaningful with `type: LoadBalancer`; requests a specific address from the cloud provider (support varies) — left empty, the provider assigns one |

`helm install` prints usage notes, and warns if re-enrollment identity checking is disabled or if Basic auth is enabled with no credentials configured.

## Verifying a deployment

```bash
kubectl port-forward svc/modest 8443
```

```bash
curl -sk https://127.0.0.1:8443/.well-known/est/cacerts | base64 -d | openssl pkcs7 -inform DER -print_certs -noout
```

If that prints your CA chain, the server is running, its issuer is configured, and TLS is terminating correctly.
