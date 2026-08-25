# EST clients

Two minimal bash clients for renewing a certificate against a Modest server, built on different
tooling: [modest-client.sh](#modest-clientsh) (openssl) and
[modest-client-keytool.sh](#modest-client-keytoolsh) (Java's `keytool`). Neither implements initial
enrollment (`/simpleenroll`) — both exist to renew a certificate you already hold, not to be a
general-purpose EST client.

## modest-client.sh

Only `/simplereenroll` (renewal) and `/cacerts` (trust bootstrap) are implemented.

Requires `bash`, `curl`, `openssl`, `base64`.

```bash
scripts/modest-client.sh --help
```

### Renewing a certificate

Input identity — either a PKCS#12 file or a separate PEM certificate and (unencrypted) private key:

```bash
scripts/modest-client.sh renew --server-url https://est.example.com:8443 \
    --cert device.pem --key device.key \
    --out-cert device-renewed.pem \
    --ca-bundle est-ca.pem
```

```bash
scripts/modest-client.sh renew --server-url https://est.example.com:8443 \
    --pkcs12 device.p12 --pkcs12-password-file p12.pass \
    --out-pkcs12 device-renewed.p12 \
    --ca-bundle est-ca.pem
```

The renewal CSR is built directly from the existing certificate (`openssl x509 -x509toreq
-copy_extensions copyall`), so the subject and SAN set are carried over byte-for-byte rather than
reconstructed by hand — which is also exactly what Modest's re-enrollment identity check requires by
default. The existing key is reused for the renewed certificate; authentication is the certificate
itself over TLS client auth, since `/simplereenroll` refuses Basic-authenticated requests while that
check is on.

Output is either a PKCS#12 container (`--out-pkcs12`) or a plain PEM certificate (`--out-cert`) —
just the renewed leaf, with no chain and none of `openssl pkcs7 -print_certs`' own
`subject=`/`issuer=` lines ahead of it. There is no `--out-key`: a renewal doesn't change the key, so
the `--key`/`--pkcs12` file you already have is still the right one. For `--out-pkcs12`, the
container's password defaults to whatever password the input `--pkcs12` used — the same protection
just carries forward — unless `--out-pkcs12-password` gives an explicit new one. Likewise, the
output container's friendly name (`-name`) matches the input `--pkcs12`'s own friendly name if it
had one; falls back to `modest-renewed` when the input had none, or wasn't a PKCS#12 at all.

### Fetching the CA chain

```bash
scripts/modest-client.sh cacerts --server-url https://est.example.com:8443 --out est-ca.pem --ca-bundle ...
```

Useful both as a one-off (to get `--ca-bundle` material for the command above) and as its own thing —
`/cacerts` needs no credentials. Writes plain concatenated PEM — no `subject=`/`issuer=` lines ahead
of each certificate.

### TLS trust

Pass `--ca-bundle FILE` to verify the EST server's own TLS certificate against a specific PEM bundle,
or `--insecure` to skip verification entirely (development only). Give neither to fall back to curl's
normal system trust store. Both clients share this behaviour.

## modest-client-keytool.sh

Renewal only, for a PKCS#12 keystore — no `/cacerts`, no separate PEM cert/key input. Built for
callers already working in `keytool`/PKCS#12 terms (a Java service's own keystore, typically) who
want the renewed keystore to be a drop-in replacement for the old one: same alias, same password,
same key, only the certificate itself changes. There's no way to change the alias or password on
output — that's deliberate, not a missing feature.

Requires `bash`, `curl`, `keytool` (a JRE/JDK on `PATH`), `base64`.

```bash
scripts/modest-client-keytool.sh --help
```

```bash
scripts/modest-client-keytool.sh --server-url https://est.example.com:8443 \
    --pkcs12 device.p12 --pkcs12-password-file p12.pass \
    --out-pkcs12 device-renewed.p12 \
    --ca-bundle est-ca.pem
```

`--alias` picks which private-key entry to renew when the keystore holds more than one; with
exactly one, it's picked automatically.

The renewal CSR is generated with `keytool -certreq` against the existing keystore entry, which
reuses the entry's own key and subject DN automatically — but, unlike openssl's
`-copy_extensions`, does *not* carry the certificate's extensions over on its own. Since Modest's
re-enrollment identity check expects the SAN set to match exactly by default, this script first
reads the current certificate's `subjectAltName` back out of `keytool -list -v`'s text output and
rebuilds it as `-certreq -ext SAN=...`, so the identity requested is exactly the one already held.

The server's reply is installed with `keytool -importcert`, a plain certificate-reply import:
keytool matches it to the existing key entry and replaces its certificate there, so the alias,
password and key are untouched by construction rather than by extra bookkeeping. No openssl is
used anywhere in this script — `keytool -certreq`'s PEM output is unwrapped with `sed`, and the TLS
client-cert handshake is done by pointing curl straight at the PKCS#12 file
(`--cert-type P12`, via a `-K` config file so the password never appears as a process argument).
