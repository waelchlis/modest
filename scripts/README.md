# modest-client.sh

A minimal bash EST client for renewing a certificate against a Modest server. Only
`/simplereenroll` (renewal) and `/cacerts` (trust bootstrap) are implemented — initial enrollment
(`/simpleenroll`) is deliberately out of scope, since this exists to renew a certificate you already
hold rather than to be a general-purpose EST client.

Requires `bash`, `curl`, `openssl`, `base64`.

```bash
scripts/modest-client.sh --help
```

## Renewing a certificate

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
just carries forward — unless `--out-pkcs12-password` gives an explicit new one.

## Fetching the CA chain

```bash
scripts/modest-client.sh cacerts --server-url https://est.example.com:8443 --out est-ca.pem --ca-bundle ...
```

Useful both as a one-off (to get `--ca-bundle` material for the command above) and as its own thing —
`/cacerts` needs no credentials. Writes plain concatenated PEM — no `subject=`/`issuer=` lines ahead
of each certificate.

## TLS trust

Pass `--ca-bundle FILE` to verify the EST server's own TLS certificate against a specific PEM bundle,
or `--insecure` to skip verification entirely (development only). Give neither to fall back to curl's
normal system trust store.
