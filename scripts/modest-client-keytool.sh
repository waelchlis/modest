#!/usr/bin/env bash
#
# modest-client-keytool.sh — renews a PKCS#12 keystore against a Modest server using the Java
# keytool CLI instead of openssl.
#
# Renewal only — no /cacerts, no initial enrollment, and no separate PEM cert/key input, unlike
# modest-client.sh. This exists specifically for callers who already work in keytool/PKCS#12 terms
# (a Java service's own keystore, typically) and want the renewed keystore to be a drop-in
# replacement: same alias, same password, same key, only the certificate itself is new.
#
# Requires: bash, curl, keytool (a JRE/JDK on PATH), base64, sed, awk, grep, mktemp.
#
# Usage:
#   modest-client-keytool.sh --server-url URL --pkcs12 FILE
#       [--pkcs12-password PASS | --pkcs12-password-file FILE]
#       [--alias ALIAS]
#       --out-pkcs12 FILE
#       [--ca-bundle FILE | --insecure]
#
# --alias picks which private-key entry to renew when the keystore holds more than one; with
# exactly one, it is picked automatically. The output keystore's password and friendly name are
# always identical to the input's — there is no way to change either here, by design.
#
# Example:
#   modest-client-keytool.sh --server-url https://est.example.com:8443 \
#       --pkcs12 device.p12 --pkcs12-password-file p12.pass \
#       --out-pkcs12 device-renewed.p12 \
#       --ca-bundle est-ca.pem

set -euo pipefail

PROGRAM_NAME=$(basename "$0")
EST_PREFIX="/.well-known/est"

# ------------------------------------------------------------------------------------------- usage

usage() {
    sed -n '2,28p' "$0" | sed 's/^# \{0,1\}//'
}

die() {
    echo "${PROGRAM_NAME}: error: $*" >&2
    exit 1
}

require_tool() {
    command -v "$1" >/dev/null 2>&1 || die "required tool '$1' not found on PATH"
}

# --------------------------------------------------------------------------------------- arg state

server_url=""
in_pkcs12=""
in_pkcs12_password=""
in_pkcs12_password_file=""
alias_name=""
out_pkcs12=""
ca_bundle=""
insecure=0

# ------------------------------------------------------------------------------------- arg parsing

if [[ $# -eq 0 ]]; then
    usage
    exit 1
fi

while [[ $# -gt 0 ]]; do
    case "$1" in
        --server-url)            server_url=$2; shift 2 ;;
        --pkcs12)                in_pkcs12=$2; shift 2 ;;
        --pkcs12-password)       in_pkcs12_password=$2; shift 2 ;;
        --pkcs12-password-file)  in_pkcs12_password_file=$2; shift 2 ;;
        --alias)                 alias_name=$2; shift 2 ;;
        --out-pkcs12)            out_pkcs12=$2; shift 2 ;;
        --ca-bundle)             ca_bundle=$2; shift 2 ;;
        --insecure)              insecure=1; shift 1 ;;
        -h|--help)                usage; exit 0 ;;
        *)
            die "unknown option '$1'"
            ;;
    esac
done

[[ -n "$server_url" ]] || die "--server-url is required"
server_url=${server_url%/}

[[ -n "$in_pkcs12" ]] || die "--pkcs12 is required"
[[ -f "$in_pkcs12" ]] || die "--pkcs12 file not found: $in_pkcs12"

[[ -z "$in_pkcs12_password" || -z "$in_pkcs12_password_file" ]] \
    || die "--pkcs12-password and --pkcs12-password-file are mutually exclusive"

[[ -n "$out_pkcs12" ]] || die "--out-pkcs12 is required"

require_tool curl
require_tool keytool
require_tool base64
require_tool mktemp

# ---------------------------------------------------------------------------------------- curl TLS

curl_tls_opts=()
if [[ "$insecure" -eq 1 && -n "$ca_bundle" ]]; then
    die "--ca-bundle and --insecure are mutually exclusive"
elif [[ "$insecure" -eq 1 ]]; then
    curl_tls_opts+=(--insecure)
elif [[ -n "$ca_bundle" ]]; then
    [[ -f "$ca_bundle" ]] || die "--ca-bundle file not found: $ca_bundle"
    curl_tls_opts+=(--cacert "$ca_bundle")
fi
# Neither given: fall back to curl's normal system trust store, correct when the server's TLS
# certificate is already publicly trusted or the host has it installed system-wide.

# ------------------------------------------------------------------------------------- temp workdir

workdir=$(mktemp -d "${TMPDIR:-/tmp}/modest-client-keytool.XXXXXX")
cleanup() { rm -rf "$workdir"; }
trap cleanup EXIT

# ------------------------------------------------------------------------------------ store setup

# The password file keytool reads via -storepass:file, which (confirmed) tolerates a trailing
# newline or CRLF the same way modest-client.sh's own password handling does. Working from a
# file — even for a password supplied inline via --pkcs12-password — means the plaintext never has
# to appear as a keytool command-line argument, which would otherwise be visible to anyone who can
# run `ps` on this host.
storepass_file="$workdir/storepass"
if [[ -n "$in_pkcs12_password_file" ]]; then
    [[ -f "$in_pkcs12_password_file" ]] || die "--pkcs12-password-file not found: $in_pkcs12_password_file"
    storepass_file="$in_pkcs12_password_file"
else
    printf '%s' "$in_pkcs12_password" > "$storepass_file"
    chmod 600 "$storepass_file"
fi

# Renewal happens on a copy: --pkcs12 is never modified, matching modest-client.sh's own
# leave-the-input-alone behaviour.
work_p12="$workdir/work.p12"
cp "$in_pkcs12" "$work_p12"

# ---------------------------------------------------------------------------------- alias handling

resolve_alias() {
    # keytool writes its own error text ("keystore password was incorrect", etc.) to stdout, not
    # stderr (confirmed directly) — every keytool call below merges both streams into one capture
    # file so a failure's message is never silently dropped.
    if [[ -n "$alias_name" ]]; then
        keytool -list -keystore "$work_p12" -storepass:file "$storepass_file" -alias "$alias_name" \
            > "$workdir/alias-check.out" 2>&1 \
            || die "alias '$alias_name' not found in --pkcs12 (wrong password?): $(cat "$workdir/alias-check.out")"
        return
    fi

    local listing="$workdir/listing.txt"
    keytool -list -keystore "$work_p12" -storepass:file "$storepass_file" \
        > "$listing" 2>&1 \
        || die "could not open --pkcs12 (wrong password?): $(cat "$listing")"

    local -a aliases=()
    while IFS= read -r line; do
        aliases+=("$line")
    done < <(awk -F, '/, *PrivateKeyEntry,/ {print $1}' "$listing")

    case "${#aliases[@]}" in
        0) die "--pkcs12 has no private-key entry to renew" ;;
        1) alias_name="${aliases[0]}" ;;
        *) die "--pkcs12 has multiple private-key entries (${aliases[*]}); specify one with --alias" ;;
    esac
}

# ------------------------------------------------------------------------------------ renewal CSR

# subject_alt_name_ext
# Reads back the current entry's own subjectAltName extension, in keytool's own -ext SAN=... syntax
# (dns:/ip:/email:), so the renewal CSR requests the identical SAN set. -certreq does not carry
# extensions over from the existing certificate on its own (confirmed against a real keystore), and
# Modest's re-enrollment identity check requires the SAN set to match exactly by default — so this
# has to be rebuilt from the certificate's own text, not skipped.
subject_alt_name_ext() {
    local detail="$workdir/entry-detail.txt"
    keytool -list -v -keystore "$work_p12" -storepass:file "$storepass_file" -alias "$alias_name" \
        > "$detail" 2>&1 \
        || die "could not read the certificate for alias '$alias_name': $(cat "$detail")"

    awk '
        /SubjectAlternativeName \[/ { in_san=1; next }
        in_san && /^\]/ { in_san=0; next }
        in_san {
            line=$0
            sub(/^[ \t]+/, "", line)
            entry=""
            if (line ~ /^DNSName:/)         { sub(/^DNSName: */, "", line);    entry="dns:" line }
            else if (line ~ /^IPAddress:/)  { sub(/^IPAddress: */, "", line);  entry="ip:" line }
            else if (line ~ /^RFC822Name:/) { sub(/^RFC822Name: */, "", line); entry="email:" line }
            if (entry != "") {
                if (out != "") out = out ","
                out = out entry
            }
        }
        END { print out }
    ' "$detail"
}

# build_renewal_csr
# Writes the PEM CSR to $workdir/renew.csr and prints its base64-of-DER form to stdout, ready for
# the EST request body. keytool always writes -certreq output as PEM (there is no DER option), so
# the PEM armour is stripped with sed/tr rather than reaching for openssl to do it — the body
# between BEGIN/END is already exactly the base64 the wire format wants (verified byte-for-byte
# identical to what `openssl req -outform DER | base64` produces from the same CSR).
build_renewal_csr() {
    local san_ext csr_pem="$workdir/renew.csr"
    san_ext=$(subject_alt_name_ext)

    local -a certreq_args=(-certreq -alias "$alias_name" -keystore "$work_p12" \
        -storepass:file "$storepass_file" -file "$csr_pem")
    if [[ -n "$san_ext" ]]; then
        certreq_args+=(-ext "SAN=${san_ext}")
    fi

    keytool "${certreq_args[@]}" > "$workdir/certreq.out" 2>&1 \
        || die "could not build a renewal CSR from the existing certificate: $(cat "$workdir/certreq.out")"

    local csr_b64="$workdir/renew.b64"
    sed -n '/-----BEGIN [A-Z ]*CERTIFICATE REQUEST-----/,/-----END [A-Z ]*CERTIFICATE REQUEST-----/p' "$csr_pem" \
        | sed '1d;$d' | tr -d '\r\n' > "$csr_b64"
    [[ -s "$csr_b64" ]] || die "could not read the CSR body keytool produced"

    echo "$csr_b64"
}

# ------------------------------------------------------------------------------------------ renew

fail_with_response() {
    local status=$1
    echo "${PROGRAM_NAME}: renewing the certificate failed with HTTP ${status}" >&2
    if [[ -s "$workdir/response.bin" ]] \
        && ! LC_ALL=C grep -qc $'[^[:print:][:space:]]' "$workdir/response.bin" 2>/dev/null; then
        echo "--- server response ---" >&2
        cat "$workdir/response.bin" >&2
        echo >&2
    fi
    exit 1
}

# do_reenroll_request CSR_B64_FILE
# TLS client-cert auth straight from the PKCS#12 file (curl's OpenSSL backend loads it directly —
# confirmed against a real Modest server, no PEM extraction needed). The cert/password pair is
# passed via a curl -K config file rather than -cert/--cert-type on the command line, so the
# plaintext password never appears as a process argument either.
do_reenroll_request() {
    local csr_b64=$1 storepass_value cfg="$workdir/curl-client.cfg"
    storepass_value=$(cat "$storepass_file")

    {
        printf 'cert-type = "P12"\n'
        printf 'cert = "%s:%s"\n' "$work_p12" "$storepass_value"
    } > "$cfg"
    chmod 600 "$cfg"

    local -a curl_args=(--silent --show-error --output "$workdir/response.bin" --write-out '%{http_code}')
    curl_args+=("${curl_tls_opts[@]}")
    curl_args+=(-K "$cfg")
    curl_args+=(-H "Content-Type: application/pkcs10")
    curl_args+=(--data-binary "@${csr_b64}")
    curl_args+=(-X POST "${server_url}${EST_PREFIX}/simplereenroll")

    curl "${curl_args[@]}"
}

run_renew() {
    resolve_alias

    local csr_b64
    csr_b64=$(build_renewal_csr)

    local status
    status=$(do_reenroll_request "$csr_b64")
    [[ "$status" == "200" ]] || fail_with_response "$status"

    local reply_der="$workdir/reply.der"
    base64 -d "$workdir/response.bin" > "$reply_der" \
        || die "the server's response was not valid base64"

    # A certificate-reply import: keytool matches the reply against the existing key entry by
    # public key and replaces its certificate (chain) in place, leaving the alias, password and key
    # untouched — exactly the "same keystore, new certificate" contract this script promises.
    keytool -importcert -alias "$alias_name" -keystore "$work_p12" -storepass:file "$storepass_file" \
        -file "$reply_der" -noprompt > "$workdir/importcert.out" 2>&1 \
        || die "could not install the renewed certificate into the keystore: $(cat "$workdir/importcert.out")"

    cp "$work_p12" "$out_pkcs12"

    echo "Wrote renewed keystore to ${out_pkcs12} (alias '${alias_name}', same password as the input)"
    echo "New certificate:"
    keytool -list -v -keystore "$out_pkcs12" -storepass:file "$storepass_file" -alias "$alias_name" 2>/dev/null \
        | grep -E '^(Owner|Valid from)' | sed 's/^/  /'
}

# ------------------------------------------------------------------------------------------- main

run_renew
