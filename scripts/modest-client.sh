#!/usr/bin/env bash
#
# modest-client.sh — a minimal EST client for renewing a certificate against a Modest server.
#
# Only /simplereenroll (certificate renewal) and /cacerts (trust bootstrap) are implemented.
# Initial enrollment (/simpleenroll) is out of scope by design — this client exists to renew a
# certificate you already hold, authenticating the renewal with that same certificate over TLS
# client-auth, which is what Modest's re-enrollment identity check expects.
#
# Requires: bash, curl, openssl, base64, mktemp.
#
# Usage:
#   modest-client.sh renew --server-url URL (--pkcs12 FILE [--pkcs12-password PASS | --pkcs12-password-file FILE]
#                                             | --cert FILE --key FILE)
#                          (--out-pkcs12 FILE [--out-pkcs12-password PASS] | --out-cert FILE)
#                          [--ca-bundle FILE | --insecure]
#
#   modest-client.sh cacerts --server-url URL --out FILE [--ca-bundle FILE | --insecure]
#
# The private key never changes across a renewal, so there is no --out-key: for --out-cert output,
# the existing --key/--pkcs12 file is still the right key for the renewed certificate. For
# --out-pkcs12 output, the container's password defaults to whatever password the input --pkcs12
# used (so the same protection just carries forward); pass --out-pkcs12-password to set a
# different one.
#
# Examples:
#   modest-client.sh renew --server-url https://est.example.com:8443 \
#       --cert device.pem --key device.key \
#       --out-cert device-renewed.pem \
#       --ca-bundle est-ca.pem
#
#   modest-client.sh renew --server-url https://est.example.com:8443 \
#       --pkcs12 device.p12 --pkcs12-password-file p12.pass \
#       --out-pkcs12 device-renewed.p12 \
#       --insecure
#
#   modest-client.sh cacerts --server-url https://est.example.com:8443 --out est-ca.pem --insecure

set -euo pipefail

PROGRAM_NAME=$(basename "$0")
EST_PREFIX="/.well-known/est"

# ------------------------------------------------------------------------------------------- usage

usage() {
    sed -n '2,37p' "$0" | sed 's/^# \{0,1\}//'
}

die() {
    echo "${PROGRAM_NAME}: error: $*" >&2
    exit 1
}

require_tool() {
    command -v "$1" >/dev/null 2>&1 || die "required tool '$1' not found on PATH"
}

# --------------------------------------------------------------------------------------- arg state

action=""
server_url=""

in_pkcs12=""
in_pkcs12_password=""
in_pkcs12_password_file=""
in_cert=""
in_key=""

out_pkcs12=""
out_pkcs12_password=""
out_cert=""

cacerts_out=""

ca_bundle=""
insecure=0

# ------------------------------------------------------------------------------------- arg parsing

if [[ $# -eq 0 ]]; then
    usage
    exit 1
fi

action=$1
shift

case "$action" in
    renew|cacerts) ;;
    -h|--help)
        usage
        exit 0
        ;;
    *)
        die "unknown action '$action' (expected 'renew' or 'cacerts')"
        ;;
esac

while [[ $# -gt 0 ]]; do
    case "$1" in
        --server-url)          server_url=$2; shift 2 ;;
        --pkcs12)               in_pkcs12=$2; shift 2 ;;
        --pkcs12-password)      in_pkcs12_password=$2; shift 2 ;;
        --pkcs12-password-file) in_pkcs12_password_file=$2; shift 2 ;;
        --cert)                 in_cert=$2; shift 2 ;;
        --key)                  in_key=$2; shift 2 ;;
        --out-pkcs12)            out_pkcs12=$2; shift 2 ;;
        --out-pkcs12-password)   out_pkcs12_password=$2; shift 2 ;;
        --out-cert)              out_cert=$2; shift 2 ;;
        --out)                   cacerts_out=$2; shift 2 ;;
        --ca-bundle)             ca_bundle=$2; shift 2 ;;
        --insecure)              insecure=1; shift 1 ;;
        -h|--help)               usage; exit 0 ;;
        *)
            die "unknown option '$1'"
            ;;
    esac
done

[[ -n "$server_url" ]] || die "--server-url is required"
server_url=${server_url%/}

require_tool curl
require_tool openssl
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

workdir=$(mktemp -d "${TMPDIR:-/tmp}/modest-client.XXXXXX")
cleanup() { rm -rf "$workdir"; }
trap cleanup EXIT

# ------------------------------------------------------------------------------------- http helper

# do_request METHOD PATH [BODY_FILE] [CONTENT_TYPE] [CLIENT_CERT] [CLIENT_KEY]
# Writes the response body to $workdir/response.bin and the HTTP status to stdout.
do_request() {
    local method=$1 path=$2 body_file=${3:-} content_type=${4:-} client_cert=${5:-} client_key=${6:-}
    local -a curl_args=(--silent --show-error --output "$workdir/response.bin" --write-out '%{http_code}')
    curl_args+=("${curl_tls_opts[@]}")
    curl_args+=(-X "$method" "${server_url}${path}")

    if [[ -n "$content_type" ]]; then
        curl_args+=(-H "Content-Type: ${content_type}")
    fi
    if [[ -n "$body_file" ]]; then
        curl_args+=(--data-binary "@${body_file}")
    fi
    if [[ -n "$client_cert" ]]; then
        curl_args+=(--cert "$client_cert")
    fi
    if [[ -n "$client_key" ]]; then
        curl_args+=(--key "$client_key")
    fi

    curl "${curl_args[@]}"
}

fail_with_response() {
    local status=$1 what=$2
    echo "${PROGRAM_NAME}: ${what} failed with HTTP ${status}" >&2
    if [[ -s "$workdir/response.bin" ]] && file_looks_like_text "$workdir/response.bin"; then
        echo "--- server response ---" >&2
        cat "$workdir/response.bin" >&2
        echo >&2
    fi
    exit 1
}

file_looks_like_text() {
    # Good enough for an EST server's plain-text error bodies without depending on `file(1)`.
    LC_ALL=C grep -qc $'[^[:print:][:space:]]' "$1" 2>/dev/null && return 1
    return 0
}

# certs_only_der_to_pem DER_FILE OUT_PEM
# Converts a certs-only PKCS#7 (RFC 7030's /cacerts and enrollment response shape) to clean,
# tightly concatenated PEM — just the certificate blocks, none of `-print_certs`' own
# "subject="/"issuer=" lines ahead of each one, and none of the blank line it leaves behind between
# certificates once those lines are stripped.
certs_only_der_to_pem() {
    local der_file=$1 out_pem=$2 raw="$workdir/print_certs.pem"
    openssl pkcs7 -inform DER -in "$der_file" -print_certs -out "$raw" \
        || die "could not parse the server's response as a certs-only PKCS#7 message"
    grep -v -E '^(subject|issuer)=|^$' "$raw" > "$out_pem"
    [[ -s "$out_pem" ]] || die "the server's response decoded to zero certificates"
}

# leaf_pem_from_chain CHAIN_PEM OUT_PEM
# Extracts just the first certificate block from a concatenated PEM file — the leaf, by the
# ordering RFC 7030 clients rely on and Modest's certs-only writer guarantees.
leaf_pem_from_chain() {
    local chain_pem=$1 out_pem=$2
    awk '/-----BEGIN CERTIFICATE-----/{n++} n==1{print} /-----END CERTIFICATE-----/{if(n==1)exit}' \
        "$chain_pem" > "$out_pem"
    [[ -s "$out_pem" ]] || die "could not find a leaf certificate in the server's response"
}

# ---------------------------------------------------------------------------------------- cacerts

run_cacerts() {
    [[ -n "$cacerts_out" ]] || die "cacerts requires --out FILE"

    local status
    status=$(do_request GET "${EST_PREFIX}/cacerts")
    [[ "$status" == "200" ]] || fail_with_response "$status" "fetching /cacerts"

    base64 -d "$workdir/response.bin" > "$workdir/cacerts.der" \
        || die "the server's /cacerts response was not valid base64"
    certs_only_der_to_pem "$workdir/cacerts.der" "$cacerts_out"

    local count
    count=$(grep -c -- '-----BEGIN CERTIFICATE-----' "$cacerts_out")
    echo "Wrote ${count} CA certificate(s) to ${cacerts_out}"
}

# ------------------------------------------------------------------------------------------ renew

materialize_input_identity() {
    local cert_pem="$workdir/in-cert.pem" key_pem="$workdir/in-key.pem" friendly_name=""

    if [[ -n "$in_pkcs12" ]]; then
        [[ -z "$in_cert" && -z "$in_key" ]] || die "--pkcs12 cannot be combined with --cert/--key"
        [[ -f "$in_pkcs12" ]] || die "--pkcs12 file not found: $in_pkcs12"
        [[ -z "$in_pkcs12_password" || -z "$in_pkcs12_password_file" ]] \
            || die "--pkcs12-password and --pkcs12-password-file are mutually exclusive"

        local passin
        if [[ -n "$in_pkcs12_password_file" ]]; then
            [[ -f "$in_pkcs12_password_file" ]] || die "--pkcs12-password-file not found: $in_pkcs12_password_file"
            passin="file:${in_pkcs12_password_file}"
        elif [[ -n "$in_pkcs12_password" ]]; then
            passin="pass:${in_pkcs12_password}"
        else
            passin="pass:"
        fi

        openssl pkcs12 -in "$in_pkcs12" -nocerts -nodes -passin "$passin" -out "$key_pem" 2>"$workdir/pkcs12-key.err" \
            || die "could not read the private key from --pkcs12 (wrong password?): $(cat "$workdir/pkcs12-key.err")"
        openssl pkcs12 -in "$in_pkcs12" -clcerts -nokeys -passin "$passin" -out "$cert_pem" 2>"$workdir/pkcs12-cert.err" \
            || die "could not read the client certificate from --pkcs12: $(cat "$workdir/pkcs12-cert.err")"
        [[ -s "$key_pem" ]] || die "--pkcs12 contained no private key"
        [[ -s "$cert_pem" ]] || die "--pkcs12 contained no client certificate (a bag of CA certs alone isn't enough)"

        # Not every PKCS#12 carries a friendlyName (openssl only emits the bag attribute line when
        # one is set), so an input file built without -name legitimately yields an empty value here
        # — falls through to write_pkcs12_output's own default rather than inventing one.
        friendly_name=$(openssl pkcs12 -in "$in_pkcs12" -nodes -passin "$passin" -info 2>/dev/null \
            | grep -m1 -E '^[[:space:]]*friendlyName:' | sed -E 's/^[[:space:]]*friendlyName:[[:space:]]*//')
    elif [[ -n "$in_cert" || -n "$in_key" ]]; then
        [[ -n "$in_cert" && -n "$in_key" ]] || die "--cert and --key must be given together"
        [[ -f "$in_cert" ]] || die "--cert file not found: $in_cert"
        [[ -f "$in_key" ]] || die "--key file not found: $in_key"
        openssl x509 -in "$in_cert" -noout >/dev/null 2>&1 || die "--cert is not a valid PEM certificate: $in_cert"
        openssl pkey -in "$in_key" -noout >/dev/null 2>&1 || die "--key is not a valid unencrypted PEM private key: $in_key"
        cp "$in_cert" "$cert_pem"
        cp "$in_key" "$key_pem"
    else
        die "provide either --pkcs12, or --cert and --key"
    fi

    chmod 600 "$key_pem"
    echo "$cert_pem:$key_pem:$friendly_name"
}

validate_output_selection() {
    if [[ -n "$out_pkcs12" ]]; then
        [[ -z "$out_cert" ]] || die "--out-pkcs12 cannot be combined with --out-cert"
    elif [[ -n "$out_cert" ]]; then
        : # nothing further to check
    else
        die "provide either --out-pkcs12 or --out-cert"
    fi
}

build_renewal_csr() {
    local cert_pem=$1 key_pem=$2 csr_pem="$workdir/renew.csr"

    # Reuses the certificate's own subject and extensions (including subjectAltName) byte-for-byte
    # rather than re-parsing and reformatting the distinguished name by hand — the classic source of
    # subtle RDN-ordering bugs in shell scripts that build a -subj string themselves. Signed with the
    # same key the certificate already carries, which both proves possession and is what Modest's
    # re-enrollment identity check (same subject, same SAN set) expects by default.
    openssl x509 -in "$cert_pem" -signkey "$key_pem" -x509toreq -copy_extensions copyall \
        -out "$csr_pem" 2>"$workdir/x509toreq.err" \
        || die "could not build a renewal CSR from the existing certificate: $(cat "$workdir/x509toreq.err")"

    echo "$csr_pem"
}

write_pkcs12_output() {
    local chain_pem=$1 key_pem=$2 friendly_name=${3:-modest-renewed}

    # The container's password defaults to whatever password the input --pkcs12 used, not a fresh
    # empty one — a renewal is meant to carry the same protection forward, not silently weaken it.
    # An explicit --out-pkcs12-password always wins.
    local passout
    if [[ -n "$out_pkcs12_password" ]]; then
        passout="pass:${out_pkcs12_password}"
    elif [[ -n "$in_pkcs12_password_file" ]]; then
        passout="file:${in_pkcs12_password_file}"
    elif [[ -n "$in_pkcs12_password" ]]; then
        passout="pass:${in_pkcs12_password}"
    else
        passout="pass:"
    fi

    openssl pkcs12 -export -in "$chain_pem" -inkey "$key_pem" -out "$out_pkcs12" \
        -passout "$passout" -name "$friendly_name" \
        || die "could not build the output PKCS#12 container"

    echo "Wrote renewed certificate and key to ${out_pkcs12} (PKCS#12)"
}

write_pem_output() {
    local leaf_pem=$1

    # Leaf only, no chain: --out-cert is the renewed certificate, not a bundle. The private key is
    # unchanged by a renewal, so it isn't written out again — the existing --key/--pkcs12 file is
    # still correct for this certificate.
    cp "$leaf_pem" "$out_cert"

    echo "Wrote renewed certificate to ${out_cert}"
}

run_renew() {
    validate_output_selection

    local identity cert_pem key_pem friendly_name
    identity=$(materialize_input_identity)
    IFS=: read -r cert_pem key_pem friendly_name <<< "$identity"

    local csr_pem
    csr_pem=$(build_renewal_csr "$cert_pem" "$key_pem")

    local csr_b64="$workdir/renew.b64"
    openssl req -in "$csr_pem" -outform DER | base64 -w0 > "$csr_b64"

    local status
    status=$(do_request POST "${EST_PREFIX}/simplereenroll" "$csr_b64" "application/pkcs10" "$cert_pem" "$key_pem")
    [[ "$status" == "200" ]] || fail_with_response "$status" "renewing the certificate"

    base64 -d "$workdir/response.bin" > "$workdir/renewed.der" \
        || die "the server's response was not valid base64"

    local chain_pem="$workdir/renewed-chain.pem"
    certs_only_der_to_pem "$workdir/renewed.der" "$chain_pem"

    local leaf_pem="$workdir/leaf.pem"
    leaf_pem_from_chain "$chain_pem" "$leaf_pem"

    if [[ -n "$out_pkcs12" ]]; then
        write_pkcs12_output "$chain_pem" "$key_pem" "$friendly_name"
    else
        write_pem_output "$leaf_pem"
    fi

    echo "New certificate:"
    openssl x509 -in "$leaf_pem" -noout -subject -dates | sed 's/^/  /'
}

# ------------------------------------------------------------------------------------------- main

case "$action" in
    cacerts) run_cacerts ;;
    renew)   run_renew ;;
esac
