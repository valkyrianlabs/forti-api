#!/usr/bin/env bash
# Generates the TLS material forti-api uses against a FortiGate, all from one private CA:
#
#   <out>/forti-api-ca.crt           trust anchor: PATH_TO_FORTIGATE_CA_CERT, and the FortiGate's
#                                    trusted CA for PKI peer (client certificate) authentication
#   <out>/forti-api-client.p12       client identity: PATH_TO_FORTIGATE_SSL_CERT
#   <out>/forti-api-client.pass      its password: FORTIGATE_SSL_CERT_PASS
#   <out>/upload/fortigate-admin.*   admin HTTPS server certificate for the FortiGate (.p12 + .pass,
#                                    or .crt + .key), with the gateway IPs as SANs
#   <out>/ca/forti-api-ca.key        CA private key: keep it off shared machines
#
# Usage: tools/gen-certs.sh [-o .certs] [-d days] IP [IP...]
#   e.g. tools/gen-certs.sh 192.168.1.1 10.0.0.1
#
# Refuses to overwrite an existing CA. PKCS#12 files use PBE-SHA1-3DES with a SHA-1 MAC, which
# every consumer reads: OpenSSL 3 without the legacy provider, LibreSSL (macOS libcurl) and FortiOS.
set -euo pipefail

out=.certs
days=1095
while getopts "o:d:" opt; do
  case "$opt" in
    o) out=$OPTARG ;;
    d) days=$OPTARG ;;
    *) exit 2 ;;
  esac
done
shift $((OPTIND - 1))
[ $# -ge 1 ] || { sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 2; }

if [ -e "$out/ca/forti-api-ca.key" ]; then
  echo "error: $out/ca/forti-api-ca.key exists; move $out aside to start over" >&2
  exit 1
fi

umask 077
mkdir -p "$out/ca" "$out/upload"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

san=$(printf 'IP:%s,' "$@")
san=${san%,}
p12_legacy=(-certpbe PBE-SHA1-3DES -keypbe PBE-SHA1-3DES -macalg sha1)

# CA (10 years)
openssl req -x509 -new -newkey rsa:3072 -sha256 -days 3650 -nodes \
  -subj "/O=forti-api/CN=forti-api CA" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier=hash" \
  -keyout "$out/ca/forti-api-ca.key" -out "$out/forti-api-ca.crt" 2>/dev/null

issue() { # issue NAME SUBJECT EXTENSIONS
  openssl req -new -newkey rsa:3072 -sha256 -nodes -subj "$2" \
    -keyout "$tmp/$1.key" -out "$tmp/$1.csr" 2>/dev/null
  printf '%b\n' "$3" > "$tmp/$1.ext"
  openssl x509 -req -sha256 -days "$days" -in "$tmp/$1.csr" \
    -CA "$out/forti-api-ca.crt" -CAkey "$out/ca/forti-api-ca.key" -CAcreateserial \
    -extfile "$tmp/$1.ext" -out "$tmp/$1.crt" 2>/dev/null
}

common="basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid"

issue client "/O=forti-api/CN=forti-api-client" "$common\nextendedKeyUsage=clientAuth"
openssl rand -hex 24 > "$out/forti-api-client.pass"
openssl pkcs12 -export "${p12_legacy[@]}" -name forti-api-client \
  -inkey "$tmp/client.key" -in "$tmp/client.crt" -certfile "$out/forti-api-ca.crt" \
  -passout "file:$out/forti-api-client.pass" -out "$out/forti-api-client.p12"

issue server "/O=forti-api/CN=$1" "$common\nextendedKeyUsage=serverAuth\nsubjectAltName=$san"
openssl rand -hex 24 > "$out/upload/fortigate-admin.pass"
openssl pkcs12 -export "${p12_legacy[@]}" -name fortigate-admin \
  -inkey "$tmp/server.key" -in "$tmp/server.crt" -certfile "$out/forti-api-ca.crt" \
  -passout "file:$out/upload/fortigate-admin.pass" -out "$out/upload/fortigate-admin.p12"
cp "$tmp/server.crt" "$out/upload/fortigate-admin.crt"
cp "$tmp/server.key" "$out/upload/fortigate-admin.key"
cp "$out/forti-api-ca.crt" "$out/upload/forti-api-ca.crt"
rm -f "$out/forti-api-ca.srl"

openssl verify -CAfile "$out/forti-api-ca.crt" "$tmp/client.crt" "$tmp/server.crt"
echo "wrote $out (client valid $days days, server SANs: $san)"
