---
title: Configuration
description: Environment variables and fortiapi::Config fields.
order: 90
status: published
tags:
  - reference
---

# Configuration

`fortiapi::default_client()` is created from `fortiapi::Config::from_env()` on first use. Replace it
with `fortiapi::set_default_client()`, or pass a `fortiapi::Client` to any call.

## Environment variables

`Config::from_env()` reads these variables. Unset or empty optional variables keep the defaults; a
missing host or API key throws a `fortiapi::Error`.

| Environment variable | `Config` field | Default | Meaning |
|---|---|---|---|
| `FORTIGATE_HOST` (or `FORTIGATE_GATEWAY_IP`) | `host` | required | Hostname or address of the FortiGate |
| `FORTIGATE_ADMIN_HTTPS_PORT` | `port` | `443` | Admin HTTPS port |
| `FORTIGATE_API_KEY` | `api_key` | required | REST API administrator key |
| `PATH_TO_FORTIGATE_CA_CERT` | `ca_bundle` | system trust store | PEM CA bundle |
| `PATH_TO_FORTIGATE_SSL_CERT` | `client_cert` | none | PKCS#12 client certificate (PKI peer authentication) |
| `FORTIGATE_SSL_CERT_PASS` | `client_cert_password` | none | Its password |
| `FORTIGATE_RESOLVE_IP` | `resolve_ip` | none | Connect to this address while verifying TLS for the host name |
| `FORTIGATE_VDOM` | `vdom` | device default | VDOM for every request (a `Query` can override it) |

## Fields set in code

These `Config` fields have no environment variable:

| `Config` field | Default | Meaning |
|---|---|---|
| `connect_timeout` | 5 s | Connection timeout |
| `timeout` | 30 s | Whole-request timeout |
| `retries`, `retry_backoff` | 2, 500 ms | Read retries (see [Errors and retries](/guides/errors-and-retries#retries)) |
| `on_exchange` | none | Callback receiving every request and reply, without credentials (see [Tracing](/guides/errors-and-retries#tracing)) |
| `max_reply_depth` | 256 | Deepest nesting of objects and arrays accepted in a JSON reply (see [Reply nesting limit](/guides/errors-and-retries#reply-nesting-limit)) |

## TLS

:::callout[TLS is always verified]{variant="info"}
TLS is always verified (peer and host name). There is no option to turn verification off.
:::

`resolve_ip` helps when the certificate is issued for a name that does not resolve to the FortiGate
from where the client runs (split-horizon DNS).

## Trust on first use

A FortiGate with a self-signed or factory certificate fails verification until you say what to trust.
`fortiapi::probe_tls(config)` (`forti_api/tls.hpp`) shows you the certificate first, so a person can
decide:

```cpp
#include <forti_api/tls.hpp>

fortiapi::TlsProbe probe = fortiapi::probe_tls(config);
if (!probe.trusted) {
    // probe.chain[0] is the device's certificate (PEM): show its fingerprint and names, and when the
    // person accepts it, save it and set config.ca_bundle to that file.
}
```

`probe_tls` connects, completes the TLS handshake and stops. It never sends an HTTP request and never
uses the API key or the client certificate. The first handshake verifies exactly as every request
does. Only when that handshake rejects the certificate does a second one run with verification off,
to collect the chain for inspection. That connection carries no data and is closed at once.
Connection failures (DNS, connect, timeout) throw `TransportError`, as requests do.

| Field | Meaning |
|---|---|
| `trusted` | the chain verified for `host` against the CA bundle (or the system trust store) |
| `verify_code`, `verify_error` | libcurl's code and message for the rejected handshake |
| `chain` | the certificates as presented, PEM, the device's own first |
| `local_ip` | this side's address of the connection: what the device sees before any NAT, for example for a trusted host |

A pinned device certificate works as the CA bundle on its own: libcurl accepts a trust anchor that is
not a root. The host name is still verified, so `host` must be a name the certificate carries. A
factory certificate names the serial number: use it as `host` and the address as `resolve_ip`.
