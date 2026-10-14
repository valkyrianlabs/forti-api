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
| | `connect_timeout` | 5 s | Connection timeout |
| | `timeout` | 30 s | Whole-request timeout |
| | `retries`, `retry_backoff` | 2, 500 ms | Read retries (see [Errors and retries](/guides/errors-and-retries)) |
| | `on_exchange` | none | Callback receiving every request and reply, without credentials |

TLS is always verified (peer and host name). `resolve_ip` helps when the certificate is issued for a
name that does not resolve to the FortiGate from where the client runs (split-horizon DNS).
