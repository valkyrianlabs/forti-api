---
title: Errors and retries
description: Exceptions, what is retried and what never is.
order: 50
status: published
tags:
  - guides
---

# Errors and retries

forti-api reports problems as exceptions derived from `fortiapi::Error` and never writes to stdout
or stderr.

| Exception | When | Details |
|---|---|---|
| `fortiapi::ApiError` | The device answered with an error (HTTP 400 or above, or an error envelope) | `http_status()`, `fortios_error()` (for example `-3`, entry not found), `body()` with the CLI messages, `not_found()` |
| `fortiapi::TransportError` | No reply: DNS, connect, TLS, timeout | `code()` (libcurl code), `before_send()` |
| `fortiapi::DecodeError` | A reply that does not match the expected shape | names the endpoint and attribute path |
| `fortiapi::SizeLimitError` | A download exceeded `DownloadOptions::max_bytes` ([Downloads](/guides/downloads)) | `limit()`; never retried |

```cpp
try {
    firewall::Addresses::add(host);
} catch (const fortiapi::ApiError& error) {
    // what() includes the HTTP status, the FortiOS error code and the CLI messages, e.g.
    // "POST cmdb/dnsfilter/profile: HTTP 500, FortiOS error -3; entry not found in datasource"
    std::cerr << error.what() << "\n";
}
```

`find()` returns `std::nullopt` for a missing object instead of throwing; `get()` throws an
`ApiError` whose `not_found()` is true.

## Retries

- Reads (GET) are retried on transport errors and on HTTP 429, 502, 503 and 504, with exponential
  backoff (`Config::retries`, `Config::retry_backoff`).
- Writes (POST, PUT, DELETE) are retried only when the connection failed before anything was sent
  (DNS, connect or TLS handshake). Once a write may have reached the device it is never repeated.
- HTTP 401 is never retried: FortiOS locks the API out (HTTP 429) after repeated authentication
  failures.

## Partial creates

FortiOS creates are not transactional. When an attribute is rejected after the object was created,
the request fails with an `ApiError` and the object still exists on the device. forti-api does not
clean up behind your back; check with `contains()` and delete it if that is what you want.

## Tracing

`Config::on_exchange` receives every request and reply (method, URL, bodies, status, timing). The
API key travels in a header that is not part of the record. For `Client::download`, the record of a
successful reply has an empty response body, because downloads such as configuration backups are
secrets.
