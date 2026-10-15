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
| `fortiapi::DecodeError` | A reply that does not match the expected shape, is not JSON, or nests deeper than `Config::max_reply_depth` | names the endpoint and attribute path |
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
  When the connection drops after a write was sent and before the reply, the call throws a
  `TransportError` whose `before_send()` is false: the outcome is unknown, so read the object back
  before deciding what to do.
- HTTP 401 is never retried: FortiOS locks the API out (HTTP 429) after repeated authentication
  failures.

## Writes never reuse a connection

Reads share one kept-alive connection per client. Each write opens a new connection and closes it
afterwards. libcurl, on its own, sends a request again when a *reused* keep-alive connection turns
out to be dead (nothing came back), which for a write that did reach the device means it runs twice:
two policies created, a delete reported as "not found". On a new connection libcurl never repeats a
request, and writes use HTTP/1.1 without `Expect: 100-continue`, which rules out libcurl's other,
protocol-level re-sends.

The cost is one TCP and TLS handshake per write, a few milliseconds on a LAN (TLS session resumption
keeps it cheap). Reads are unaffected, and the read after a write goes back to the kept-alive
connection.

## Reply nesting limit

A JSON reply nested deeper than `Config::max_reply_depth` levels of objects and arrays (default
256) is refused with a `DecodeError` before anything is built from it; FortiOS replies nest well
under 10 levels. The limit protects callers that copy, compare or print replies, operations that
recurse once per level and would overflow the stack on a hostile body thousands of levels deep. An
error reply (HTTP 400 or above) that is too deep is treated like one that is not JSON: `ApiError`
and `exchange()` keep it as `{"raw": "<body>"}`.

## Partial creates

FortiOS creates are not transactional. When an attribute is rejected after the object was created,
the request fails with an `ApiError` and the object still exists on the device. forti-api does not
clean up behind your back; check with `contains()` and delete it if that is what you want.

## Tracing

`Config::on_exchange` receives every request and reply (method, URL, bodies, status, timing). The
API key travels in a header that is not part of the record. For `Client::download`, the record of a
successful reply has an empty response body, because downloads such as configuration backups are
secrets.
