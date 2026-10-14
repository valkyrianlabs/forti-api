---
title: Downloads and configuration backups
description: Raw (non-JSON) replies with Client::download, size limits, streaming, and handling backups safely.
order: 55
status: published
tags:
  - guides
---

# Downloads and configuration backups

Most FortiOS endpoints answer with JSON, which `Client::get` and the typed endpoints decode. Some
answer with a file instead: the configuration backup (`monitor/system/config/backup`) is plain
FortiOS configuration text. `Client::download` returns any reply body as raw bytes, text or binary,
without decoding it. It uses the client's transport, authentication, TLS verification, timeouts,
retry policy and error handling.

```cpp
#include <forti_api/monitor.hpp>
using namespace fortiapi;

Download backup = Monitor::download("system/config/backup", Query().set("scope", "global"));
// backup.http_status          200
// backup.content_type         "application/octet-stream" (FortiOS 7.4.8)
// backup.content_disposition  as sent by the device
// backup.body                 the configuration, starting with "#config-version="
// backup.bytes                its size
```

`Monitor::download(relative, query, options, client)` prefixes `monitor/` like `Monitor::get`;
`Client::download(api_path, query, options)` takes a full API path. A second overload,
`Client::download(method, api_path, query, body, options)`, sends any method with an optional JSON
body. POST, PUT and DELETE follow the write retry policy: they are never repeated once they may have
reached the device.

## Limits and streaming

```cpp
struct DownloadOptions {
    std::size_t max_bytes = 64 * 1024 * 1024;
    std::function<void(std::string_view)> sink;
};
```

- `max_bytes` caps the body, buffered or streamed. A larger body aborts the transfer with
  `fortiapi::SizeLimitError` (`limit()` returns the cap). Nothing is returned, the partial buffer is
  overwritten and discarded, and the request is not retried. The limit counts decoded bytes, after
  HTTP compression.
- `sink`, when set, receives the body of a successful reply in chunks as it arrives, and
  `Download::body` stays empty (`bytes` still counts it). Error replies never reach the sink.
  After any exception the sink may hold part of the body, which the caller must discard.

## Errors and retries

- HTTP outside 2xx throws `ApiError`, as `Client::get` does. When the error body is a FortiOS JSON
  envelope, `fortios_error()` and the CLI messages are available; any other body is kept as
  `body()["raw"]`.
- A 2xx reply is returned as it is. If an endpoint can answer either with a file or with a JSON
  envelope, check `content_type`.
- Retries match the rest of the client: GET is retried on transport errors and HTTP 429, 502, 503
  and 504, but not after part of the body has reached a sink, because a sink cannot take data back.
- `Config::on_exchange` records a download like any other request, except that the record of a
  successful reply never carries the body. Error replies are recorded with their body. The API key
  never appears in a record or in an exception message.

## Handling configuration backups

A configuration backup holds the device's whole configuration: password hashes, pre-shared keys,
private keys, API tokens and the network layout. Treat it as a credential.

- Store backups with restrictive permissions (owner read/write only, `0600`), created that way
  rather than tightened afterwards.
- Never log, print or trace a backup, and never put one in an exception message or a crash report.
- Never write backups into shared temporary directories such as `/tmp`; use a private directory
  owned by the service.
- Keep backups in memory no longer than needed. `body` is an ordinary `std::string`: overwrite it
  before releasing it if your threat model calls for it.

Streaming straight into a file created with `0600` keeps the backup out of memory:

```cpp
#include <fcntl.h>
#include <unistd.h>

int fd = ::open("/var/lib/myservice/backups/fw.conf", O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
if (fd < 0) throw std::system_error(errno, std::generic_category(), "backup file");
DownloadOptions options;
options.sink = [fd](std::string_view chunk) {
    while (!chunk.empty()) {
        ssize_t n = ::write(fd, chunk.data(), chunk.size());
        if (n < 0) throw std::system_error(errno, std::generic_category(), "backup write");
        chunk.remove_prefix(static_cast<std::size_t>(n));
    }
};
try {
    Monitor::download("system/config/backup", Query().set("scope", "global"), options);
} catch (...) {
    ::close(fd);
    ::unlink("/var/lib/myservice/backups/fw.conf");   // never keep a partial backup
    throw;
}
::close(fd);
```

On FortiOS 7.4.8 a GET with `scope=global` returns the whole device configuration as
`application/octet-stream`; the live test suite validates this. The web GUI sends a POST to the same
path instead.

## Custom transports

`HttpRequest` carries two fields for downloads, and `HttpResponse` one, all defaulted, so existing
`Transport` implementations compile and work unchanged:

| Field | Meaning |
|---|---|
| `HttpRequest::max_body` | Stop reading once the body exceeds it, and throw `SizeLimitError` |
| `HttpRequest::on_body` | When set, deliver the body of a 2xx reply here in chunks instead of `HttpResponse::body` |
| `HttpResponse::headers` | The final response's headers, as received; `header(name)` looks one up case-insensitively |

`fortiapi::detail::BodyWriter` implements both body rules, and `CurlTransport` uses it. A transport
that ignores them still works: the client then checks the limit and feeds the sink once the whole
body has arrived, so memory is bounded only by the transport.
