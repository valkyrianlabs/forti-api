<!--
vl-release staged release notes: the user-facing story of the NEXT release.
Maintained continuously while working; `vlr prepare` promotes it into the release notes
history (and the GitHub release) and resets this file to this template.

Format: the first line is "# <release title>" WITHOUT a version number (vlr adds it).
Everything after the title is the Markdown release body. Describe the resulting behavior
for users and operators; keep it representative of what actually ships.
-->
# Raw downloads and configuration backups

forti-api can now fetch endpoints that answer with a file instead of JSON, most importantly the
FortiOS configuration backup, so tools can take a backup before a critical change.

```cpp
auto backup = fortiapi::Monitor::download("system/config/backup",
                                          fortiapi::Query().set("scope", "global"));
// backup.body starts with "#config-version=", backup.content_type, backup.content_disposition
```

- `Client::download(api_path, query, options)` (and an overload taking a method and JSON body)
  returns the reply as raw bytes, text or binary, with the HTTP status, `Content-Type` and
  `Content-Disposition`. It uses the same connection, authentication, TLS verification, timeouts
  and retry policy as every other call. HTTP errors still raise `ApiError`, with the FortiOS error
  code and CLI messages when the error body is JSON.
- Memory is bounded: `DownloadOptions::max_bytes` (64 MiB by default) aborts a larger reply with
  `SizeLimitError` and discards what arrived. `DownloadOptions::sink` streams the body in chunks,
  for example straight into a file, instead of holding it in memory.
- `Config::on_exchange` never receives the body of a successful download.
- Custom `Transport` implementations keep compiling unchanged. To bound memory and stream, they can
  honor the new `HttpRequest::max_body` and `on_body` fields and fill `HttpResponse::headers`
  (see the downloads guide).

Configuration backups contain password hashes, keys and the network layout: store them with
owner-only permissions, never log them, and never put them in shared temporary directories.

Validated against FortiOS 7.4.8: `GET monitor/system/config/backup?scope=global` returns the
configuration as `application/octet-stream`.
