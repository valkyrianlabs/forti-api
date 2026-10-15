<!--
vl-release staged release notes: the user-facing story of the NEXT release.
Maintained continuously while working; `vlr prepare` promotes it into the release notes
history (and the GitHub release) and resets this file to this template.

Format: the first line is "# <release title>" WITHOUT a version number (vlr adds it).
Everything after the title is the Markdown release body. Describe the resulting behavior
for users and operators; keep it representative of what actually ships.
-->
# Raw downloads, configuration backups and write safety

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

## Writes are never sent twice

libcurl re-sends a request on its own when a reused keep-alive connection turns out to be dead.
For a write that had already reached the FortiGate, that meant running it twice: a second firewall
policy with a new id, a delete reported as "not found", a monitor action executed twice. forti-api
now gives every write (POST, PUT, DELETE) its own new connection, which libcurl never re-sends on,
and closes it afterwards. When the connection drops before the reply, the call throws
`TransportError` with `before_send() == false`: the write may or may not have happened, and it is
never repeated. Each write pays one TCP and TLS handshake (a few milliseconds on a LAN); reads keep
sharing one kept-alive connection.

## Safer object keys and replies

- A key that is exactly `.` or `..` is sent as `%2E` / `%2E%2E`, and paths go out exactly as built.
  Before, libcurl removed such dot segments, so `Addresses::del("..")` addressed a different path
  than the object named.
- JSON replies nested deeper than `Config::max_reply_depth` (256 by default) are refused with a
  `DecodeError`, so a hostile or broken peer cannot make later copies or dumps of the reply
  overflow the stack.

## Meson subprojects

Used as a Meson subproject, forti-api no longer builds its example and tests and no longer installs
its headers and `forti-api.pc` alongside your project. `dependency('forti-api')` and
`forti_api_dep` work as before.
