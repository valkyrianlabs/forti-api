<!--
vl-release staged changelog: package-facing changes for the NEXT release.
Maintained continuously while working; `vlr prepare` renders it into debian/changelog
and resets this file to this template.

Format: one "- " bullet per change (concise, technical). Indent continuation lines.
Optional "## Section" headings group bullets; if used, every bullet must be under one.
One level of nested "  - " detail bullets is allowed. Consolidate; don't paste commit logs.
-->
- Add Client::download and Monitor::download: raw (non-JSON) reply bodies, text or binary, through
  the client's transport, authentication, TLS, timeouts, retry policy and ApiError mapping.
  - DownloadOptions: max_bytes (default 64 MiB; SizeLimitError, partial data wiped, never
    retried) and an optional chunked sink; Download carries status, Content-Type,
    Content-Disposition, body and byte count.
  - on_exchange records of successful downloads omit the body.
  - Transport extension, source-compatible: defaulted HttpRequest::max_body / on_body and
    HttpResponse::headers (with case-insensitive header()); CurlTransport captures headers and
    enforces both through detail::BodyWriter.
- Live suite: read-only configuration backup test (memory only) and FORTI_API_LIVE_READ_ONLY=1,
  which refuses every write and skips the leftover purge.
- Writes are never sent twice: CurlTransport gives every POST/PUT/DELETE a new connection
  (CURLOPT_FRESH_CONNECT, CURLOPT_FORBID_REUSE), HTTP/1.1 and no Expect: 100-continue, so libcurl's
  internal re-send of a request that got nothing back on a reused keep-alive connection
  (Curl_retry_request) can no longer repeat a write that reached the device. A dropped write reply
  is a TransportError with before_send() false. Costs one TCP+TLS handshake per write; reads keep
  the shared connection.
- fortiapi::path() sends a key that is exactly "." or ".." as %2E / %2E%2E, and CurlTransport sets
  CURLOPT_PATH_AS_IS, so such keys can no longer address the table or its parent.
- Config::max_reply_depth (default 256): a 2xx JSON reply nested deeper is a DecodeError, checked
  while parsing (nlohmann parser callback); a too-deep error reply is kept as {"raw": body}.
- As a Meson subproject, forti-api builds no example or tests and installs no headers or .pc;
  standalone builds are unchanged.
