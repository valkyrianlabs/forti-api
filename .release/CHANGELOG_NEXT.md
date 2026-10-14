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
