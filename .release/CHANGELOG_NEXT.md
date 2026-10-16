<!--
vl-release staged changelog: package-facing changes for the NEXT release.
Maintained continuously while working; `vlr prepare` renders it into debian/changelog
and resets this file to this template.

Format: one "- " bullet per change (concise, technical). Indent continuation lines.
Optional "## Section" headings group bullets; if used, every bullet must be under one.
One level of nested "  - " detail bullets is allowed. Consolidate; don't paste commit logs.
-->
- New `fortiapi::probe_tls()` (forti_api/tls.hpp): a handshake-only TLS probe
  (CONNECT_ONLY, no request, no credentials) returning trust, the presented chain
  (PEM) and the local IP; an unverified second handshake runs only to collect a
  rejected chain for inspection.
