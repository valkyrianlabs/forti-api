<!--
vl-release staged changelog: package-facing changes for the NEXT release.
Maintained continuously while working; `vlr prepare` renders it into debian/changelog
and resets this file to this template.

Format: one "- " bullet per change (concise, technical). Indent continuation lines.
Optional "## Section" headings group bullets; if used, every bullet must be under one.
One level of nested "  - " detail bullets is allowed. Consolidate; don't paste commit logs.
-->
- Default DNSProfile domain-filter-table to 0; table 2 made profile creation fail with -3.
- Only write DNS filter profiles that reference the category in global_allow_category and
  ThreatFeed::del; skip the sweep while another feed provides the category.
- Return the FortiGate Response from DNSFilter add/update/del and ThreatFeed::add.
- Add fortiapi::Client (client.hpp): timeouts, keep-alive, percent-encoded paths, Query builder,
  ApiError/TransportError/DecodeError, no retries of mutations after a possible send, redacted
  exchange hook. The pre-generation accessors now use it; the old curl code is gone.
- Request gzip only: FortiOS sends log/* replies as deflate streams libcurl cannot decode.
- Split tests: network-free unit suite (run in CI) and an opt-in live suite (-Dlive_tests=true)
  behind a guard transport and a config-change-log audit.
