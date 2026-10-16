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
- Add the runtime schema: forti_api/schema.hpp (fortiapi::schema) with the
  generated tables in forti_api/gen/schema.hpp and their types in
  forti_api/schema_types.hpp.
  - Every endpoint (path, kind, type, table key) and attribute (key, C++
    type, reset value, read-only flag, nested types, options, ranges, sizes,
    references, help); fortiapi::gen::fortios_version.
  - decode, writable, create_body, update_body, diff, key_of, object_path and
    check_values; schema::ValidationError. No typed model is included.
  - A unit test compares the tables and functions with the typed models.
- Tests: the schema comparison runs on a sample of endpoints in the unit suite,
  on every endpoint with -Dexhaustive_tests=true; the live coverage test is
  compiled in 10 shards. Typed-model shards build without debug info or
  sanitizer instrumentation. The package build is unchanged (tests disabled).
