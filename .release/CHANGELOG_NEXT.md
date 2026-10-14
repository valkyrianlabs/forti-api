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
- Generate endpoint headers from FortiOS cmdb schema snapshots (tools/fortios, codegen/api.toml,
  include/forti_api/gen): Field<T> with absent/populated/modified/cleared states, Table<Spec> and
  Singleton<Spec>, option constants, decode errors naming the attribute path.
- Treat unset integers reported as "" as absent; accept numbers sent as text.
- Remove the pre-generation API (FortiAPI, FortiAuth, FortiGate::/System:: accessors, types/**);
  port DNS category, threat feed, schedule, service and trusthost helpers onto generated types.
- Add Monitor passthrough, feed_state() and per-command error reporting for push feeds.
- Generate all 487 cmdb endpoints (generate_all from the discovery catalog) and typed read-only
  monitor endpoints from sanitized GUI recon shapes (MonitorGet<Spec>); per-group headers and an
  endpoint registry. Option constants are nested in their types.
- Decode string-keyed maps; reserve preprocessor macro names in generated identifiers.
- Curated names for common firewall tables; Table<Spec>::key exposes the key member.
- Live suite: CRUD round-trips on 24 approved inert collections.
