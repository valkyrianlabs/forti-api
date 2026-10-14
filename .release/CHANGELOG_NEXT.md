<!--
vl-release staged changelog: package-facing changes for the NEXT release.
Maintained continuously while working; `vlr prepare` renders it into debian/changelog
and resets this file to this template.

Format: one "- " bullet per change (concise, technical). Indent continuation lines.
Optional "## Section" headings group bullets; if used, every bullet must be under one.
One level of nested "  - " detail bullets is allowed. Consolidate; don't paste commit logs.
-->
- Generate every cmdb endpoint from FortiOS 7.4.8 schema snapshots (487 on a FortiGate-60F) and
  typed read-only monitor endpoints from sanitized GUI recon shapes (tools/fortios, codegen/).
- Add fortiapi::Field<T> (absent/populated/modified/cleared; updates send only changes),
  Table<Spec>, Singleton<Spec>, MonitorGet<Spec>, per-group headers and an endpoint registry.
- Replace the transport with fortiapi::Client: timeouts, keep-alive, percent-encoded keys, Query
  builder, typed errors, no retries of mutations after a possible send, gzip only (FortiOS log
  replies are deflate streams libcurl cannot decode).
- Remove the pre-generation API (FortiAPI, FortiAuth, FortiGate::/System:: accessors, types/**);
  port DNS category, threat feed, schedule, service and trusthost helpers to generated types.
- Decode unset integers reported as "" as absent and numbers sent as text.
- Ship a source archive and a Homebrew formula (valkyrianlabs/homebrew-tap); publish the docs.
- Tests: network-free unit suite (CI, ASan/UBSan); opt-in live suite behind a guard transport and a
  config-change-log audit, with decode coverage of every endpoint and CRUD round-trips on 24
  approved inert collections.
