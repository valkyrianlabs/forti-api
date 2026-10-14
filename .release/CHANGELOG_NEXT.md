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
