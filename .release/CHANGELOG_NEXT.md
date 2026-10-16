<!--
vl-release staged changelog: package-facing changes for the NEXT release.
Maintained continuously while working; `vlr prepare` renders it into debian/changelog
and resets this file to this template.

Format: one "- " bullet per change (concise, technical). Indent continuation lines.
Optional "## Section" headings group bullets; if used, every bullet must be under one.
One level of nested "  - " detail bullets is allowed. Consolidate; don't paste commit logs.
-->

- Documentation: the docs package (docs set forti-api) is rewritten in Payload
  Markdown directives (TOCs, tabs, steps, callouts, cards, badges, buttons),
  with new summary tables for endpoint operations, install locations, retries,
  download calls and filter expressions. The headers and the package contents
  are unchanged.
