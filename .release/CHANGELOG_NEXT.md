<!--
vl-release staged changelog: package-facing changes for the NEXT release.
Maintained continuously while working; `vlr prepare` renders it into debian/changelog
and resets this file to this template.

Format: one "- " bullet per change (concise, technical). Indent continuation lines.
Optional "## Section" headings group bullets; if used, every bullet must be under one.
One level of nested "  - " detail bullets is allowed. Consolidate; don't paste commit logs.
-->

- Recommend valkyrianlabs-archive-keyring so renewed APT signing-key metadata reaches existing installs
  through upgrades (it owns /usr/share/keyrings/valkyrianlabs.gpg and links an unmodified
  /etc/apt/keyrings/valkyrianlabs.gpg to it).
- Portable number parsing: floating-point values sent as text no longer use std::from_chars (missing
  from Apple libc++ before Xcode 26, which broke every build on macOS 15); integers unchanged.
- The runtime schema tables have hidden visibility (#pragma GCC visibility), so consumers' executables
  no longer resolve thousands of weak symbols at start-up (forti-cli: 25 ms to 5 ms).

