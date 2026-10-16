<!--
vl-release staged release notes: the user-facing story of the NEXT release.
Maintained continuously while working; `vlr prepare` promotes it into the release notes
history (and the GitHub release) and resets this file to this template.

Format: the first line is "# <release title>" WITHOUT a version number (vlr adds it).
Everything after the title is the Markdown release body. Describe the resulting behavior
for users and operators; keep it representative of what actually ships.
-->
# Documentation in Payload Markdown

The forti-api documentation is now authored with Payload Markdown directives, so the docs site
renders it as structured pages instead of plain Markdown. The content is the same, checked against
the headers; new tables summarize it. The SDK headers and the packages are unchanged.

- **Installation** puts APT, Homebrew, vendoring and the source build side by side in tabs, with a
  table of where each method puts the headers and `forti-api.pc`.
- **Quick start** and **Testing** are numbered steps, and the quick start gains a table of the
  `Table` and `Singleton` operations.
- **Warnings are callouts**: authentication lockout, writes whose outcome is unknown, partial
  creates, tables sent whole, dot-segment keys, helpers that write to every matching DNS filter
  profile, configuration backups as credentials, and the live FortiGate test rules.
- **The overview** links every section through cards, with release, CI and license badges.
- **Reference and guides**: the configuration reference separates environment variables from
  code-only fields, the retry policy is a table, and the download calls and filter expressions
  are summarized in tables.
