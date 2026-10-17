<!--
vl-release staged changelog: package-facing changes for the NEXT release.
Maintained continuously while working; `vlr prepare` renders it into debian/changelog
and resets this file to this template.

Format: one "- " bullet per change (concise, technical). Indent continuation lines.
Optional "## Section" headings group bullets; if used, every bullet must be under one.
One level of nested "  - " detail bullets is allowed. Consolidate; don't paste commit logs.
-->

- Add fortiapi::ChildTable<Spec, &Type::attribute> (Table<Spec>::child<...>): list, find, get,
  contains, add, update and del of single entries of a table attribute on cmdb child paths
  (cmdb/<path>/<parent key>/<attribute>[/<entry key>]); updates send only the entry's changes.
- Generated table entry structs and fortiapi::Ref name their key member (static constexpr mkey);
  `mkey` is now a reserved member name in the generator.
- Reply records child_path and child_mkey; on child paths mkey is the parent's key.
