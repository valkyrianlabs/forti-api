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
- Reply records child_path, child_mkey, http_method, old_revision and revision_changed. On child
  paths mkey is the new entry's key on POST, the parent's on PUT and the entry's on DELETE
  (FortiOS 7.4.8, validated live); ChildTable::add takes a device-assigned key from child_mkey or
  from mkey of a child POST reply.
- Live suite: the guard admits writes on child paths of forti-api-test-* objects in approved
  collections (name-keyed entries must be forti-api-test-* too); new live tests for address-group
  members, access-list rules, the config-log attribution of child writes and concurrent writers.
