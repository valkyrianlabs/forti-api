<!--
vl-release staged release notes: the user-facing story of the NEXT release.
Maintained continuously while working; `vlr prepare` promotes it into the release notes
history (and the GitHub release) and resets this file to this template.

Format: the first line is "# <release title>" WITHOUT a version number (vlr adds it).
Everything after the title is the Markdown release body. Describe the resulting behavior
for users and operators; keep it representative of what actually ships.
-->

# Child tables: change one DHCP reservation, not the whole list

## One entry of a table attribute at a time

`fortiapi::ChildTable<Spec, &Type::attribute>` (also `Table<Spec>::child<&Type::attribute>`) reads
and writes single entries of a table attribute on FortiOS's child paths,
`cmdb/<path>/<parent key>/<attribute>[/<entry key>]`: `list`, `find`, `get`, `contains`, `add`,
`update` and `del`. Until now the only way to change one DHCP reservation, one address in a
policy's `srcaddr` or one access-list rule was `Table::update` with the whole list, so a bug in that
list could drop or change the other entries. Now each write touches one entry:

```cpp
using Reservations = fortiapi::system::dhcp::Servers::child<&fortiapi::system::dhcp::Server::reserved_address>;
fortiapi::system::dhcp::Server::ReservedAddressEntry entry;
entry.id = 0u;                         // the device assigns the next id
entry.ip = "192.0.2.50";
entry.mac = "00:00:5e:00:53:32";
Reservations::add(1, entry);           // POST cmdb/system.dhcp/server/1/reserved-address
Reservations::del(1, 7);               // DELETE cmdb/system.dhcp/server/1/reserved-address/7
```

- `update` sends only the entry's modified and cleared attributes, to the entry's own path.
- Keys are encoded like table keys (one path segment each; `.` and `..` are sent as `%2E` and
  `%2E%2E`), entries decode with the usual `from_json`, writes are never re-sent, and a missing
  entry or parent is an `ApiError` with `not_found()` (`find` returns `std::nullopt`).
- It works for every table attribute of a generated table: every generated `...Entry` struct now
  names its key member (`static constexpr auto mkey = &Entry::id;`, from the schema's mkey), and so
  does `fortiapi::Ref` (`name`).
- Adding an entry whose key exists fails (HTTP 500, FortiOS error -5) and changes nothing; a PUT
  never creates a missing entry.
- `Reply` gains `child_path` and `child_mkey`, and for every write `http_method`, `old_revision` and
  `revision_changed`. On child paths `mkey` names a different key per method: the new entry on POST,
  the parent on PUT, the entry on DELETE (PUT and DELETE also report the entry as `child_mkey`).
  `ChildTable::add` stores a device-assigned key from `child_mkey`, or from `mkey` of a child POST
  reply, and never overwrites a key the caller set.

Validated live on FortiOS 7.4.8 (address-group members and access-list rules), including concurrent
writers: adds and entry updates from separate clients never lose each other's changes, while a PUT of
the parent that includes the table still replaces it silently. A GET's `revision` compared with a
write's `old_revision` shows that something else wrote to the table in between. See the child tables
guide.

## Child tables in the runtime schema

`fortiapi::schema` gains the same child tables for attributes chosen at run time, so a program that
handles any endpoint (forti's command engine) needs no typed model for them. `child_table(endpoint,
attribute)` finds a table attribute with keyed entries. `child_path(endpoint, attribute, parent,
&entry)` builds exactly `ChildTable::path`. `created_entry_key(attribute, reply)` returns the key of
the entry a POST created, by the rule `ChildTable::add` uses, which now has one shared definition.

