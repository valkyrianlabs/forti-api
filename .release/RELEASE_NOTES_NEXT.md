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
- `Reply` gains `child_path` and `child_mkey`. On child paths FortiOS reports the parent's key as
  `mkey` and the entry's as `child_mkey`; `ChildTable::add` takes a device-assigned key only from
  `child_mkey` and never overwrites a key the caller set.

The path shapes and replies were checked read-only against FortiOS 7.4.8.
