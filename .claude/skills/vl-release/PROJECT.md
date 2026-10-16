<!-- vl-release:generated-local -- regenerate with `vlr install-local-skill` after changing release.toml; local edits are overwritten -->
# forti-api: release specifics

Generated from this repository's `release.toml`. The general workflow is in `SKILL.md`;
this file says how it applies here.

## Files

| Purpose | Path |
|---|---|
| Release contract | `release.toml` |
| Staged changelog (keep current) | `.release/CHANGELOG_NEXT.md` |
| Staged release notes (keep current) | `.release/RELEASE_NOTES_NEXT.md` |
| Published release notes (do not edit) | `RELEASE_NOTES.md` |
| Published Debian changelog (do not edit) | `debian/changelog` |

## Versions

- Canonical: `VERSION`
- Kept in sync by `vlr version …`: `meson.build` (meson)
- Tags: `vX.Y.Z` on branch `main`; GitHub release title: `vX.Y.Z — <title>`

## Release channels

- **Debian packages** (built by `vlr build-deb` from `debian/`, revision 1):
  - `libforti-api-dev`: architecture `all`; must ship `usr/include/forti_api.hpp`, `usr/include/forti_api/client.hpp`, `usr/include/forti_api/endpoint.hpp`, `usr/include/forti_api/field.hpp`, `usr/include/forti_api/firewall.hpp`, `usr/include/forti_api/gen/all.hpp`, `usr/include/forti_api/gen/firewall/policy.hpp`, `usr/include/forti_api/gen/schema.hpp`, `usr/include/forti_api/schema.hpp`, `usr/include/forti_api/schema_types.hpp`, `usr/include/forti_api/third_party/nlohmann/json.hpp`, `usr/include/forti_api/third_party/nlohmann/LICENSE.MIT`, `usr/share/pkgconfig/forti-api.pc`, `usr/share/doc/libforti-api-dev/copyright`; must never ship `usr/include/nlohmann/*`, `usr/lib/*`, `usr/bin/*`, `*.p12`, `*.cer`, `*/.env`; ships byte-identical copies of `include/forti_api/client.hpp`, `include/forti_api/gen/firewall/policy.hpp`, `third_party/nlohmann/include/nlohmann/json.hpp`
- **APT**: https://apt.valkyrianlabs.com (suite `stable`, components main), published by release CI with `vlr publish-deb`
- **Source archive** of the prepared tree, attached to the GitHub release
- **Homebrew**: formula template `packaging/homebrew/forti-api.rb`, published to `valkyrianlabs/homebrew-tap` as `Formula/forti-api.rb`

## Before considering substantial work complete

```sh
vlr check
```
