<!--
vl-release staged release notes: the user-facing story of the NEXT release.
Maintained continuously while working; `vlr prepare` promotes it into the release notes
history (and the GitHub release) and resets this file to this template.

Format: the first line is "# <release title>" WITHOUT a version number (vlr adds it).
Everything after the title is the Markdown release body. Describe the resulting behavior
for users and operators; keep it representative of what actually ships.
-->

# Builds on macOS 15, faster-starting consumers, APT key updates

## Builds on macOS 15 and Intel Macs again

forti-api 1.1's runtime schema parsed decimal numbers with floating-point `std::from_chars`, which
Apple's libc++ provides only from Xcode 26: every consumer failed to compile on macOS 15 (Xcode 16),
including Homebrew source builds there and on Intel Macs. Decimal numbers that FortiOS sends as text
are now parsed through the JSON number grammar (locale-independent, whole text only, as before);
integers still use `from_chars`. FortiOS 7.4.8 has no decimal attributes, so typical reads never take
that path.

## Faster process start for SDK consumers

The runtime schema's tables (`forti_api/gen/schema.hpp`) now have hidden visibility. With default
visibility each was a weak exported symbol, and an executable using the schema spent about 20 ms at
every start resolving thousands of them (forti-cli: 13,600 load-time binds, 25 ms to start; now 600 and
5 ms), with no flag needed in the consumer.

## APT signing key updates arrive through upgrades

`libforti-api-dev` now recommends `valkyrianlabs-archive-keyring`, the package that carries the Valkyrian Labs
APT repository's signing key. Installing `libforti-api-dev` from the repository installs it (APT installs recommended packages by default), and from then on any change
to the key (such as the removal of its expiry date) reaches the machine through normal upgrades
instead of a manual re-download.

- The package owns `/usr/share/keyrings/valkyrianlabs.gpg`. An unmodified copy of the key at
  `/etc/apt/keyrings/valkyrianlabs.gpg` (the path the installation docs used) is replaced by a link to
  it, so existing `signed-by=` source lines keep working unchanged; a modified file is left alone.
- It is a recommendation, not a hard dependency, so the standalone `.deb` from a GitHub release still
  installs on a system without the repository configured. On machines that already have the package,
  install the keyring once with `sudo apt install valkyrianlabs-archive-keyring`.
