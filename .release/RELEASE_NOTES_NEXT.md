<!--
vl-release staged release notes: the user-facing story of the NEXT release.
Maintained continuously while working; `vlr prepare` promotes it into the release notes
history (and the GitHub release) and resets this file to this template.

Format: the first line is "# <release title>" WITHOUT a version number (vlr adds it).
Everything after the title is the Markdown release body. Describe the resulting behavior
for users and operators; keep it representative of what actually ships.
-->
# Safer DNS filter and threat feed writes

- `DNSFilter::add` no longer fails with HTTP 500 on firewalls without a domain filter table: new
  profiles default to no domain filter instead of table 2, which FortiOS rejected after
  half-creating the profile.
- `DNSFilter::global_allow_category` and `ThreatFeed::del` only rewrite DNS filter profiles that
  actually use the category, and `ThreatFeed::del` leaves profiles alone while another feed still
  provides it.
- `DNSFilter::add`, `update`, `del` and `ThreatFeed::add` return the FortiGate response, so callers
  can check `status`.
