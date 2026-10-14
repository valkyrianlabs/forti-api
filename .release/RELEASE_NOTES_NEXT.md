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

## New transport: `fortiapi::Client`

- Connect and request timeouts, one kept-alive connection per client (TLS sessions reused), and the
  system trust store unless a CA bundle is configured; the client certificate is optional.
- Object names are percent-encoded (`10.0.0.0/24` stays one path segment) and a `Query` builder covers
  `vdom`, `filter`, `format`, `start`/`count`, `datasource`, `with_meta`, `skip` and `action`.
- FortiOS errors become `ApiError` (HTTP status, FortiOS error code, CLI messages); no output on
  stdout/stderr, and the debug hook never sees the API key.
- Reads retry on throttling and gateway errors; configuration changes are never retried once they may
  have reached the device.
- `FORTIGATE_HOST` + `FORTIGATE_RESOLVE_IP` connect to a pinned address while verifying TLS for the
  hostname.
