<!--
vl-release staged release notes: the user-facing story of the NEXT release.
Maintained continuously while working; `vlr prepare` promotes it into the release notes
history (and the GitHub release) and resets this file to this template.

Format: the first line is "# <release title>" WITHOUT a version number (vlr adds it).
Everything after the title is the Markdown release body. Describe the resulting behavior
for users and operators; keep it representative of what actually ships.
-->
# Trust on first use, and a lighter schema for consumers

## See a device's certificate before trusting it

`fortiapi::probe_tls(config)` (`forti_api/tls.hpp`) connects to the FortiGate, completes the TLS
handshake and stops: no HTTP request, no API key, no client certificate. It reports whether the
certificate verified, and the chain as presented, so a person can inspect a self-signed or factory
certificate and pin it as the `ca_bundle`. The device's own certificate works as a trust anchor, and
the host name is still verified. It also reports the local address of the connection, which is what
the FortiGate sees (before any NAT), for example for an API user's trusted host. TLS verification of
requests is unchanged: it cannot be turned off.
