<!--
vl-release staged changelog: package-facing changes for the NEXT release.
Maintained continuously while working; `vlr prepare` renders it into debian/changelog
and resets this file to this template.

Format: one "- " bullet per change (concise, technical). Indent continuation lines.
Optional "## Section" headings group bullets; if used, every bullet must be under one.
One level of nested "  - " detail bullets is allowed. Consolidate; don't paste commit logs.
-->
- Add fortiapi::system::feed_status() and FeedStatus: a threat feed's loaded
  state, error, file status, accepted/valid/invalid counts, device-wide entry
  cap (limit), overflow flag and last content update, from one entry-list
  request that transfers no entries (start past the end, count=1: FortiOS
  counts valid/invalid only up to the end of the window).
- Add fortiapi::system::feed_entries(feed, start, count): one server-side page
  of a feed's entries; count 0 sends no request.
- feed_state shares the reply parsing; entry validity sent as text is read too.
- Live suite: FORTI_API_LIVE_NO_PURGE=1 skips the leftover purge; new live test
  for feed status counts and paging.
