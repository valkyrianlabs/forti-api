<!--
vl-release staged release notes: the user-facing story of the NEXT release.
Maintained continuously while working; `vlr prepare` promotes it into the release notes
history (and the GitHub release) and resets this file to this template.

Format: the first line is "# <release title>" WITHOUT a version number (vlr adds it).
Everything after the title is the Markdown release body. Describe the resulting behavior
for users and operators; keep it representative of what actually ships.
-->

# Threat feed status and paging without downloading the feed

## `feed_status`: a feed's counters in one request

`fortiapi::system::feed_status(feed)` returns a `FeedStatus` (`loaded`, `error`, `file_status`,
`accepted`, `valid`, `invalid`, `limit`, `overflow`, `last_update`) from a single
`monitor/system/external-resource/entry-list` request that transfers no entries, so checking a
feed of a million entries costs the same as one of five. Use it to wait for a new feed to load
(`loaded`, with `error` `"Connect pending"` until then), to confirm that a push was applied
(`last_update`, in Unix seconds, advances a few seconds after the push) and to watch capacity:
`limit` is the device-wide entry cap all feeds share (1000000 on a FortiGate-60F), and `overflow`
is FortiOS's flag that a feed is over it. Numbers sent as text are read too; missing values stay 0.

FortiOS counts `valid_count` and `invalid_count` only up to the end of the requested window
(asked for the first entry, it reports one valid entry however large the feed), so `feed_status`
asks for one entry at a start no feed reaches and gets the counts of the whole feed.

## `feed_entries`: one page of entries

`fortiapi::system::feed_entries(feed, start, count)` returns entries `[start, start + count)` in
FortiOS order, paged by FortiOS (one request), for verifying a sample of a large feed. Past the end
or before the feed is loaded the page is short or empty; `count` 0 returns nothing without a
request, since FortiOS would read it as "every entry".

`feed_state` still returns every entry. Validated live on FortiOS 7.4.8: a push of four domains, an
exact duplicate and one invalid entry reports 4 accepted, 4 valid, 1 invalid, and the pages
reassemble the full list. See the threat feeds guide.

## Live suite

`FORTI_API_LIVE_NO_PURGE=1` skips the suite's leftover purge, for a run beside `forti-api-test-*`
objects another run or an operator still uses; each test still removes what it created.
