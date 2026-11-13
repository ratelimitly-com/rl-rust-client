# Wide rate windows (source support, unreleased)

Existing `Resource::new` and ID helpers retain their uint32 API and identities.
Use additive `WideResource::new` and `request().consume_wide(&resource, tokens)`
only for explicitly configured servers with capability bit 5. This call is the
opt-in assertion; requests needing >uint32 select QW/RW and have no timeout
fallback. All-short requests retain RT/RR even when using the additive type.
`derive_bucket_id_wide_bytes` retains v1 identities for short mixed members.

ApiKey accepts both credential formats and exposes `format_version()` and
`window_cap(): WindowCap`. Unlimited is a tag, never a TTL; requests are finite
1..31536000000 ms. V1 code31 remains finite4294967295. Guards, latency reporting
and dedup TTLs are unchanged. No writer, release, migration or deployment added.

Run `cargo test --all-features -j1`. Static shared KATs pin versioned caps, exact
resource identities and RT/RR/QW/RW bytes, including mixed short/annual requests.
