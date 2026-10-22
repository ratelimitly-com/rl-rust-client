# Changelog

All notable changes to the `ratelimitly` crate will be documented in this
file. The project follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.1] - 2026-10-22

### Fixed

- Reach IPv4-only r-servers from Windows (rl #335). The client sent IPv4
  destinations from an IPv6 socket, which Windows makes IPv6-only by default,
  so every request failed with `WSAEFAULT` (os error 10014). Linux hosts with
  `net.ipv6.bindv6only=1` failed the same way with `ENETUNREACH`. The client
  now clears `IPV6_V6ONLY` on its IPv6 socket on every OS and sends IPv4
  destinations as IPv4-mapped addresses (`::ffff:a.b.c.d`), which Windows
  requires even on a dual-stack socket; replies from a mapped address are
  matched to the IPv4 endpoint.

### Changed

- `socket2` is a dependency on every target, not only Windows.
- Update `thiserror` to 2.0 and `blake2` to 0.11.

## [0.1.0] - 2026-08-30

### Added

- Initial public Rust API for resource requests, latency guards, and latency
  reports.
- Configurable high-availability request policies.
- API-key quota validation and DNS SRV server discovery.
- An explicit DNS-server override for deterministic tests and controlled
  development environments.
- Deterministic public DNS/UDP integration tests for discovery, HA selection,
  retries, completion delivery, timeouts, latency reports, and steering.
- Property tests for untrusted API-key text and UDP response payloads.

### Fixed

- Defer source-port steering until concurrent requests using the active socket
  have completed.
- Preserve the active socket's IPv4 or IPv6 address family when source-port
  steering selects a replacement port.
- Wait for the response router to begin receiving from a replacement socket
  before source-port steering completes.
- Keep replacement source ports monotonic across the dynamic range and use
  exclusive Windows binds so responses cannot be diverted to a more-specific
  local socket sharing the selected port.

[Unreleased]: https://github.com/ratelimitly-com/rl-rust-client/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/ratelimitly-com/rl-rust-client/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/ratelimitly-com/rl-rust-client/releases/tag/v0.1.0
