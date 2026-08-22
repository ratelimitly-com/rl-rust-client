# Changelog

All notable changes to the `ratelimitly` crate will be documented in this
file. The project follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

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

[Unreleased]: https://github.com/ratelimitly-com/rl-rust-client/commits/main
