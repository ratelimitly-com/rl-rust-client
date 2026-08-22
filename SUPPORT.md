# Support

`rl-rust-client` is the official asynchronous Rust client for Ratelimitly. The
public repository supports the client API, documented request policies, crate
packaging, and the platform/MSRV matrix exercised by CI. It does not provide
support for hosted-service accounts, API-key provisioning, control-plane or
DNS operations, private server infrastructure, or unrelated application code.

## Before opening an issue

1. Read the [README](README.md) and the relevant guide under [`docs/`](docs/).
2. Reproduce the problem against the latest supported release or current
   `main` from a clean checkout.
3. Reduce it to the smallest request, request policy, or client construction
   that still fails.
4. Run `cargo test --all-features` and the narrowest relevant test.
5. Remove API keys, packet contents, private hostnames, customer identifiers,
   and other sensitive data from every example and log.

## What to include

Open a focused [GitHub issue](https://github.com/ratelimitly-com/rl-rust-client/issues)
for reproducible client defects, documentation problems, and focused usage
questions. Include:

- crate version or commit;
- Rust and Cargo versions;
- operating system, architecture, and Tokio version;
- a minimal compilable example using placeholders or the synthetic fixture;
- request-policy settings when relevant;
- expected and observed behavior; and
- the exact validation command and redacted output.

Issues are public by default. Do not include suspected vulnerabilities,
credentials, production packet captures, or sensitive customer data. Follow
[`SECURITY.md`](SECURITY.md) for private vulnerability reporting.

Support is provided on a best-effort basis. An issue records a problem or
question; it does not establish a response-time, remediation, or compatibility
commitment beyond the published documentation and release notes.
