# Contributing to rl-rust-client

Thank you for helping improve the official Ratelimitly Rust client. Code,
tests, documentation, examples, and reproducible bug reports are welcome.

Do not open a public issue or pull request for a suspected vulnerability.
Follow the private reporting instructions in [`SECURITY.md`](SECURITY.md).

## Choose a focused change

Keep each pull request limited to one reviewable problem. Open an issue before
investing in a substantial public API, request-policy, compatibility, or
behavioral change so its contract and test approach can be agreed first. Small
fixes and documentation corrections may go directly to a pull request.

Public behavior changes must update their tests, rustdoc, deeper guides, and
changelog entry in the same pull request. Do not document planned behavior as
though it were already implemented.

## Prepare a public checkout

Install [Rust with rustup](https://rustup.rs/). The crate declares Rust 1.88 as
its minimum supported Rust version (MSRV), while normal development uses the
current stable toolchain:

```sh
rustup toolchain install stable --component rustfmt --component clippy
rustup toolchain install 1.88.0
git clone https://github.com/ratelimitly-com/rl-rust-client.git
cd rl-rust-client
```

Create a topic branch from current upstream `main`. Contributors using a fork
should replace `origin` with an `upstream` remote pointing at this repository:

```sh
git fetch origin
git switch -c <short-topic> origin/main
```

Use your own Git identity and email address, or your own GitHub-provided
no-reply address. The project does not assign a shared commit identity.

## Develop and test

Useful focused commands are:

| Change | Focused validation |
| --- | --- |
| Rust source or tests | `cargo test --all-features` |
| Public API or lints | `cargo clippy --all-targets --all-features -- -D warnings` |
| Formatting | `cargo fmt --check` |
| Rustdoc or examples | `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features` |
| Dependency policy | `cargo deny check` |
| Package contents or release files | `bash tools/check-package.sh` |

The deterministic network suite binds local UDP sockets on IPv4 and IPv6
loopback. It uses a synthetic no-auth API key, local DNS, and local r-server
fixtures; it requires no RateLimitly account, production credential, private
repository, or live service.

Before requesting review, run the complete local gate:

```sh
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features
CARGO_RESOLVER_INCOMPATIBLE_RUST_VERSIONS=fallback cargo +1.88.0 test --all-features
cargo deny check
bash tools/check-package.sh
```

`cargo deny` is provided by the
[`cargo-deny`](https://github.com/EmbarkStudios/cargo-deny) project. The package
check performs a crates.io publish dry run and may access the registry, but it
does not upload the crate. `tools/check-package.sh` requires Bash and is run by
the Linux package job in CI; contributors developing on Windows should run the
portable Cargo gates locally and rely on that required job for the package
artifact check.

## Preserve the public boundary

Applications should need only the API exported from `ratelimitly`. Wire-format,
authentication, resolver, and runtime implementation details remain private so
they can evolve without becoming accidental compatibility promises.

When changing public behavior:

- preserve the distinction between a granted decision, a rejected decision,
  and an operational failure;
- keep resource requests and latency reports independent;
- update deterministic failure-path coverage, not only the successful path;
- use reserved names and synthetic credentials in examples and tests; and
- keep API keys, packet captures, private hostnames, local paths, and customer
  identifiers out of commits, logs, fixtures, issues, and pull requests.

## Open a pull request

Review the exact branch before pushing:

```sh
git status --short
git diff --check
git diff --stat origin/main...HEAD
git diff origin/main...HEAD
```

The pull request should explain:

- the problem and user-visible result;
- important API, compatibility, security, or failure-policy decisions;
- tests run locally;
- documentation and examples changed; and
- the related issue, when one exists.

Every required GitHub Actions job must pass. A green workflow does not replace
review; keep the implementation, public documentation, and tests synchronized
with the final reviewed result.
