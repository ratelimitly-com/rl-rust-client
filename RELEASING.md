# Releasing the Rust client

This runbook applies to releases of the `ratelimitly` crate on crates.io. The
first public release remains blocked until the public-readiness issue is
complete and the release candidate passes every required repository check.

## Prepare the release

1. Start from a clean, up-to-date `main` branch.
2. Choose the version according to Semantic Versioning and update
   `package.version` in `Cargo.toml`.
3. Move the relevant entries from `Unreleased` in `CHANGELOG.md` into a dated
   version section.
4. Confirm that `rust-version` and the minimum-supported-Rust CI job agree.
5. Confirm the supported Linux, macOS, and Windows target matrix is green.
6. Review `cargo package --list` and confirm that it contains only the public
   source, examples, tests, documentation, license, and changelog.

## Validate the release candidate

Run all checks from a clean checkout of the exact candidate commit:

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features
bash tools/check-package.sh
cargo deny check
```

The package script checks the exact allowlist, builds the `.crate`, extracts it
into a fresh temporary directory, runs its tests and documentation build, and
finishes with `cargo publish --dry-run`. This verifies the artifact that users
receive rather than relying only on the repository checkout.

## Authentication and setup

crates.io publishing uses an API token stored as a GitHub Actions secret:

- Secret name: `CARGO_REGISTRY_TOKEN` (or `CRATES_IO_TOKEN`)
- Permission: Scoped token with publish rights for the `ratelimitly` crate on crates.io

## Publish and verify

1. Obtain approval for the release candidate through the repository's release
   process.
2. In GitHub Actions, manually dispatch the `publish-crates` workflow from `main`
   with version `X.Y.Z` (without the `v` prefix). This workflow validates the
   package contracts and publishes the crate using the `CARGO_REGISTRY_TOKEN` secret.
3. Confirm that crates.io accepted the expected version and that docs.rs built
   its API documentation successfully.
4. From the exact published `main` commit, manually dispatch the `release`
   workflow with `publish` enabled. Do not enable publication merely to test
   the workflow; pull requests and a dispatch with `publish` disabled exercise
   its validation path.
5. The workflow downloads the crate from crates.io and requires it to be
   byte-identical to the reviewed archive before it creates the matching tag,
   provenance attestations, and GitHub release.

Do not place crates.io tokens in the repository, shell history, logs, issues,
or pull requests.
