#!/usr/bin/env bash
set -euo pipefail

expected=$(printf '%s\n' \
    .cargo_vcs_info.json \
    CHANGELOG.md \
    Cargo.lock \
    Cargo.toml \
    Cargo.toml.orig \
    LICENSE \
    README.md \
    docs/concepts.md \
    docs/configuration.md \
    docs/errors.md \
    docs/ha-policy.md \
    examples/simple_client.rs \
    src/api_key.rs \
    src/api_key_codec.rs \
    src/client.rs \
    src/config.rs \
    src/error.rs \
    src/lib.rs \
    src/model.rs \
    src/protocol.rs \
    src/public_client.rs \
    src/request_policy.rs \
    tests/network_policy.rs \
    tests/public_api.rs \
    tests/support/mod.rs)
actual=$(cargo package --list)

if [[ "$actual" != "$expected" ]]; then
    diff -u <(printf '%s\n' "$expected") <(printf '%s\n' "$actual") || true
    echo "Cargo package contents differ from the reviewed allowlist" >&2
    exit 1
fi

cargo package

archive=$(find target/package -maxdepth 1 -type f -name 'ratelimitly-*.crate' | sort | tail -n 1)
if [[ -z "$archive" ]]; then
    echo "cargo package did not produce a ratelimitly archive" >&2
    exit 1
fi

extract_root=$(mktemp -d)
trap 'rm -rf "$extract_root"' EXIT
tar -xzf "$archive" -C "$extract_root"
package_dir=$(find "$extract_root" -mindepth 1 -maxdepth 1 -type d | head -n 1)
if [[ -z "$package_dir" ]]; then
    echo "Cargo archive did not contain a package directory" >&2
    exit 1
fi

cargo test --manifest-path "$package_dir/Cargo.toml" --all-features
RUSTDOCFLAGS="-D warnings" cargo doc \
    --manifest-path "$package_dir/Cargo.toml" \
    --no-deps \
    --all-features
cargo publish --dry-run
