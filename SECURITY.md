# Security Policy

## Report privately

Do not open a public issue or pull request for a suspected vulnerability.
Submit it through GitHub's private vulnerability reporting for this repository:

[Open a private security report](https://github.com/ratelimitly-com/rl-rust-client/security/advisories/new)

The report is private to the repository's security maintainers and requires a
GitHub account. GitHub private reporting is the authoritative security contact
for `rl-rust-client`; this project does not advertise an unverified email
alias.

Report vulnerabilities in the Rust client, its published crate, deterministic
fixtures, CI, or release tooling here. If the root cause belongs to another
Ratelimitly component or a third-party dependency, report it to that project as
well and explain the Rust-client impact in this private report.

Test only systems and API keys you own or are explicitly authorized to test.
The local DNS and UDP fixtures are the preferred reproduction environment.

## What to include

Include enough detail for a maintainer to reproduce and assess the report:

- affected commit, crate version, or tag;
- Rust and Cargo versions, operating system, architecture, and Tokio version;
- the request operation and request-policy settings involved;
- minimal reproduction steps and the expected and observed behavior;
- the security impact and required attacker position or preconditions; and
- a proposed mitigation or patch, if available.

Remove API keys, authentication material, customer identifiers, private
hostnames, personal data, and unrelated application data from logs, traces,
configurations, and packet captures. A synthetic fixture reproducer is more
useful than a production capture.

## Supported versions

The crate has not yet made its first public crates.io release. Until then,
security fixes target current `main`; private pre-public tags are not supported
release lines.

After the first public release, security fixes target the latest published
release and current `main` unless release notes explicitly extend support to an
older line. Users of older releases should expect to upgrade. Pre-1.0 releases
do not promise public API compatibility between minor versions.

The supported Rust version and native platform matrix are declared in
`Cargo.toml`, CI, and the release notes. A report affecting another platform is
still welcome, but it does not create an unrecorded support commitment.

## Response and coordinated disclosure

Maintainers aim to acknowledge a private report within three business days,
provide an initial impact assessment within seven business days, and post an
update at least every fourteen calendar days while investigation continues.
These are response targets, not a guarantee that a fix can be produced within
a fixed time.

For a confirmed issue, maintainers will coordinate remediation, supported
version impact, release timing, and public disclosure with the reporter. A
GitHub Security Advisory and CVE request may be used when appropriate. Do not
publish technical details or proof-of-concept code before the agreed disclosure
date. Reporter credit is given only with permission.

## Credential handling

Treat every Ratelimitly API key as a credential even though the public `ApiKey`
type redacts its `Debug` output. Never commit or publish a real key in source,
examples, issues, pull requests, CI logs, process arguments, panic output, test
artifacts, or packet captures.

If a key is exposed, revoke or rotate it through the Ratelimitly control plane,
remove it from accessible logs and artifacts where possible, and record the
affected deployment and time window in the private report. Rewriting one Git
branch does not remove a secret from existing clones, caches, forks, or other
refs.
