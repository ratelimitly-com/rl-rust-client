# Ratelimitly Rust client

## What Ratelimitly does

[Ratelimitly](https://ratelimitly.com/) is a distributed admission-control
service. Before beginning work, an application can ask whether the work may
consume one or more rate-limited resources. The same decision can also require
recently measured service latencies to remain below specified thresholds.

The `ratelimitly` crate is the official Rust client. It exposes two independent
operations:

- A **resource request** describes intended work as zero or more resource
  consumptions and zero or more latency guards. Ratelimitly evaluates every
  non-empty request atomically. A grant consumes every requested quantity and
  authorizes the work; a rejection consumes nothing.
- A **latency report** contributes measured service latencies to trackers used
  by future guards. It consumes no resource and makes no admission decision.

An application may use either operation without the other. A typical service
requests admission, performs the work only after a grant, and optionally
reports the measured latency afterward. A dedicated observer may only report
latencies, while another application may only request resources.

## Three outcomes, not two

A non-empty resource request has three application-level outcomes:

1. **Granted**: Ratelimitly consumed every requested quantity; the application
   may perform the work.
2. **Rejected**: Ratelimitly consumed nothing; the application must not perform
   the work.
3. **Failed**: the client did not obtain a decision because of a configuration,
   discovery, communication, or timeout problem.

Failure is neither grant nor rejection. A failure can occur after Ratelimitly
has received the request, so it does not prove that no resource was consumed.
The application must explicitly choose its own fail-open, fail-closed, or
fallback behavior.

## Three small examples

The examples assume that the API key is stored in the
`RATELIMITLY_API_KEY` environment variable and that Tokio runs the async
application:

```rust
use ratelimitly::{ApiKey, Client};

let api_key: ApiKey = std::env::var("RATELIMITLY_API_KEY")?.parse()?;
let client = Client::builder(api_key).build().await?;
```

Never put an API key in source code, examples, command-line arguments, or logs.

### Request one token

In English: “Get me one token for `checkout`, whose limit is 100 tokens per
second.”

```rust
use std::time::Duration;
use ratelimitly::{Decision, Resource};

let checkout = Resource::new(
    "checkout",                 // Stable application-defined resource name.
    Duration::from_secs(1),     // Rate-counter window.
    100,                        // Tokens available in that window.
)?;

let response = client
    .request()
    .consume(&checkout, 1)?     // Request one token.
    .send()
    .await?;                    // Failure is returned as Err.

match response.decision() {
    Decision::Granted => perform_checkout().await?,
    Decision::Rejected => return_service_busy(),
}
```

A grant consumes the token and authorizes `perform_checkout`; a rejection
consumes nothing. `Result::Err` represents failure to obtain a decision.

### Report one measured latency

In English: “Record that one call to `inventory` took 18 ms.”

```rust
use std::time::Duration;
use ratelimitly::LatencyTracker;

let inventory = LatencyTracker::builder("inventory")
    .sample_ttl(Duration::from_secs(10)) // Maximum sample lifetime.
    .max_samples(100)                   // Samples considered by the tracker.
    .min_samples(5)                     // Warm-up before guards take effect.
    .build()?;

client
    .report_latency(
        &inventory,                     // Tracker receiving the sample.
        Duration::from_millis(18),      // Measured service duration.
    )
    .await?;
```

Measure the service operation with a monotonic clock—not the Ratelimitly
request. The report does not request or consume a token.

### Request one token with one latency guard

In English: “Get me one token for `checkout`, but only if the tracked
`inventory` latency is below 100 ms.”

```rust
let response = client
    .request()
    .consume(&checkout, 1)?
    .guard(
        &inventory,                     // Same tracker definition as reports.
        Duration::from_millis(100),     // Admission requires latency < 100 ms.
    )?
    .send()
    .await?;

match response.decision() {
    Decision::Granted => perform_checkout().await?,
    Decision::Rejected => return_service_busy(),
}
```

The resource consumption and guard form one atomic decision. If either fails,
the complete request is rejected and no token is consumed.

## Request shapes

Resource and guard counts are independent:

| Resources | Guards | Behavior |
| --- | --- | --- |
| zero | zero | Local grant; no Ratelimitly request is made. |
| one or more | zero | Resource-consumption request. |
| zero | one or more | Guard-only request. |
| one or more | one or more | Atomic combined decision. |

See [Concepts](docs/concepts.md) for resource identities, latency trackers, and
API-key limits.

## Installation

Add the crate with Cargo:

```bash
cargo add ratelimitly
```

The client is asynchronous and uses Tokio. It requires Rust 1.88 or newer and
uses the Rust 2024 edition. Raising the minimum supported Rust version is a
breaking change and will be reflected in the crate's semantic versioning.

The supported native targets are:

- `x86_64-unknown-linux-gnu` and `aarch64-unknown-linux-gnu`;
- `x86_64-apple-darwin` and `aarch64-apple-darwin`; and
- `x86_64-pc-windows-msvc`.

Other targets are best effort. The first public release is blocked on CI for
the supported platform matrix and Rust 1.88 as well as current stable Rust.

## Documentation

- [Rust API reference](https://docs.rs/ratelimitly)
- [Concepts and operation model](docs/concepts.md)
- [Configuration and API-key handling](docs/configuration.md)
- [High-availability request policy](docs/ha-policy.md)
- [Decisions, failures, and application policy](docs/errors.md)

## License

Licensed under the [MIT License](LICENSE).
