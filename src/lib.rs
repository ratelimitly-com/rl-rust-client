//! The official Rust client for [Ratelimitly](https://ratelimitly.com/).
//!
//! Ratelimitly provides atomic admission decisions for work that consumes
//! rate-limited resources and may depend on latency conditions. This crate has
//! two independent operations:
//!
//! - a [resource request](Client::request) asks whether work may proceed and
//!   may consume one or more [`Resource`] quantities;
//! - a [latency report](Client::report_latency) records one observation for a
//!   [`LatencyTracker`] used by future guards.
//!
//! A non-empty resource request returns either [`Decision::Granted`] or
//! [`Decision::Rejected`]. Failure to obtain a decision is returned as
//! [`Error`], never disguised as a rejection. An empty request is the identity
//! case: it grants locally without contacting Ratelimitly.
//!
//! # Configure and reuse a client
//!
//! API keys are credentials. Load them from protected configuration and treat
//! [`ApiKey`] as opaque. A client owns a UDP socket, DNS discovery state, and a
//! background response task; construct it once and reuse or clone it across
//! requests. The client requires a Tokio runtime.
//!
//! ```no_run
//! use ratelimitly::{ApiKey, Client, RequestPolicy};
//!
//! # async fn configure() -> Result<(), Box<dyn std::error::Error>> {
//! let api_key: ApiKey = std::env::var("RATELIMITLY_API_KEY")?.parse()?;
//! let client = Client::builder(api_key)
//!     .request_policy(RequestPolicy::default())
//!     .build()
//!     .await?;
//! # drop(client);
//! # Ok(())
//! # }
//! ```
//!
//! # Resource-only request
//!
//! A grant consumes the requested quantity and authorizes the protected work.
//! A rejection consumes nothing.
//!
//! ```no_run
//! use std::time::Duration;
//! use ratelimitly::{Client, Decision, Error, Resource};
//!
//! # async fn resource_only(client: &Client) -> Result<(), Error> {
//! let checkout = Resource::new("checkout", Duration::from_secs(1), 100)?;
//! let response = client.request().consume(&checkout, 1)?.send().await?;
//!
//! match response.decision() {
//!     Decision::Granted => { /* perform the admitted work */ }
//!     Decision::Rejected => { /* do not perform the work */ }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # Guard-only request
//!
//! A guard may be evaluated without consuming a resource. The tracker
//! definition used here must match the definition used by reporters.
//!
//! ```no_run
//! use std::time::Duration;
//! use ratelimitly::{Client, Decision, Error, LatencyTracker};
//!
//! # async fn guard_only(client: &Client) -> Result<(), Error> {
//! let inventory = LatencyTracker::builder("inventory")
//!     .sample_ttl(Duration::from_secs(10))
//!     .max_samples(100)
//!     .min_samples(5)
//!     .build()?;
//! let response = client
//!     .request()
//!     .guard(&inventory, Duration::from_millis(100))?
//!     .send()
//!     .await?;
//! assert!(matches!(response.decision(), Decision::Granted | Decision::Rejected));
//! # Ok(())
//! # }
//! ```
//!
//! # Combined request
//!
//! Resource consumptions and latency guards form one atomic decision.
//!
//! ```no_run
//! use std::time::Duration;
//! use ratelimitly::{Client, Error, LatencyTracker, Resource};
//!
//! # async fn combined(client: &Client) -> Result<(), Error> {
//! let checkout = Resource::new("checkout", Duration::from_secs(1), 100)?;
//! let inventory = LatencyTracker::builder("inventory")
//!     .sample_ttl(Duration::from_secs(10))
//!     .max_samples(100)
//!     .min_samples(5)
//!     .build()?;
//! let response = client
//!     .request()
//!     .consume(&checkout, 1)?
//!     .guard(&inventory, Duration::from_millis(100))?
//!     .metrics_label("checkout-api")?
//!     .send()
//!     .await?;
//! # let _ = response;
//! # Ok(())
//! # }
//! ```
//!
//! # Empty request
//!
//! ```no_run
//! use ratelimitly::{Client, Decision, Error};
//!
//! # async fn empty(client: &Client) -> Result<(), Error> {
//! let response = client.request().send().await?;
//! assert_eq!(response.decision(), Decision::Granted);
//! assert_eq!(response.selected_server_id(), None);
//! # Ok(())
//! # }
//! ```
//!
//! # Latency report
//!
//! Measure the protected service operation with a monotonic clock. Reporting
//! is independent of resource admission and does not consume a token.
//!
//! ```no_run
//! use std::time::Duration;
//! use ratelimitly::{Client, Error, LatencyTracker};
//!
//! # async fn report(client: &Client) -> Result<(), Error> {
//! let inventory = LatencyTracker::builder("inventory")
//!     .sample_ttl(Duration::from_secs(10))
//!     .max_samples(100)
//!     .min_samples(5)
//!     .build()?;
//! client
//!     .report_latency(&inventory, Duration::from_millis(18))
//!     .await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Deeper documentation
//!
//! The repository contains guides to the
//! [operation model](https://github.com/ratelimitly-com/rl-rust-client/blob/main/docs/concepts.md),
//! [configuration](https://github.com/ratelimitly-com/rl-rust-client/blob/main/docs/configuration.md),
//! [HA policy](https://github.com/ratelimitly-com/rl-rust-client/blob/main/docs/ha-policy.md),
//! and [failure semantics](https://github.com/ratelimitly-com/rl-rust-client/blob/main/docs/errors.md).

#![warn(missing_docs)]

mod api_key;
mod api_key_codec;
mod client;
mod config;
mod error;
mod model;
mod protocol;
mod public_client;
mod request_policy;

pub use api_key::{ApiKey, ApiKeyError};
pub use error::{ConfigurationError, Error};
pub use model::{
    Decision, GuardResult, LatencyTracker, LatencyTrackerBuilder, LatencyTrackerId, Resource,
    ResourceId, ResourceResult, Response,
};
pub use protocol::{
    derive_bucket_id, derive_bucket_id_bytes, derive_latency_tracker_id,
    derive_latency_tracker_id_bytes,
};
pub use public_client::{Client, ClientBuilder, RequestBuilder};
pub use request_policy::{RequestPolicy, RequestPolicyBuilder, Schedule};
