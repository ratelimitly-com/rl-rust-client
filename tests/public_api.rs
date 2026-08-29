use std::time::Duration;
use std::{net::SocketAddr, str::FromStr};

use ratelimitly::{ApiKey, Client, Decision, LatencyTracker, RequestPolicy, Resource, Schedule};

const SYNTHETIC_NONE_KEY: &str = "rl-none1qyyqwps9qspsyq2sk8e0sfdp3ys";

fn synthetic_api_key() -> ApiKey {
    SYNTHETIC_NONE_KEY.parse().expect("synthetic key is valid")
}

fn inventory_tracker() -> LatencyTracker {
    LatencyTracker::builder("inventory")
        .sample_ttl(Duration::from_secs(10))
        .max_samples(100)
        .min_samples(5)
        .build()
        .expect("tracker definition is valid")
}

#[test]
fn api_key_is_validated_opaque_and_redacted() {
    let key = synthetic_api_key();

    assert_eq!(key.key_id(), 0x0102_0304_0506_0708);
    let debug = format!("{key:?}");
    assert!(debug.contains("REDACTED"));
    assert!(!debug.contains(SYNTHETIC_NONE_KEY));

    let invalid = "not-a-ratelimitly-api-key";
    let error = invalid.parse::<ApiKey>().expect_err("invalid key accepted");
    assert!(!error.to_string().contains(invalid));
    assert!(!format!("{error:?}").contains(invalid));
}

#[test]
fn request_policy_uses_durations_and_validates_its_horizon() {
    let default = RequestPolicy::default();
    assert_eq!(default.horizon(), Duration::from_millis(60));

    let custom = RequestPolicy::builder()
        .unit(Duration::from_millis(25))
        .replays(3)
        .replay_gap(Schedule::fixed(1))
        .final_receive_units(0)
        .completion_delivery(false)
        .build()
        .expect("valid policy");
    assert_eq!(custom.horizon(), Duration::from_millis(100));

    assert!(
        RequestPolicy::builder()
            .unit(Duration::ZERO)
            .build()
            .is_err()
    );
}

#[test]
fn resources_and_trackers_are_content_defined() {
    let checkout = Resource::new("checkout", Duration::from_secs(1), 100)
        .expect("resource definition is valid");
    let changed_rate = Resource::new("checkout", Duration::from_secs(1), 101)
        .expect("resource definition is valid");

    assert_eq!(checkout.name(), "checkout");
    assert_eq!(checkout.window(), Duration::from_secs(1));
    assert_eq!(checkout.rate_limit(), 100);
    assert_ne!(checkout.id(), changed_rate.id());

    let inventory = inventory_tracker();
    let changed_samples = LatencyTracker::builder("inventory")
        .sample_ttl(Duration::from_secs(10))
        .max_samples(101)
        .min_samples(5)
        .build()
        .expect("tracker definition is valid");

    assert_eq!(inventory.name(), "inventory");
    assert_eq!(inventory.sample_ttl(), Duration::from_secs(10));
    assert_eq!(inventory.max_samples(), 100);
    assert_eq!(inventory.min_samples(), 5);
    assert_ne!(inventory.id(), changed_samples.id());
}

#[test]
fn tracker_builder_requires_a_complete_definition() {
    assert!(LatencyTracker::builder("inventory").build().is_err());
}

#[tokio::test]
async fn client_uses_one_key_and_empty_request_grants_locally() {
    let client = Client::builder(synthetic_api_key())
        .build()
        .await
        .expect("client construction succeeds without network access");

    assert_eq!(
        client.service_domain(),
        "c-72623859790382856.p0.ratelimitly.com"
    );

    let response = client
        .request()
        .send()
        .await
        .expect("empty request succeeds locally");
    assert_eq!(response.decision(), Decision::Granted);
    assert!(response.resource_results().is_empty());
    assert!(response.guard_results().is_empty());
    assert_eq!(response.selected_server_id(), None);
}

#[tokio::test]
async fn client_builder_accepts_explicit_service_domain() {
    let dns_server = SocketAddr::from_str("127.0.0.1:5300").expect("valid socket address");
    let client = Client::builder(synthetic_api_key())
        .service_domain("test.ratelimitly.invalid")
        .expect("service domain is valid")
        .dns_server(dns_server)
        .build()
        .await
        .expect("client construction succeeds without network access");

    assert_eq!(client.service_domain(), "test.ratelimitly.invalid");
}

#[tokio::test]
async fn request_builder_accepts_a_bounded_metrics_label() {
    let client = Client::builder(synthetic_api_key())
        .build()
        .await
        .expect("client construction succeeds");

    let _request = client
        .request()
        .metrics_label("checkout-api")
        .expect("short label is valid");
    assert!(client.request().metrics_label("x".repeat(65_527)).is_err());
}

#[tokio::test]
async fn request_builder_validates_token_quantities() {
    let client = Client::builder(synthetic_api_key())
        .build()
        .await
        .expect("client construction succeeds");
    let resource = Resource::new("checkout", Duration::from_secs(1), 100)
        .expect("resource definition itself is valid");

    assert!(client.request().consume(&resource, 0).is_err());
    assert!(client.request().consume(&resource, 70_000).is_err());
}

#[tokio::test]
async fn client_rejects_policy_beyond_api_key_limit_without_disclosing_key() {
    let policy = RequestPolicy::builder()
        .unit(Duration::from_millis(200))
        .replays(1)
        .replay_gap(Schedule::fixed(1))
        .final_receive_units(1)
        .build()
        .expect("policy is structurally valid");

    let error = Client::builder(synthetic_api_key())
        .request_policy(policy)
        .build()
        .await
        .expect_err("policy exceeds the synthetic key's 300 ms limit");

    assert!(!error.to_string().contains(SYNTHETIC_NONE_KEY));
    assert!(!format!("{error:?}").contains(SYNTHETIC_NONE_KEY));
}

#[test]
fn client_is_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Client>();
}
