mod support;

use std::time::Duration;

use hickory_resolver::TokioResolver;
use hickory_resolver::config::{NameServerConfig, ResolverConfig};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use ratelimitly::{ApiKey, Client, Decision, Error, RequestPolicy, Resource, Schedule};
use std::net::{IpAddr, SocketAddr};

use support::{
    DnsFixture, Endpoint, MockServer, PDU_LATENCY_REPORT, PDU_RATE_REQUEST, Reply, SERVICE_DOMAIN,
};

/// RFC 6666 discard-only prefix: syntactically routable, never reachable.
const UNREACHABLE_V6: &str = "100::1";

/// An endpoint this host cannot send to, standing in for the IPv6 address a
/// dual-stack SRV target contributes on an IPv4-only host.
fn unreachable_endpoint(server_id: u64) -> Endpoint {
    Endpoint {
        server_id,
        address: SocketAddr::new(
            IpAddr::V6(UNREACHABLE_V6.parse().expect("discard prefix parses")),
            9,
        ),
    }
}

/// True when this host rejects a datagram to the discard prefix outright.
/// Networks that blackhole it instead cannot exercise a send failure.
fn host_rejects_unreachable_v6() -> bool {
    let Ok(probe) = std::net::UdpSocket::bind("[::]:0") else {
        return false;
    };
    probe
        .send_to(
            b"\x00",
            SocketAddr::new(
                IpAddr::V6(UNREACHABLE_V6.parse().expect("discard prefix parses")),
                9,
            ),
        )
        .is_err()
}

const SYNTHETIC_NONE_KEY: &str = "rl-none1qyyqwps9qspsyq2sk8e0sfdp3ys";

fn synthetic_api_key() -> ApiKey {
    SYNTHETIC_NONE_KEY.parse().expect("synthetic key is valid")
}

fn policy(
    unit_ms: u64,
    replays: u32,
    final_receive_units: u32,
    completion_delivery: bool,
) -> RequestPolicy {
    RequestPolicy::builder()
        .unit(Duration::from_millis(unit_ms))
        .replays(replays)
        .replay_gap(Schedule::fixed(1))
        .final_receive_units(final_receive_units)
        .completion_delivery(completion_delivery)
        .build()
        .expect("test policy is valid")
}

async fn client_for(dns: &DnsFixture, request_policy: RequestPolicy) -> Client {
    Client::builder(synthetic_api_key())
        .service_domain(SERVICE_DOMAIN)
        .expect("fixture service domain is valid")
        .dns_server(dns.address)
        .request_policy(request_policy)
        .build()
        .await
        .expect("fixture client builds")
}

async fn send_resource_request(client: &Client) -> Result<ratelimitly::Response, Error> {
    let resource = Resource::new("network-policy-test", Duration::from_secs(1), 100)?;
    client.request().consume(&resource, 1)?.send().await
}

#[tokio::test]
async fn dns_fixture_answers_srv_queries() {
    let server = MockServer::start(100, vec![]).await;
    let dns = DnsFixture::start(vec![server.endpoint()]).await;
    let mut name_server = NameServerConfig::udp_and_tcp(dns.address.ip());
    for connection in &mut name_server.connections {
        connection.port = dns.address.port();
    }
    let resolver = TokioResolver::builder_with_config(
        ResolverConfig::from_parts(None, Vec::new(), vec![name_server]),
        TokioRuntimeProvider::default(),
    )
    .build()
    .expect("resolver builds");

    let records = resolver
        .srv_lookup(format!("_ratelimitly._udp.{SERVICE_DOMAIN}"))
        .await
        .expect("fixture answers SRV query");
    assert_eq!(records.answers().len(), 1);
}

#[tokio::test]
async fn single_server_request_uses_discovered_endpoint() {
    let server = MockServer::start(100, vec![Reply::grant(Duration::ZERO)]).await;
    let dns = DnsFixture::start(vec![server.endpoint()]).await;
    let client = client_for(&dns, policy(50, 0, 0, false)).await;

    let response = send_resource_request(&client)
        .await
        .expect("request succeeds");

    assert_eq!(response.decision(), Decision::Granted);
    assert_eq!(response.selected_server_id(), Some(100));
    server.wait_for_count(PDU_RATE_REQUEST, 1).await;
}

#[tokio::test]
async fn unreachable_endpoint_does_not_abort_the_request() {
    if !host_rejects_unreachable_v6() {
        eprintln!("skipping: this host accepts datagrams to {UNREACHABLE_V6}");
        return;
    }
    let server = MockServer::start(100, vec![Reply::grant(Duration::ZERO)]).await;
    // The unreachable endpoint is discovered alongside the reachable one, so a
    // successful request proves the send loop continued past its failure.
    let dns = DnsFixture::start(vec![unreachable_endpoint(200), server.endpoint()]).await;
    let client = client_for(&dns, policy(50, 0, 0, false)).await;

    let response = send_resource_request(&client)
        .await
        .expect("request survives an unreachable endpoint");

    assert_eq!(response.decision(), Decision::Granted);
    assert_eq!(response.selected_server_id(), Some(100));
    server.wait_for_count(PDU_RATE_REQUEST, 1).await;
}

#[tokio::test]
async fn request_fails_when_every_endpoint_is_unreachable() {
    if !host_rejects_unreachable_v6() {
        eprintln!("skipping: this host accepts datagrams to {UNREACHABLE_V6}");
        return;
    }
    let dns = DnsFixture::start(vec![unreachable_endpoint(100)]).await;
    let client = client_for(&dns, policy(50, 0, 0, false)).await;

    let error = send_resource_request(&client)
        .await
        .expect_err("no endpoint could be reached");

    assert!(matches!(error, Error::Communication(_)), "got {error:?}");
}

#[tokio::test]
async fn oldest_server_wins_even_when_a_younger_server_responds_first() {
    let oldest = MockServer::start(100, vec![Reply::reject(Duration::from_millis(20))]).await;
    let younger = MockServer::start(200, vec![Reply::grant(Duration::from_millis(1))]).await;
    let dns = DnsFixture::start(vec![oldest.endpoint(), younger.endpoint()]).await;
    let client = client_for(&dns, policy(80, 0, 0, false)).await;

    let response = send_resource_request(&client)
        .await
        .expect("request succeeds");

    assert_eq!(response.decision(), Decision::Rejected);
    assert_eq!(response.selected_server_id(), Some(100));
    oldest.wait_for_count(PDU_RATE_REQUEST, 1).await;
    younger.wait_for_count(PDU_RATE_REQUEST, 1).await;
}

#[tokio::test]
async fn initial_round_fallback_is_followed_by_completion_delivery() {
    let oldest = MockServer::start(100, vec![Reply::Ignore, Reply::Ignore]).await;
    let younger = MockServer::start(200, vec![Reply::grant(Duration::ZERO)]).await;
    let dns = DnsFixture::start(vec![oldest.endpoint(), younger.endpoint()]).await;
    let client = client_for(&dns, policy(50, 1, 0, true)).await;

    let response = send_resource_request(&client)
        .await
        .expect("request succeeds");

    assert_eq!(response.decision(), Decision::Granted);
    assert_eq!(response.selected_server_id(), Some(200));
    oldest.wait_for_count(PDU_RATE_REQUEST, 2).await;
    assert_eq!(younger.count(PDU_RATE_REQUEST), 1);

    let oldest_requests: Vec<_> = oldest
        .received()
        .into_iter()
        .filter(|item| item.pdu_type == Some(PDU_RATE_REQUEST))
        .collect();
    let younger_request = younger
        .received()
        .into_iter()
        .find(|item| item.pdu_type == Some(PDU_RATE_REQUEST))
        .expect("younger server received request");
    assert_eq!(oldest_requests[0].request_id, oldest_requests[1].request_id);
    assert_eq!(oldest_requests[0].request_id, younger_request.request_id);
}

#[tokio::test]
async fn silent_initial_round_replays_to_all_missing_servers() {
    let oldest = MockServer::start(
        100,
        vec![Reply::Ignore, Reply::reject(Duration::from_millis(20))],
    )
    .await;
    let younger = MockServer::start(
        200,
        vec![Reply::Ignore, Reply::grant(Duration::from_millis(1))],
    )
    .await;
    let dns = DnsFixture::start(vec![oldest.endpoint(), younger.endpoint()]).await;
    let client = client_for(&dns, policy(50, 1, 0, false)).await;

    let response = send_resource_request(&client)
        .await
        .expect("request succeeds");

    assert_eq!(response.decision(), Decision::Granted);
    assert_eq!(response.selected_server_id(), Some(200));
    oldest.wait_for_count(PDU_RATE_REQUEST, 2).await;
    younger.wait_for_count(PDU_RATE_REQUEST, 2).await;
}

#[tokio::test]
async fn delayed_response_can_complete_in_the_final_receive_phase() {
    let server = MockServer::start(100, vec![Reply::grant(Duration::from_millis(70))]).await;
    let dns = DnsFixture::start(vec![server.endpoint()]).await;
    let client = client_for(&dns, policy(50, 0, 1, false)).await;

    let response = send_resource_request(&client)
        .await
        .expect("request succeeds");

    assert_eq!(response.decision(), Decision::Granted);
    assert_eq!(response.selected_server_id(), Some(100));
    assert_eq!(server.count(PDU_RATE_REQUEST), 1);
}

#[tokio::test]
async fn malformed_response_is_ignored_and_the_request_is_replayed() {
    let server = MockServer::start(
        100,
        vec![
            Reply::Malformed {
                delay: Duration::ZERO,
            },
            Reply::grant(Duration::ZERO),
        ],
    )
    .await;
    let dns = DnsFixture::start(vec![server.endpoint()]).await;
    let client = client_for(&dns, policy(50, 1, 0, false)).await;

    let response = send_resource_request(&client)
        .await
        .expect("request succeeds");

    assert_eq!(response.decision(), Decision::Granted);
    server.wait_for_count(PDU_RATE_REQUEST, 2).await;
}

#[tokio::test]
async fn silent_horizon_returns_timeout() {
    let server = MockServer::start(100, vec![Reply::Ignore]).await;
    let dns = DnsFixture::start(vec![server.endpoint()]).await;
    let client = client_for(&dns, policy(30, 0, 0, false)).await;

    let error = send_resource_request(&client)
        .await
        .expect_err("silent request must time out");

    assert!(matches!(error, Error::Timeout));
    assert_eq!(server.count(PDU_RATE_REQUEST), 1);
}

#[tokio::test]
async fn latency_report_is_sent_once_to_every_discovered_server() {
    let first = MockServer::start(100, vec![]).await;
    let second = MockServer::start(200, vec![]).await;
    let dns = DnsFixture::start(vec![first.endpoint(), second.endpoint()]).await;
    let client = client_for(&dns, policy(50, 0, 0, false)).await;
    let tracker = ratelimitly::LatencyTracker::builder("inventory")
        .sample_ttl(Duration::from_secs(10))
        .max_samples(20)
        .min_samples(5)
        .build()
        .expect("tracker is valid");

    client
        .report_latency(&tracker, Duration::from_millis(18))
        .await
        .expect("latency report succeeds");

    first.wait_for_count(PDU_LATENCY_REPORT, 1).await;
    second.wait_for_count(PDU_LATENCY_REPORT, 1).await;
    assert_eq!(first.count(PDU_LATENCY_REPORT), 1);
    assert_eq!(second.count(PDU_LATENCY_REPORT), 1);
}

#[tokio::test]
async fn steering_feedback_changes_the_source_port_for_the_next_request() {
    let server = MockServer::start(
        100,
        vec![
            Reply::grant_with_steering(Duration::ZERO, false),
            Reply::grant_with_steering(Duration::ZERO, false),
        ],
    )
    .await;
    let dns = DnsFixture::start(vec![server.endpoint()]).await;
    let client = client_for(&dns, policy(50, 0, 0, false)).await;

    send_resource_request(&client)
        .await
        .expect("first request succeeds");
    send_resource_request(&client)
        .await
        .expect("second request succeeds");
    server.wait_for_count(PDU_RATE_REQUEST, 2).await;

    let requests: Vec<_> = server
        .received()
        .into_iter()
        .filter(|item| item.pdu_type == Some(PDU_RATE_REQUEST))
        .collect();
    assert_ne!(requests[0].source.port(), requests[1].source.port());
    assert_ne!(requests[0].request_id, requests[1].request_id);
    assert!(requests[1].received_at >= requests[0].received_at);
}

#[tokio::test]
async fn steering_waits_for_concurrent_requests_before_rebinding() {
    const CONCURRENT_REQUESTS: usize = 16;
    let mut replies: Vec<_> = (0..CONCURRENT_REQUESTS)
        .map(|index| Reply::grant_with_steering(Duration::from_millis(1 + index as u64 * 3), false))
        .collect();
    replies.push(Reply::grant_with_steering(Duration::ZERO, true));
    let server = MockServer::start(100, replies).await;
    let dns = DnsFixture::start(vec![server.endpoint()]).await;
    let client = client_for(&dns, policy(200, 0, 0, false)).await;

    let mut requests = Vec::with_capacity(CONCURRENT_REQUESTS);
    for _ in 0..CONCURRENT_REQUESTS {
        let client = client.clone();
        requests.push(tokio::spawn(
            async move { send_resource_request(&client).await },
        ));
    }
    for request in requests {
        let response = request
            .await
            .expect("request task does not panic")
            .expect("concurrent request succeeds");
        assert_eq!(response.decision(), Decision::Granted);
    }

    send_resource_request(&client)
        .await
        .expect("request after deferred steering succeeds");
    server
        .wait_for_count(PDU_RATE_REQUEST, CONCURRENT_REQUESTS + 1)
        .await;

    let received: Vec<_> = server
        .received()
        .into_iter()
        .filter(|item| item.pdu_type == Some(PDU_RATE_REQUEST))
        .collect();
    let initial_port = received[0].source.port();
    assert!(
        received[..CONCURRENT_REQUESTS]
            .iter()
            .all(|request| request.source.port() == initial_port)
    );
    assert_ne!(received[CONCURRENT_REQUESTS].source.port(), initial_port);
}
