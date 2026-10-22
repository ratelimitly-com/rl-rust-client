//! rl #335: production publishes A records only, so every client must reach an
//! IPv4-only r-server. This runs on every CI target, including Windows, where
//! an IPv6 socket is IPv6-only unless the client turns `IPV6_V6ONLY` off.

#[allow(dead_code)]
mod support;

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use ratelimitly::{ApiKey, Client, Decision, Error, RequestPolicy, Resource, Schedule};

use support::{DnsFixture, MockServer, PDU_RATE_REQUEST, Reply, SERVICE_DOMAIN};

const SYNTHETIC_NONE_KEY: &str = "rl-none1qyyqwps9qspsyq2sk8e0sfdp3ys";

#[tokio::test]
async fn reaches_an_ipv4_only_server_discovered_by_name() {
    // SRV -> s-100.<domain> -> A 127.0.0.1, served by an IPv4-only socket.
    let server = MockServer::start_on(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        100,
        vec![Reply::grant(Duration::ZERO)],
    )
    .await;
    let dns = DnsFixture::start(vec![server.endpoint()]).await;

    let client = Client::builder(SYNTHETIC_NONE_KEY.parse::<ApiKey>().expect("key"))
        .service_domain(SERVICE_DOMAIN)
        .expect("fixture service domain is valid")
        .dns_server(dns.address)
        .request_policy(
            RequestPolicy::builder()
                .unit(Duration::from_millis(100))
                .replays(1)
                .replay_gap(Schedule::fixed(1))
                .final_receive_units(1)
                .completion_delivery(false)
                .build()
                .expect("policy"),
        )
        .build()
        .await
        .expect("client builds");

    let resource = Resource::new("ipv4-endpoint", Duration::from_secs(1), 100).expect("resource");
    let result = client
        .request()
        .consume(&resource, 1)
        .expect("consume")
        .send()
        .await;

    if let Err(Error::Communication(error)) = &result {
        let detail = format!(
            "IPv4-only server unreachable: kind={:?} raw_os_error={:?} error={error}",
            error.kind(),
            error.raw_os_error()
        );
        // A GitHub Actions annotation, so the OS error is readable from the API.
        println!("::error title=rl335 ipv4_endpoint::{detail}");
        panic!("{detail}");
    }
    let response = result.expect("request to an IPv4-only server succeeds");
    assert_eq!(response.decision(), Decision::Granted);
    assert_eq!(server.count(PDU_RATE_REQUEST), 1);
}
