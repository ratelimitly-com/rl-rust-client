#![cfg(feature = "traffic-stats")]

#[allow(dead_code)]
mod support;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ratelimitly::{
    ApiKey, Client, LatencyTracker, RequestPolicy, Resource, Schedule, TrafficStats,
};
use support::{
    DnsFixture, Endpoint, MockServer, PDU_RATE_REQUEST, Reply, SERVICE_DOMAIN, build_rate_response,
};
use tokio::net::UdpSocket;
use tokio::time::{sleep, timeout};

const KEY: &str = "rl-none1qyyqwps9qspsyq2sk8e0sfdp3ys";

fn policy() -> RequestPolicy {
    RequestPolicy::builder()
        .unit(Duration::from_millis(100))
        .replays(1)
        .replay_gap(Schedule::fixed(1))
        .final_receive_units(1)
        .completion_delivery(true)
        .build()
        .unwrap()
}

async fn client(dns: &DnsFixture) -> Client {
    Client::builder(KEY.parse::<ApiKey>().unwrap())
        .service_domain(SERVICE_DOMAIN)
        .unwrap()
        .dns_server(dns.address)
        .request_policy(policy())
        .build()
        .await
        .unwrap()
}

// Independent packet-length journal: no protocol-size assumptions in totals.
#[derive(Default)]
struct Journal {
    received: Vec<usize>,
    sent: Vec<usize>,
}

async fn reconcile(ip: IpAddr) {
    let socket = UdpSocket::bind((ip, 0)).await.unwrap();
    let endpoint = Endpoint {
        server_id: 100,
        address: socket.local_addr().unwrap(),
    };
    let journal = Arc::new(Mutex::new(Journal::default()));
    let log = Arc::clone(&journal);
    let server = tokio::spawn(async move {
        let mut buffer = [0; 65536];
        // One resource request and one independent latency report.
        for _ in 0..2 {
            let (len, source) = socket.recv_from(&mut buffer).await.unwrap();
            log.lock().unwrap().received.push(len);
            let packet = &buffer[..len];
            if u16::from_le_bytes(packet[44..46].try_into().unwrap()) == PDU_RATE_REQUEST {
                let response = build_rate_response(packet, 100, true, true);
                for data in [vec![0; 6000], vec![], response.clone(), response] {
                    let sent = socket.send_to(&data, source).await.unwrap();
                    log.lock().unwrap().sent.push(sent);
                }
            }
        }
    });
    let dns = DnsFixture::start(vec![endpoint]).await;
    let client = client(&dns).await;
    assert_eq!(client.traffic_stats(), TrafficStats::default());
    client.request().send().await.unwrap(); // Empty request is local.
    assert_eq!(client.traffic_stats(), TrafficStats::default());
    let resource = Resource::new("traffic", Duration::from_secs(1), 100).unwrap();
    client
        .request()
        .consume(&resource, 1)
        .unwrap()
        .send()
        .await
        .unwrap();
    let tracker = LatencyTracker::builder("traffic")
        .sample_ttl(Duration::from_secs(1))
        .max_samples(10)
        .min_samples(5)
        .build()
        .unwrap();
    client
        .report_latency(&tracker, Duration::from_millis(1))
        .await
        .unwrap();
    timeout(Duration::from_secs(2), server)
        .await
        .unwrap()
        .unwrap();
    timeout(Duration::from_secs(2), async {
        while client.traffic_stats().received.datagrams != 4 {
            sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .unwrap();
    let stats = client.traffic_stats();
    let journal = journal.lock().unwrap();
    let headers = if ip.is_ipv4() { 28 } else { 48 };
    assert_eq!(stats.sent.datagrams, journal.received.len() as u64);
    assert_eq!(
        stats.sent.payload_bytes,
        journal.received.iter().sum::<usize>() as u64
    );
    assert_eq!(
        stats.sent.ip_bytes,
        journal.received.iter().map(|n| n + headers).sum::<usize>() as u64
    );
    assert_eq!(stats.received.datagrams, journal.sent.len() as u64);
    assert_eq!(
        stats.received.payload_bytes,
        journal.sent.iter().sum::<usize>() as u64
    );
    assert_eq!(
        stats.received.ip_bytes,
        journal.sent.iter().map(|n| n + headers).sum::<usize>() as u64
    );
    assert_eq!(stats.send_failures, 0);
    assert!(!stats.incomplete);
    assert_eq!(client.clone().traffic_stats(), stats);
}

#[tokio::test]
async fn ipv4_physical_traffic_matches_independent_journal() {
    reconcile(IpAddr::V4(Ipv4Addr::LOCALHOST)).await;
}

#[tokio::test]
async fn ipv6_physical_traffic_matches_independent_journal() {
    reconcile(IpAddr::V6(Ipv6Addr::LOCALHOST)).await;
}

async fn request(client: &Client) -> Result<ratelimitly::Response, ratelimitly::Error> {
    let resource = Resource::new("traffic", Duration::from_secs(1), 100).unwrap();
    client.request().consume(&resource, 1).unwrap().send().await
}

#[tokio::test]
async fn fanout_replay_and_completion_delivery_are_physical_sends() {
    let oldest = MockServer::start_on(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        100,
        vec![Reply::Ignore, Reply::grant(Duration::ZERO)],
    )
    .await;
    let younger = MockServer::start_on(IpAddr::V4(Ipv4Addr::LOCALHOST), 200, vec![]).await;
    let dns = DnsFixture::start(vec![oldest.endpoint(), younger.endpoint()]).await;
    let client = client(&dns).await;
    request(&client).await.unwrap();
    younger.wait_for_count(PDU_RATE_REQUEST, 3).await;
    let packets: Vec<_> = oldest
        .received()
        .into_iter()
        .chain(younger.received())
        .collect();
    assert_eq!(packets.len(), 5); // initial x2, replay x2, completion x1
    assert!(
        packets
            .iter()
            .all(|p| p.request_id == packets[0].request_id)
    );
    let stats = client.traffic_stats();
    let payload = packets.iter().map(|p| p.payload_bytes as u64).sum::<u64>();
    assert_eq!(stats.sent.datagrams, 5);
    assert_eq!(stats.sent.payload_bytes, payload);
    assert_eq!(stats.sent.ip_bytes, payload + 5 * 28);
    assert_eq!(stats.received.datagrams, 1);
}

#[tokio::test]
async fn timeout_still_reports_sent_bytes_and_no_invented_received_bytes() {
    let server = MockServer::start_on(IpAddr::V4(Ipv4Addr::LOCALHOST), 100, vec![]).await;
    let dns = DnsFixture::start(vec![server.endpoint()]).await;
    let client = client(&dns).await;
    assert!(matches!(
        request(&client).await,
        Err(ratelimitly::Error::Timeout)
    ));
    assert_eq!(client.traffic_stats().sent.datagrams, 2);
    assert_eq!(client.traffic_stats().received.datagrams, 0);
}

#[tokio::test]
async fn steering_does_not_reset_totals_and_independent_clients_start_at_zero() {
    let server = MockServer::start_on(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        100,
        vec![
            Reply::grant_with_steering(Duration::ZERO, false),
            Reply::grant(Duration::ZERO),
        ],
    )
    .await;
    let dns = DnsFixture::start(vec![server.endpoint()]).await;
    let client = client(&dns).await;
    request(&client).await.unwrap();
    request(&client).await.unwrap();
    let packets = server.received();
    assert_ne!(packets[0].source.port(), packets[1].source.port());
    assert_eq!(client.traffic_stats().sent.datagrams, 2);
    assert_eq!(client.traffic_stats().received.datagrams, 2);
    let independent = Client::builder(KEY.parse().unwrap()).build().await.unwrap();
    assert_eq!(independent.traffic_stats(), TrafficStats::default());
}
