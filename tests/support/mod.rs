use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hickory_proto::op::Message;
use hickory_proto::rr::rdata::{A, AAAA, SRV};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;
use tokio::time::{Instant, sleep, timeout};

pub const SERVICE_DOMAIN: &str = "fixture.ratelimitly.com";

const TLV_TENANT: u16 = 0x4C52;
const TLV_AUTH_NONE: u16 = 0x414E;
const PDU_RATE_RESPONSE: u16 = 0x5252;
pub const PDU_RATE_REQUEST: u16 = 0x5452;
pub const PDU_LATENCY_REPORT: u16 = 0x524C;

#[derive(Clone, Debug)]
pub struct Endpoint {
    pub server_id: u64,
    pub address: SocketAddr,
}

struct TaskGuard(JoinHandle<()>);

impl Drop for TaskGuard {
    fn drop(&mut self) {
        self.0.abort();
    }
}

pub struct DnsFixture {
    pub address: SocketAddr,
    _task: TaskGuard,
}

impl DnsFixture {
    pub async fn start(endpoints: Vec<Endpoint>) -> Self {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind DNS fixture");
        let address = socket.local_addr().expect("DNS fixture address");
        let socket = Arc::new(socket);
        let task = tokio::spawn(async move {
            let mut buffer = [0_u8; 2048];
            loop {
                let Ok((length, peer)) = socket.recv_from(&mut buffer).await else {
                    break;
                };
                let Ok(request) = Message::from_vec(&buffer[..length]) else {
                    continue;
                };
                let mut response = request.clone().into_response();
                response.metadata.recursion_available = true;

                for query in &request.queries {
                    match query.query_type() {
                        RecordType::SRV
                            if query.name().to_string().eq_ignore_ascii_case(&format!(
                                "_ratelimitly._udp.{SERVICE_DOMAIN}."
                            )) =>
                        {
                            for endpoint in &endpoints {
                                let target = target_name(endpoint.server_id);
                                response.add_answer(Record::from_rdata(
                                    query.name().clone(),
                                    1,
                                    RData::SRV(SRV::new(10, 1, endpoint.address.port(), target)),
                                ));
                            }
                        }
                        RecordType::A => {
                            if let Some(endpoint) = endpoint_for_name(&endpoints, query.name())
                                && let IpAddr::V4(address) = endpoint.address.ip()
                            {
                                response.add_answer(Record::from_rdata(
                                    query.name().clone(),
                                    1,
                                    RData::A(A(address)),
                                ));
                            }
                        }
                        RecordType::AAAA => {
                            if let Some(endpoint) = endpoint_for_name(&endpoints, query.name())
                                && let IpAddr::V6(address) = endpoint.address.ip()
                            {
                                response.add_answer(Record::from_rdata(
                                    query.name().clone(),
                                    1,
                                    RData::AAAA(AAAA(address)),
                                ));
                            }
                        }
                        _ => {}
                    }
                }

                let Ok(encoded) = response.to_vec() else {
                    continue;
                };
                let _ = socket.send_to(&encoded, peer).await;
            }
        });

        Self {
            address,
            _task: TaskGuard(task),
        }
    }
}

fn target_name(server_id: u64) -> Name {
    Name::from_str(&format!("s-{server_id}.{SERVICE_DOMAIN}."))
        .expect("fixture target is a valid DNS name")
}

fn endpoint_for_name<'a>(endpoints: &'a [Endpoint], name: &Name) -> Option<&'a Endpoint> {
    endpoints
        .iter()
        .find(|endpoint| target_name(endpoint.server_id) == *name)
}

#[derive(Clone, Debug)]
pub enum Reply {
    Ignore,
    Decision {
        delay: Duration,
        granted: bool,
        steering_feedback: bool,
    },
    Malformed {
        delay: Duration,
    },
}

impl Reply {
    pub fn grant(delay: Duration) -> Self {
        Self::Decision {
            delay,
            granted: true,
            steering_feedback: true,
        }
    }

    pub fn reject(delay: Duration) -> Self {
        Self::Decision {
            delay,
            granted: false,
            steering_feedback: true,
        }
    }

    pub fn grant_with_steering(delay: Duration, keep_port: bool) -> Self {
        Self::Decision {
            delay,
            granted: true,
            steering_feedback: keep_port,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ReceivedDatagram {
    pub source: SocketAddr,
    pub pdu_type: Option<u16>,
    pub request_id: Option<[u8; 16]>,
    pub received_at: Instant,
}

pub struct MockServer {
    endpoint: Endpoint,
    received: Arc<Mutex<Vec<ReceivedDatagram>>>,
    _task: TaskGuard,
}

impl MockServer {
    pub async fn start(server_id: u64, replies: Vec<Reply>) -> Self {
        let socket = Arc::new(
            UdpSocket::bind(SocketAddr::new(server_loopback(), 0))
                .await
                .expect("bind mock r-server"),
        );
        let endpoint = Endpoint {
            server_id,
            address: socket.local_addr().expect("mock r-server address"),
        };
        let received = Arc::new(Mutex::new(Vec::new()));
        let task_received = Arc::clone(&received);
        let task_socket = Arc::clone(&socket);
        let task = tokio::spawn(async move {
            let mut buffer = [0_u8; 2048];
            let mut rate_request_index = 0usize;
            loop {
                let Ok((length, source)) = task_socket.recv_from(&mut buffer).await else {
                    break;
                };
                let packet = buffer[..length].to_vec();
                let pdu_type = read_u16(&packet, 44);
                let request_id = packet.get(12..28).and_then(|bytes| bytes.try_into().ok());
                task_received
                    .lock()
                    .expect("received log lock")
                    .push(ReceivedDatagram {
                        source,
                        pdu_type,
                        request_id,
                        received_at: Instant::now(),
                    });

                if pdu_type != Some(PDU_RATE_REQUEST) {
                    continue;
                }
                let reply = replies
                    .get(rate_request_index)
                    .cloned()
                    .unwrap_or(Reply::Ignore);
                rate_request_index += 1;
                let response_socket = Arc::clone(&task_socket);
                match reply {
                    Reply::Ignore => {}
                    Reply::Decision {
                        delay,
                        granted,
                        steering_feedback,
                    } => {
                        let response =
                            build_rate_response(&packet, server_id, granted, steering_feedback);
                        tokio::spawn(async move {
                            sleep(delay).await;
                            let _ = response_socket.send_to(&response, source).await;
                        });
                    }
                    Reply::Malformed { delay } => {
                        let mut response = build_rate_response(&packet, server_id, true, true);
                        response[44..46].copy_from_slice(&0xFFFF_u16.to_le_bytes());
                        tokio::spawn(async move {
                            sleep(delay).await;
                            let _ = response_socket.send_to(&response, source).await;
                        });
                    }
                }
            }
        });

        Self {
            endpoint,
            received,
            _task: TaskGuard(task),
        }
    }

    pub fn endpoint(&self) -> Endpoint {
        self.endpoint.clone()
    }

    pub fn received(&self) -> Vec<ReceivedDatagram> {
        self.received.lock().expect("received log lock").clone()
    }

    pub fn count(&self, pdu_type: u16) -> usize {
        self.received()
            .iter()
            .filter(|item| item.pdu_type == Some(pdu_type))
            .count()
    }

    pub async fn wait_for_count(&self, pdu_type: u16, expected: usize) {
        timeout(Duration::from_secs(2), async {
            while self.count(pdu_type) < expected {
                sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap_or_else(|_| {
            panic!(
                "timed out waiting for {expected} packets of type {pdu_type:#06x}; received {:?}",
                self.received()
            )
        });
    }
}

fn server_loopback() -> IpAddr {
    #[cfg(target_os = "macos")]
    {
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    }
    #[cfg(not(target_os = "macos"))]
    {
        IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)
    }
}

fn build_rate_response(
    request: &[u8],
    server_id: u64,
    granted: bool,
    steering_feedback: bool,
) -> Vec<u8> {
    assert!(request.len() >= 52, "fixture received a truncated request");
    assert_eq!(read_u16(request, 0), Some(TLV_TENANT));
    assert_eq!(read_u16(request, 40), Some(TLV_AUTH_NONE));

    let mut response = request[..40].to_vec();
    response[4..12].copy_from_slice(&server_id.to_le_bytes());
    response[36] = u8::from(steering_feedback);
    response.extend_from_slice(&TLV_AUTH_NONE.to_le_bytes());
    response.extend_from_slice(&4_u16.to_le_bytes());

    let mut body = Vec::new();
    body.extend_from_slice(&0_u16.to_le_bytes());
    body.extend_from_slice(&u16::from(!granted).to_le_bytes());
    if !granted {
        let mut resource = [0_u8; 28];
        resource[24..26].copy_from_slice(&1_u16.to_le_bytes());
        body.extend_from_slice(&resource);
    }
    let pdu_size = 8 + body.len();
    response.extend_from_slice(&PDU_RATE_RESPONSE.to_le_bytes());
    response.extend_from_slice(&(pdu_size as u16).to_le_bytes());
    response.extend_from_slice(&[0_u8; 4]);
    response.extend_from_slice(&body);
    response
}

fn read_u16(data: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        data.get(offset..offset + 2)?.try_into().ok()?,
    ))
}
