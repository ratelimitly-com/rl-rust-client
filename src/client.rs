// Reference implementation of the r-client.
// Spec references:
// - rl/docs/spec/r-client.md
// - rl/docs/spec/wire_protocol.md
use hickory_resolver::TokioResolver;
use hickory_resolver::config::{NameServerConfig, ResolverConfig};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::rr::RData;
#[cfg(windows)]
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket as StdUdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;
#[cfg(windows)]
use std::{mem, os::windows::io::AsRawSocket};
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, RwLock, mpsc, watch};
use tokio::time::{Instant, timeout};
use uuid::Uuid;
#[cfg(windows)]
use windows_sys::Win32::Networking::WinSock::{
    SO_EXCLUSIVEADDRUSE, SOCKET_ERROR, SOL_SOCKET, setsockopt,
};

use crate::api_key_codec::ApiKeyLimits;
use crate::config::{AuthMethod, CoreConfig};
use crate::error::CoreError;
use crate::error::CoreError as RClientError;
use crate::protocol::{
    GuardBlock, LatencyGuard, PDU_RATE_REQUEST, RateLimitResult, ResourceBlock, ResourceRequest,
    SERVICE_LATENCY_BLOCK_WIRE_LEN, ServiceLatencyReport, TLV_TENANT, TenantHeader, decrypt_pdu,
    derive_bucket_id, derive_latency_tracker_id, encrypt_pdu,
};

pub(crate) struct CoreClient {
    config: Arc<CoreConfig>,
    socket: Arc<RwLock<Arc<UdpSocket>>>,
    socket_epoch: watch::Sender<u64>,
    socket_epoch_ready: Mutex<watch::Receiver<u64>>,
    request_activity: RwLock<()>,
    steering_apply_lock: Mutex<()>,
    steering_pending: AtomicBool,
    inflight: InflightMap,
    response_task: tokio::task::JoinHandle<()>,
    servers: Arc<Mutex<Vec<ServerEndpoint>>>,
    last_dns_refresh: Arc<Mutex<Instant>>,
    server_stats: Arc<Mutex<HashMap<u64, ServerStats>>>, // server_id -> stats
    api_key_limits: ApiKeyLimits,
    cookie_hash_cache: Option<[u8; 32]>, // Cached cookie hash for performance
    aes_key_cache: Option<[u8; 32]>,     // Cached AES key for performance
    resolver: TokioResolver,
    steering_stats: Arc<Mutex<SteeringStats>>,
}

type InflightMap = Arc<StdMutex<HashMap<Uuid, mpsc::UnboundedSender<ResponsePacket>>>>;

const STEERING_PORT_MIN: u16 = 49_152;
const STEERING_PORT_COUNT: usize = u16::MAX as usize - STEERING_PORT_MIN as usize + 1;

struct InflightRegistration {
    request_id: Uuid,
    inflight: InflightMap,
}

impl Drop for InflightRegistration {
    fn drop(&mut self) {
        lock_inflight(&self.inflight).remove(&self.request_id);
    }
}

fn lock_inflight(
    inflight: &StdMutex<HashMap<Uuid, mpsc::UnboundedSender<ResponsePacket>>>,
) -> std::sync::MutexGuard<'_, HashMap<Uuid, mpsc::UnboundedSender<ResponsePacket>>> {
    inflight
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
type RClient = CoreClient;

#[derive(Debug, Default)]
struct SteeringStats {
    feedback_zero_count: u64,
    port_changes: u64,
    last_port: Option<u16>,
    next_port: u16,
}

#[derive(Debug, Clone)]
struct ServerStats {
    last_seen: Instant,
    valid_responses: u64,
    send_failures: u64,
}

#[derive(Debug, Clone)]
struct ServerEndpoint {
    host: String,
    port: u16,
    server_id: Option<u64>,
}

struct ResponsePacket {
    data: Vec<u8>,
    addr: SocketAddr,
}

struct ResolvedTargets {
    targets: Vec<SocketAddr>,
    target_server_ids: HashMap<SocketAddr, u64>,
    allowed_server_ids: HashSet<u64>,
}

const TENANT_TLV_LEN: usize = 40;
const PDU_HEADER_LEN: usize = 8;
const MAX_PACKET_SIZE: usize = 1200;
const SERVER_ID_EPOCH_S_2025: u64 = 1_735_689_600;

enum PduData<'a> {
    Borrowed(&'a [u8]),
    Owned(Vec<u8>),
}

impl<'a> PduData<'a> {
    fn as_slice(&self) -> &[u8] {
        match self {
            Self::Borrowed(data) => data,
            Self::Owned(data) => data.as_slice(),
        }
    }
}

impl ServerStats {
    fn new(now: Instant) -> Self {
        Self {
            last_seen: now,
            valid_responses: 0,
            send_failures: 0,
        }
    }
}

impl CoreClient {
    fn server_start_s_from_id(server_id: u64) -> u64 {
        SERVER_ID_EPOCH_S_2025 + (server_id >> 23)
    }

    pub(crate) async fn new(config: CoreConfig) -> Result<Self, CoreError> {
        // Spec: r-client.md §2.1 (UDP transport) and §3.1 (DNS SRV discovery).
        let socket = Self::bind_udp_socket(0)?;
        let resolver = Self::build_resolver(config.dns_server)?;
        let api_key_limits = config.api_key.limits.clone();
        let dedup_limit = config.api_key.limits.dedup_ttl_ms_max;
        config
            .effective_request_policy()
            .horizon_ms(dedup_limit)
            .map_err(|message| CoreError::Config(message.to_string()))?;

        let cookie_hash_cache = match &config.api_key.auth_method {
            AuthMethod::Cookie(secret) => Some(*secret),
            _ => None,
        };
        let aes_key_cache = match &config.api_key.auth_method {
            AuthMethod::AesGcm(secret) => Some(*secret),
            _ => None,
        };

        let socket = Arc::new(RwLock::new(Arc::new(socket)));
        let (socket_epoch, socket_epoch_rx) = watch::channel(0u64);
        let (socket_epoch_ready_tx, socket_epoch_ready_rx) = watch::channel(0u64);
        let inflight = Arc::new(StdMutex::new(HashMap::new()));

        let router_socket = Arc::clone(&socket);
        let router_inflight = Arc::clone(&inflight);
        let response_task = tokio::spawn(async move {
            CoreClient::response_router(
                router_socket,
                router_inflight,
                socket_epoch_rx,
                socket_epoch_ready_tx,
            )
            .await;
        });
        let initial_last_dns_refresh = Instant::now()
            .checked_sub(Duration::from_secs(
                config.dns_refresh_interval_s.saturating_add(1),
            ))
            .unwrap_or_else(Instant::now);

        let client = Self {
            config: Arc::new(config),
            socket,
            socket_epoch,
            socket_epoch_ready: Mutex::new(socket_epoch_ready_rx),
            request_activity: RwLock::new(()),
            steering_apply_lock: Mutex::new(()),
            steering_pending: AtomicBool::new(false),
            inflight,
            response_task,
            servers: Arc::new(Mutex::new(Vec::new())),
            last_dns_refresh: Arc::new(Mutex::new(initial_last_dns_refresh)),
            server_stats: Arc::new(Mutex::new(HashMap::new())),
            api_key_limits,
            cookie_hash_cache,
            aes_key_cache,
            resolver,
            steering_stats: Arc::new(Mutex::new(SteeringStats::default())),
        };

        Ok(client)
    }

    fn build_resolver(dns_server: Option<SocketAddr>) -> Result<TokioResolver, CoreError> {
        if let Some(address) = dns_server {
            let mut name_server = NameServerConfig::udp_and_tcp(address.ip());
            for connection in &mut name_server.connections {
                connection.port = address.port();
            }
            return TokioResolver::builder_with_config(
                ResolverConfig::from_parts(None, Vec::new(), vec![name_server]),
                TokioRuntimeProvider::default(),
            )
            .build()
            .map_err(|error| CoreError::Dns(error.to_string()));
        }

        TokioResolver::builder_tokio()
            .and_then(|builder| builder.build())
            .map_err(|error| CoreError::Dns(error.to_string()))
    }

    async fn _refresh_servers(&self) -> Result<(), RClientError> {
        let mut servers = self.servers.lock().await;
        let mut last_refresh = self.last_dns_refresh.lock().await;

        // Spec: r-client.md §3.1 (SRV discovery). This reference client is SRV-only.
        // SRV lookup
        let srv_query = format!("_ratelimitly._udp.{}", self.config.api_key.service_domain);
        if let Ok(srv_records) = self.resolver.srv_lookup(srv_query.as_str()).await {
            let mut resolved_servers = Vec::new();
            for answer in srv_records.answers() {
                let RData::SRV(record) = &answer.data else {
                    continue;
                };
                let target = record.target.to_string();
                // Spec: r-client.md §8 (HA server_id). We encode server_id in SRV target as "s-<decimal>".
                let server_id = Self::parse_server_id_from_target(&target);
                if server_id.is_none() {
                    continue;
                }
                if let Ok(ip_addrs) = self.resolver.lookup_ip(target.as_str()).await {
                    for ip in ip_addrs.iter() {
                        resolved_servers.push(ServerEndpoint {
                            host: ip.to_string(),
                            port: record.port,
                            server_id,
                        });
                    }
                }
            }
            if !resolved_servers.is_empty() {
                *servers = resolved_servers;
                *last_refresh = Instant::now();
                return Ok(());
            }
        }

        Err(RClientError::Dns("No SRV servers found".to_string()))
    }

    fn dedup_ttl_ms_limit(&self) -> Option<u32> {
        Some(self.api_key_limits.dedup_ttl_ms_max)
    }

    pub async fn check_rate_limit(
        &self,
        resources: &[ResourceRequest],
        guards: &[LatencyGuard],
        metrics_label: Option<&str>,
    ) -> Result<RateLimitResult, RClientError> {
        // Spec: r-client.md §6.1 (checkRateLimit).
        self._check_rate_limit_with_retries(resources, guards, metrics_label)
            .await
    }

    async fn _check_rate_limit_with_retries(
        &self,
        resources: &[ResourceRequest],
        guards: &[LatencyGuard],
        metrics_label: Option<&str>,
    ) -> Result<RateLimitResult, RClientError> {
        // Spec: r-client.md §8 (broadcast same unique_id to all servers).
        Self::validate_rate_windows_against_quota(
            resources,
            Some(self.api_key_limits.rate_window_size_ms_max),
        )?;
        if resources.is_empty() && guards.is_empty() {
            return Ok(RateLimitResult {
                success: true,
                guard_results: Vec::new(),
                resource_results: Vec::new(),
                server_id: 0,
                steering_feedback: false,
            });
        }

        let policy = self.config.effective_request_policy();
        let dedup_limit = self.dedup_ttl_ms_limit().unwrap_or(u32::MAX);
        let dedup_ttl_ms = policy
            .horizon_ms(dedup_limit)
            .map_err(|message| RClientError::Config(message.to_string()))?;
        self.maybe_periodic_dns_refresh().await?;
        let resolved = self.current_targets().await?;
        if resolved.targets.is_empty() {
            return Err(RClientError::Dns("No servers available".to_string()));
        }

        // A steering response may replace the shared socket, but only after
        // every request already using it has finished. Concurrent requests
        // share this read guard; steering takes the corresponding write guard.
        let request_activity_guard = self.request_activity.read().await;

        let request_id = Uuid::new_v4();
        let tenant_header = self.build_tenant_header(&request_id);
        let pdu_body = Self::build_rate_request_body(resources, guards, metrics_label)?;
        let pdu_data = Self::build_rate_request_pdu(dedup_ttl_ms, pdu_body.as_ref())?;
        let auth_header_size = Self::auth_header_size(&self.config.api_key.auth_method);

        if TENANT_TLV_LEN + auth_header_size + pdu_data.len() > MAX_PACKET_SIZE {
            return Err(RClientError::Protocol(
                "Packet too large for MTU target".to_string(),
            ));
        }

        let mut packet = bytes::BytesMut::with_capacity(MAX_PACKET_SIZE);
        Self::write_tenant_header(&mut packet, &tenant_header);
        self.append_auth_tlv(&mut packet, pdu_data.as_ref())?;

        let (response_tx, mut response_rx) = mpsc::unbounded_channel();
        lock_inflight(&self.inflight).insert(request_id, response_tx);
        let _inflight_registration = InflightRegistration {
            request_id,
            inflight: Arc::clone(&self.inflight),
        };

        let mut seen_server_ids: HashSet<u64> = HashSet::new();
        let mut seen_addrs: HashSet<SocketAddr> = HashSet::new();
        let oldest_server_id = resolved
            .allowed_server_ids
            .iter()
            .copied()
            .min_by(|a, b| Self::compare_server_age(*a, *b));
        let started_at = Instant::now();
        let mut best: Option<RateLimitResult> = None;
        let outcome: Result<Option<RateLimitResult>, RClientError> = async {
            for round in 0..=policy.replay_count {
                self.send_to_missing(&packet, &resolved, &seen_server_ids, &seen_addrs)
                    .await?;
                let units = policy
                    .replay_gap
                    .units(round)
                    .map_err(|message| RClientError::Config(message.to_string()))?;
                let deadline = Instant::now()
                    + Duration::from_millis(policy.unit_ms.saturating_mul(units as u64));
                while Instant::now() < deadline {
                    let remaining = deadline - Instant::now();
                    let received = match timeout(remaining, response_rx.recv()).await {
                        Ok(Some(value)) => value,
                        _ => break,
                    };
                    if let Some(result) = self
                        .accept_policy_response(
                            received,
                            &resolved.allowed_server_ids,
                            &mut seen_server_ids,
                            &mut seen_addrs,
                        )
                        .await
                    {
                        if best.as_ref().is_none_or(|current| {
                            Self::compare_server_age(result.server_id, current.server_id).is_lt()
                        }) {
                            best = Some(result.clone());
                        }
                        if oldest_server_id == Some(result.server_id) || round > 0 {
                            return Ok(best);
                        }
                    }
                }
                if best.is_some() {
                    return Ok(best);
                }
            }

            if policy.final_receive_units > 0 {
                let deadline = Instant::now()
                    + Duration::from_millis(
                        policy
                            .unit_ms
                            .saturating_mul(policy.final_receive_units as u64),
                    );
                while Instant::now() < deadline {
                    let remaining = deadline - Instant::now();
                    let received = match timeout(remaining, response_rx.recv()).await {
                        Ok(Some(value)) => value,
                        _ => break,
                    };
                    if let Some(result) = self
                        .accept_policy_response(
                            received,
                            &resolved.allowed_server_ids,
                            &mut seen_server_ids,
                            &mut seen_addrs,
                        )
                        .await
                    {
                        return Ok(Some(result));
                    }
                }
            }
            Ok(None)
        }
        .await;

        let selected = outcome?;
        if let Some(result) = selected {
            if policy.completion_delivery
                && started_at.elapsed() < Duration::from_millis(dedup_ttl_ms as u64)
            {
                let _ = self
                    .send_to_missing(&packet, &resolved, &seen_server_ids, &seen_addrs)
                    .await;
            }
            drop(request_activity_guard);
            self.apply_steering_feedback(&result).await?;
            Ok(result)
        } else {
            Err(RClientError::Timeout)
        }
    }

    fn compare_server_age(left: u64, right: u64) -> std::cmp::Ordering {
        (Self::server_start_s_from_id(left), left)
            .cmp(&(Self::server_start_s_from_id(right), right))
    }

    async fn send_to_missing(
        &self,
        packet: &[u8],
        resolved: &ResolvedTargets,
        seen_server_ids: &HashSet<u64>,
        seen_addrs: &HashSet<SocketAddr>,
    ) -> Result<(), RClientError> {
        // One unreachable endpoint must not discard the endpoints behind it: a
        // dual-stack SRV target expands to one endpoint per address sharing a
        // server id, so an IPv6 address on an IPv4-only host would otherwise
        // fail every request. Fail only if nothing got out at all.
        let mut attempted = 0usize;
        let mut delivered = 0usize;
        let mut last_error = None;
        // Empty until something fails, so the healthy path allocates nothing.
        let mut failed_server_ids: Vec<u64> = Vec::new();
        {
            let socket = self.socket.read().await;
            for target in &resolved.targets {
                let responded = resolved.target_server_ids.get(target).map_or_else(
                    || seen_addrs.contains(target),
                    |id| seen_server_ids.contains(id),
                );
                if responded {
                    continue;
                }
                attempted += 1;
                match socket.send_to(packet, target).await {
                    Ok(_) => delivered += 1,
                    Err(error) => {
                        if let Some(id) = resolved.target_server_ids.get(target) {
                            failed_server_ids.push(*id);
                        }
                        last_error = Some(error);
                    }
                }
            }
        }
        if delivered == 0 {
            if let Some(error) = last_error {
                return Err(RClientError::Io(error));
            }
        } else if delivered < attempted {
            self.record_send_failures(&failed_server_ids).await;
        }
        Ok(())
    }

    /// Counts endpoints a send could not reach.
    ///
    /// Partial delivery is otherwise invisible: the call still returns `Ok`
    /// through the endpoints that worked, while the HA path selects the oldest
    /// replica's answer, so losing the oldest replica silently downgrades the
    /// result. This is a counter rather than a log line because it sits on the
    /// per-request send path, where a persistently unreachable endpoint would
    /// otherwise emit one record per request for as long as it stays down. The
    /// stats lock is taken after the socket guard is released, and only when
    /// something actually failed.
    async fn record_send_failures(&self, server_ids: &[u64]) {
        if server_ids.is_empty() {
            return;
        }
        let now = Instant::now();
        let mut stats = self.server_stats.lock().await;
        for id in server_ids {
            stats
                .entry(*id)
                .or_insert_with(|| ServerStats::new(now))
                .send_failures += 1;
        }
    }

    async fn accept_policy_response(
        &self,
        packet: ResponsePacket,
        allowed_server_ids: &HashSet<u64>,
        seen_server_ids: &mut HashSet<u64>,
        seen_addrs: &mut HashSet<SocketAddr>,
    ) -> Option<RateLimitResult> {
        let server_id = Self::peek_server_id(&packet.data)?;
        if !allowed_server_ids.is_empty() && !allowed_server_ids.contains(&server_id) {
            return None;
        }
        match self._parse_rate_response(&packet.data) {
            Ok(result) => {
                seen_server_ids.insert(result.server_id);
                seen_addrs.insert(packet.addr);
                let mut stats = self.server_stats.lock().await;
                let now = Instant::now();
                let entry = stats
                    .entry(result.server_id)
                    .or_insert_with(|| ServerStats::new(now));
                entry.last_seen = now;
                entry.valid_responses += 1;
                Some(result)
            }
            Err(_) => None,
        }
    }

    fn validate_rate_windows_against_quota(
        resources: &[ResourceRequest],
        rate_window_size_ms_max: Option<u32>,
    ) -> Result<(), RClientError> {
        let Some(limit) = rate_window_size_ms_max else {
            return Ok(());
        };
        if let Some(resource) = resources
            .iter()
            .find(|resource| resource.window_size_ms > limit)
        {
            return Err(RClientError::Protocol(format!(
                "Resource '{}' window_size_ms {} exceeds rate_window_size_ms_max {}",
                resource.bucket_name, resource.window_size_ms, limit
            )));
        }
        Ok(())
    }

    fn now_millis() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
    }

    fn build_tenant_header(&self, request_id: &Uuid) -> TenantHeader {
        // Spec: r-client.md §5.1 (Tenant Header) and wire_protocol.md §Tenant TLV.
        TenantHeader {
            tlv_type: TLV_TENANT,
            tlv_size: TENANT_TLV_LEN as u16,
            key_id: self.config.api_key.key_id,
            unique_id: *request_id.as_bytes(),
            time_stamp: Self::now_millis(),
            steering_feedback: self.config.api_key.steering_feedback as u8,
            tenant_mgmt_flag: 0,
            padding: [0, 0],
        }
    }

    fn write_tenant_header(packet: &mut bytes::BytesMut, header: &TenantHeader) {
        packet.extend_from_slice(&[0u8; TENANT_TLV_LEN]);
        header.write_to_buffer(&mut packet[..TENANT_TLV_LEN]);
    }

    fn build_rate_request_body(
        resources: &[ResourceRequest],
        guards: &[LatencyGuard],
        metrics_label: Option<&str>,
    ) -> Result<bytes::BytesMut, RClientError> {
        // Spec: wire_protocol.md §rate_request PDU.
        let guard_len = std::mem::size_of::<GuardBlock>();
        let resource_len = std::mem::size_of::<ResourceBlock>();
        let mut body = bytes::BytesMut::with_capacity(
            4 + guards.len() * guard_len + resources.len() * resource_len,
        );
        body.extend_from_slice(&(guards.len() as u16).to_le_bytes());
        body.extend_from_slice(&(resources.len() as u16).to_le_bytes());

        for guard in guards {
            // Spec: r-client.md §5.2 (Guard Block layout).
            let guard_block = GuardBlock {
                latency_tracker_id: derive_latency_tracker_id(
                    &guard.latency_tracker_name,
                    guard.ttl_ms,
                    guard.max_samples,
                    guard.min_sample_threshold,
                ),
                ttl_ms: guard.ttl_ms,
                max_samples: guard.max_samples,
                min_sample_threshold: guard.min_sample_threshold,
                latency_threshold: guard.threshold_ms,
                current_latency: 0,
            };
            let offset = body.len();
            body.resize(offset + guard_len, 0);
            guard_block.write_to_buffer(&mut body[offset..]);
        }

        for resource in resources {
            // Spec: r-client.md §5.3 (Resource Block layout).
            let resource_block = ResourceBlock {
                bucket_id: derive_bucket_id(
                    &resource.bucket_name,
                    resource.window_size_ms,
                    resource.rate_limit,
                ),
                window_size_ms: resource.window_size_ms,
                rate_limit: resource.rate_limit,
                tokens_requested: resource.tokens_requested,
                padding: 0,
            };
            let offset = body.len();
            body.resize(offset + resource_len, 0);
            resource_block.write_to_buffer(&mut body[offset..]);
        }

        if let Some(label) = metrics_label {
            // Spec: wire_protocol.md §Metrics Label TLV.
            Self::append_metrics_label_tlv(&mut body, label)?;
        }

        Ok(body)
    }

    fn build_latency_report_body(reports: &[ServiceLatencyReport]) -> bytes::BytesMut {
        // Spec: wire_protocol.md §latency_report PDU (count + ServiceLatency blocks).
        let block_len = SERVICE_LATENCY_BLOCK_WIRE_LEN;
        let mut body = bytes::BytesMut::with_capacity(4 + reports.len() * block_len);
        body.extend_from_slice(&(reports.len() as u16).to_le_bytes());
        body.extend_from_slice(&[0u8; 2]); // padding

        for report in reports {
            let block = crate::protocol::ServiceLatencyBlock {
                latency_tracker_id: derive_latency_tracker_id(
                    &report.latency_tracker_name,
                    report.ttl_ms,
                    report.max_samples,
                    report.min_sample_threshold,
                ),
                ttl_ms: report.ttl_ms,
                max_samples: report.max_samples,
                min_sample_threshold: report.min_sample_threshold,
                observed_latency: report.observed_latency,
            };
            let offset = body.len();
            body.resize(offset + block_len, 0);
            block.write_to_buffer(&mut body[offset..]);
        }

        body
    }

    fn build_pdu(pdu_type: u16, body: &[u8]) -> Result<bytes::BytesMut, RClientError> {
        // Spec: wire_protocol.md §General PDU Format (pdu_size includes header).
        let pdu_size = PDU_HEADER_LEN + body.len();
        if pdu_size > u16::MAX as usize {
            return Err(RClientError::Protocol("PDU too large".to_string()));
        }

        let mut pdu = bytes::BytesMut::with_capacity(pdu_size);
        pdu.extend_from_slice(&pdu_type.to_le_bytes());
        pdu.extend_from_slice(&(pdu_size as u16).to_le_bytes());
        pdu.extend_from_slice(&[0u8; 4]);
        pdu.extend_from_slice(body);
        Ok(pdu)
    }

    fn build_rate_request_pdu(
        dedup_ttl_ms: u32,
        body: &[u8],
    ) -> Result<bytes::BytesMut, RClientError> {
        let pdu_size = PDU_HEADER_LEN + body.len();
        if pdu_size > u16::MAX as usize {
            return Err(RClientError::Protocol("PDU too large".to_string()));
        }

        let mut pdu = bytes::BytesMut::with_capacity(pdu_size);
        pdu.extend_from_slice(&PDU_RATE_REQUEST.to_le_bytes());
        pdu.extend_from_slice(&(pdu_size as u16).to_le_bytes());
        pdu.extend_from_slice(&dedup_ttl_ms.to_le_bytes());
        pdu.extend_from_slice(body);
        Ok(pdu)
    }

    fn auth_header_size(auth_method: &AuthMethod) -> usize {
        match auth_method {
            AuthMethod::None => 4,
            AuthMethod::Cookie(_) => 36,
            AuthMethod::AesGcm(_) => 32,
        }
    }

    fn append_auth_tlv(
        &self,
        packet: &mut bytes::BytesMut,
        pdu_data: &[u8],
    ) -> Result<(), RClientError> {
        match &self.config.api_key.auth_method {
            AuthMethod::None => {
                // Spec: r-client.md §4.1 (Auth None TLV).
                packet.extend_from_slice(&crate::protocol::TLV_AUTH_NONE.to_le_bytes());
                packet.extend_from_slice(&4u16.to_le_bytes());
                packet.extend_from_slice(pdu_data);
            }
            AuthMethod::Cookie(_) => {
                // Cookie Bech32 stores the canonical 32-byte cookie hash.
                packet.extend_from_slice(&crate::protocol::TLV_AUTH_COOKIE.to_le_bytes());
                packet.extend_from_slice(&36u16.to_le_bytes());
                let cookie = self
                    .cookie_hash_cache
                    .as_ref()
                    .ok_or_else(|| RClientError::Auth("Missing cookie hash cache".to_string()))?;
                packet.extend_from_slice(cookie);
                packet.extend_from_slice(pdu_data);
            }
            AuthMethod::AesGcm(_) => {
                // Spec: r-client.md §4.3 (AES-256-GCM).
                let key = self.aes_key_cache.as_ref().unwrap();
                packet.extend_from_slice(&crate::protocol::TLV_AUTH_AES.to_le_bytes());
                packet.extend_from_slice(&32u16.to_le_bytes());
                let (encrypted_pdu, nonce, auth_tag) = encrypt_pdu(pdu_data, key, packet.as_ref());
                packet.extend_from_slice(&nonce);
                packet.extend_from_slice(&auth_tag);
                packet.extend_from_slice(&encrypted_pdu);
            }
        }
        Ok(())
    }

    fn bind_udp_socket(port: u16) -> Result<UdpSocket, RClientError> {
        #[cfg(target_os = "macos")]
        let socket = Self::bind_udp_socket_for_family(port, false)
            .or_else(|_| Self::bind_udp_socket_for_family(port, true))?;

        #[cfg(not(target_os = "macos"))]
        let socket = Self::bind_udp_socket_for_family(port, true)
            .or_else(|_| Self::bind_udp_socket_for_family(port, false))?;

        Ok(socket)
    }

    fn bind_udp_socket_for_family(port: u16, ipv6: bool) -> Result<UdpSocket, RClientError> {
        let address = if ipv6 {
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port)
        } else {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port)
        };

        #[cfg(not(windows))]
        let std_socket = StdUdpSocket::bind(address)?;

        #[cfg(windows)]
        let std_socket: StdUdpSocket = {
            let domain = if ipv6 { Domain::IPV6 } else { Domain::IPV4 };
            let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
            let exclusive: i32 = 1;
            let result = unsafe {
                setsockopt(
                    socket.as_raw_socket() as usize,
                    SOL_SOCKET,
                    SO_EXCLUSIVEADDRUSE,
                    std::ptr::from_ref(&exclusive).cast(),
                    mem::size_of_val(&exclusive) as i32,
                )
            };
            if result == SOCKET_ERROR {
                return Err(std::io::Error::last_os_error().into());
            }
            socket.bind(&address.into())?;
            socket.into()
        };

        std_socket.set_nonblocking(true)?;
        Ok(UdpSocket::from_std(std_socket)?)
    }

    fn next_steering_port(port: u16) -> u16 {
        if !(STEERING_PORT_MIN..u16::MAX).contains(&port) {
            STEERING_PORT_MIN
        } else {
            port + 1
        }
    }

    fn bind_next_steering_socket(
        next_port: u16,
        current_port: u16,
        ipv6: bool,
    ) -> Result<(UdpSocket, u16), RClientError> {
        let mut candidate = if next_port == 0 {
            Self::next_steering_port(current_port)
        } else {
            next_port
        };
        let mut last_error = None;

        for _ in 0..STEERING_PORT_COUNT {
            match Self::bind_udp_socket_for_family(candidate, ipv6) {
                Ok(socket) => {
                    return Ok((socket, Self::next_steering_port(candidate)));
                }
                Err(RClientError::Io(error)) if error.kind() == std::io::ErrorKind::AddrInUse => {
                    last_error = Some(error);
                    candidate = Self::next_steering_port(candidate);
                }
                Err(error) => return Err(error),
            }
        }

        Err(last_error
            .unwrap_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::AddrNotAvailable,
                    "no exclusive UDP source port is available for steering",
                )
            })
            .into())
    }

    async fn current_targets(&self) -> Result<ResolvedTargets, RClientError> {
        let servers = self.servers.lock().await.clone();
        let mut targets = Vec::with_capacity(servers.len());
        let mut target_server_ids = HashMap::new();
        let mut allowed_server_ids: HashSet<u64> = HashSet::new();

        for server in servers.iter() {
            if let Ok(ip_addr) = server.host.parse::<IpAddr>() {
                let addr = SocketAddr::new(ip_addr, server.port);
                targets.push(addr);
                if let Some(id) = server.server_id {
                    allowed_server_ids.insert(id);
                    target_server_ids.insert(addr, id);
                }
                continue;
            }

            let lookup = self
                .resolver
                .lookup_ip(server.host.as_str())
                .await
                .map_err(|e| RClientError::Dns(e.to_string()))?;
            for ip in lookup.iter() {
                let addr = SocketAddr::new(ip, server.port);
                targets.push(addr);
                if let Some(id) = server.server_id {
                    allowed_server_ids.insert(id);
                    target_server_ids.insert(addr, id);
                }
            }
        }
        Ok(ResolvedTargets {
            targets,
            target_server_ids,
            allowed_server_ids,
        })
    }

    async fn maybe_periodic_dns_refresh(&self) -> Result<(), RClientError> {
        if self.last_dns_refresh.lock().await.elapsed().as_secs()
            > self.config.dns_refresh_interval_s
        {
            self._refresh_servers().await?;
        }
        Ok(())
    }

    fn append_metrics_label_tlv(
        pdu_body: &mut bytes::BytesMut,
        label: &str,
    ) -> Result<(), RClientError> {
        // Spec: wire_protocol.md §Metrics Label TLV (4-byte alignment).
        let label_bytes = label.as_bytes();
        if label_bytes.len() > u16::MAX as usize {
            return Err(RClientError::Protocol("Metrics label too long".to_string()));
        }
        let body_len = 2 + label_bytes.len();
        let padding = (4 - (body_len % 4)) % 4;
        let tlv_size = 4 + body_len + padding;
        if tlv_size > u16::MAX as usize {
            return Err(RClientError::Protocol(
                "Metrics label TLV too large".to_string(),
            ));
        }

        pdu_body.extend_from_slice(&crate::protocol::TLV_METRICS_LABEL.to_le_bytes());
        pdu_body.extend_from_slice(&(tlv_size as u16).to_le_bytes());
        pdu_body.extend_from_slice(&(label_bytes.len() as u16).to_le_bytes());
        pdu_body.extend_from_slice(label_bytes);
        if padding > 0 {
            let pad = [0u8; 4];
            pdu_body.extend_from_slice(&pad[..padding]);
        }

        Ok(())
    }

    fn _parse_rate_response(&self, data: &[u8]) -> Result<RateLimitResult, RClientError> {
        Self::parse_rate_response_with_auth(
            data,
            &self.config.api_key.auth_method,
            self.cookie_hash_cache.as_ref(),
            self.aes_key_cache.as_ref(),
        )
    }

    fn parse_rate_response_with_auth(
        data: &[u8],
        auth_method: &AuthMethod,
        cookie_hash_cache: Option<&[u8; 32]>,
        aes_key_cache: Option<&[u8; 32]>,
    ) -> Result<RateLimitResult, RClientError> {
        let (tenant_header, pos) = Self::parse_tenant_header(data)?;
        // Spec: r-client.md §8 (server overwrites key_id with server_id).
        let server_id = tenant_header.key_id;
        let steering_feedback = tenant_header.steering_feedback != 0;

        // Spec: r-client.md §4 (Auth TLV).
        let pdu_data =
            Self::parse_auth_tlv(data, pos, auth_method, cookie_hash_cache, aes_key_cache)?;
        Self::parse_rate_response_pdu(pdu_data.as_slice(), server_id, steering_feedback)
    }

    fn parse_tenant_header(data: &[u8]) -> Result<(TenantHeader, usize), RClientError> {
        // Spec: wire_protocol.md §Tenant Header TLV.
        let pos = 0;
        if data.len() < pos + 4 {
            return Err(RClientError::Protocol(
                "Buffer too small for Tenant TLV header".to_string(),
            ));
        }
        let tenant_tlv_type = u16::from_le_bytes([data[pos], data[pos + 1]]);
        if tenant_tlv_type != crate::protocol::TLV_TENANT {
            return Err(RClientError::Protocol(format!(
                "Expected Tenant TLV type {:#x}, got {:#x}",
                crate::protocol::TLV_TENANT,
                tenant_tlv_type
            )));
        }
        let tenant_tlv_size = u16::from_le_bytes([data[pos + 2], data[pos + 3]]) as usize;
        if tenant_tlv_size < TENANT_TLV_LEN {
            return Err(RClientError::Protocol("Tenant TLV too small".to_string()));
        }
        if data.len() < pos + tenant_tlv_size {
            return Err(RClientError::Protocol(
                "Buffer too small for Tenant TLV body".to_string(),
            ));
        }
        let tenant_header = TenantHeader::read_from_buffer(&data[pos..pos + tenant_tlv_size])
            .map_err(|e| RClientError::Protocol(e.to_string()))?;
        Ok((tenant_header, pos + tenant_tlv_size))
    }

    fn parse_auth_tlv<'a>(
        data: &'a [u8],
        pos: usize,
        auth_method: &AuthMethod,
        cookie_hash_cache: Option<&[u8; 32]>,
        aes_key_cache: Option<&[u8; 32]>,
    ) -> Result<PduData<'a>, RClientError> {
        if data.len() < pos + 4 {
            return Err(RClientError::Protocol(
                "Buffer too small for Auth TLV header".to_string(),
            ));
        }
        let auth_tlv_type = u16::from_le_bytes([data[pos], data[pos + 1]]);
        let auth_tlv_size = u16::from_le_bytes([data[pos + 2], data[pos + 3]]) as usize;
        if auth_tlv_size < 4 {
            return Err(RClientError::Protocol("Invalid Auth TLV size".to_string()));
        }
        if data.len() < pos + auth_tlv_size {
            return Err(RClientError::Protocol(
                "Buffer too small for Auth TLV body".to_string(),
            ));
        }

        let expected_auth_type = match auth_method {
            AuthMethod::None => crate::protocol::TLV_AUTH_NONE,
            AuthMethod::Cookie(_) => crate::protocol::TLV_AUTH_COOKIE,
            AuthMethod::AesGcm(_) => crate::protocol::TLV_AUTH_AES,
        };
        if auth_tlv_type != expected_auth_type {
            return Err(RClientError::Auth(format!(
                "Auth type mismatch: expected {:#x}, got {:#x}",
                expected_auth_type, auth_tlv_type
            )));
        }

        let pdu_start = pos + auth_tlv_size;
        if data.len() < pdu_start {
            return Err(RClientError::Protocol(
                "Buffer too small for PDU".to_string(),
            ));
        }

        match auth_tlv_type {
            crate::protocol::TLV_AUTH_NONE => {
                if auth_tlv_size != 4 {
                    return Err(RClientError::Protocol(format!(
                        "Invalid size for AUTH_NONE TLV: {}",
                        auth_tlv_size
                    )));
                }
                Ok(PduData::Borrowed(&data[pdu_start..]))
            }
            crate::protocol::TLV_AUTH_COOKIE => {
                if auth_tlv_size != 36 {
                    return Err(RClientError::Protocol(format!(
                        "Invalid size for AUTH_COOKIE TLV: {}",
                        auth_tlv_size
                    )));
                }
                let auth_tlv_body = &data[pos + 4..pos + auth_tlv_size];
                if matches!(auth_method, AuthMethod::Cookie(_)) {
                    let expected = cookie_hash_cache.ok_or_else(|| {
                        RClientError::Auth("Missing cookie hash cache".to_string())
                    })?;
                    if auth_tlv_body != expected {
                        return Err(RClientError::Auth("Cookie auth mismatch".to_string()));
                    }
                }
                Ok(PduData::Borrowed(&data[pdu_start..]))
            }
            crate::protocol::TLV_AUTH_AES => {
                if auth_tlv_size != 32 {
                    return Err(RClientError::Protocol(format!(
                        "Invalid size for AUTH_AES TLV: {}",
                        auth_tlv_size
                    )));
                }
                let auth_tlv_body = &data[pos + 4..pos + auth_tlv_size];
                let mut nonce = [0u8; 12];
                nonce.copy_from_slice(&auth_tlv_body[0..12]);
                let mut auth_tag = [0u8; 16];
                auth_tag.copy_from_slice(&auth_tlv_body[12..28]);

                let key = aes_key_cache
                    .ok_or_else(|| RClientError::Auth("Missing AES key cache".to_string()))?;
                let encrypted_pdu = &data[pdu_start..];
                let aad = &data[..pos + 4 + 12];

                // Spec: r-client.md §4.3 (AES-256-GCM).
                let pdu_data_owned = decrypt_pdu(encrypted_pdu, key, &nonce, &auth_tag, aad)
                    .map_err(|_| RClientError::Protocol("AES decryption failed".to_string()))?;
                Ok(PduData::Owned(pdu_data_owned))
            }
            _ => Err(RClientError::Protocol(format!(
                "Unknown Auth TLV type: {:#x}",
                auth_tlv_type
            ))),
        }
    }

    fn parse_rate_response_pdu(
        pdu_data: &[u8],
        server_id: u64,
        steering_feedback: bool,
    ) -> Result<RateLimitResult, RClientError> {
        // Spec: wire_protocol.md §rate_response PDU.
        if pdu_data.len() < PDU_HEADER_LEN {
            return Err(RClientError::Protocol(
                "Buffer too small for PDU header".to_string(),
            ));
        }
        let pdu_type = u16::from_le_bytes([pdu_data[0], pdu_data[1]]);
        if pdu_type != crate::protocol::PDU_RATE_RESPONSE {
            return Err(RClientError::Protocol(format!(
                "Unexpected PDU type: {:#x}",
                pdu_type
            )));
        }
        let pdu_size = u16::from_le_bytes([pdu_data[2], pdu_data[3]]) as usize;
        if pdu_size < PDU_HEADER_LEN {
            return Err(RClientError::Protocol("Invalid PDU size".to_string()));
        }
        if pdu_data.len() < pdu_size {
            return Err(RClientError::Protocol("Incomplete PDU data".to_string()));
        }
        // pdu_size includes header; body starts after 8-byte header.
        let pdu_body = &pdu_data[PDU_HEADER_LEN..pdu_size];

        if pdu_body.len() < 4 {
            return Err(RClientError::Protocol(
                "Buffer too small for counts".to_string(),
            ));
        }
        let mut pos = 0;
        let guard_count = u16::from_le_bytes([pdu_body[pos], pdu_body[pos + 1]]) as usize;
        pos += 2;
        let resource_count = u16::from_le_bytes([pdu_body[pos], pdu_body[pos + 1]]) as usize;
        pos += 2;

        let guard_len = std::mem::size_of::<GuardBlock>();
        let resource_len = std::mem::size_of::<ResourceBlock>();

        let mut guard_results = Vec::with_capacity(guard_count);
        for _ in 0..guard_count {
            if pdu_body.len() < pos + guard_len {
                return Err(RClientError::Protocol(
                    "Buffer too small for GuardBlock".to_string(),
                ));
            }
            // Spec: wire_protocol.md §rate_response Guard Blocks.
            let block = GuardBlock::read_from_buffer(&pdu_body[pos..])
                .map_err(|e| RClientError::Protocol(e.to_string()))?;
            pos += guard_len;
            guard_results.push(crate::protocol::GuardResult {
                latency_tracker_id: block.latency_tracker_id,
                threshold_ms: block.latency_threshold,
                current_latency_ms: block.current_latency,
                passed: block.current_latency < block.latency_threshold,
            });
        }

        let mut resource_results = Vec::with_capacity(resource_count);
        for _ in 0..resource_count {
            if pdu_body.len() < pos + resource_len {
                return Err(RClientError::Protocol(
                    "Buffer too small for ResourceBlock".to_string(),
                ));
            }
            // Spec: wire_protocol.md §rate_response Resource Blocks.
            let block = ResourceBlock::read_from_buffer(&pdu_body[pos..])
                .map_err(|e| RClientError::Protocol(e.to_string()))?;
            pos += resource_len;
            resource_results.push(crate::protocol::ResourceResult {
                bucket_id: block.bucket_id,
                tokens_deficit: block.tokens_requested,
                actual_rate: block.rate_limit,
            });
        }

        // Spec: wire_protocol.md §rate_response TLV Parameters (optional); trailing TLVs are ignored.

        // Spec: r-client.md §6.1.2 (success requires all guards pass and no deficits).
        let success = guard_results.iter().all(|g| g.passed)
            && resource_results.iter().all(|r| r.tokens_deficit == 0);

        Ok(RateLimitResult {
            success,
            guard_results,
            resource_results,
            server_id,
            steering_feedback,
        })
    }

    fn peek_server_id(data: &[u8]) -> Option<u64> {
        // Spec: r-client.md §8 (server_id stored in response key_id).
        if data.len() < 12 {
            return None;
        }
        let tlv_type = u16::from_le_bytes([data[0], data[1]]);
        let tlv_size = u16::from_le_bytes([data[2], data[3]]) as usize;
        if tlv_type != crate::protocol::TLV_TENANT || tlv_size < 40 || data.len() < tlv_size {
            return None;
        }
        Some(u64::from_le_bytes(data[4..12].try_into().ok()?))
    }

    fn peek_request_id(data: &[u8]) -> Option<Uuid> {
        // Spec: r-client.md §6.1 (unique_id used for request/response correlation).
        if data.len() < 28 {
            return None;
        }
        let tlv_type = u16::from_le_bytes([data[0], data[1]]);
        let tlv_size = u16::from_le_bytes([data[2], data[3]]) as usize;
        if tlv_type != crate::protocol::TLV_TENANT || tlv_size < 40 || data.len() < tlv_size {
            return None;
        }
        Uuid::from_slice(&data[12..28]).ok()
    }

    fn parse_server_id_from_target(target: &str) -> Option<u64> {
        // Spec: r-client.md §3.1 (SRV target). This implementation encodes server_id
        // in the first DNS label as "s-<decimal>" to support HA validation.
        let trimmed = target.trim_end_matches('.');
        let first = trimmed.split('.').next()?;
        let lower = first.to_ascii_lowercase();
        let decimal = lower.strip_prefix("s-")?;
        if decimal.is_empty() {
            return None;
        }
        if decimal.len() > 1 && decimal.starts_with('0') {
            return None;
        }
        if !decimal.chars().all(|c| c.is_ascii_digit()) {
            return None;
        }
        decimal.parse::<u64>().ok()
    }

    async fn response_router(
        socket: Arc<RwLock<Arc<UdpSocket>>>,
        inflight: InflightMap,
        mut socket_epoch_rx: watch::Receiver<u64>,
        socket_epoch_ready: watch::Sender<u64>,
    ) {
        // Spec: r-client.md §6.1 (route responses by unique_id).
        let debug = std::env::var("RCLIENT_DEBUG")
            .map(|v| v != "0")
            .unwrap_or(false);
        let mut buf = [0u8; 2048];
        loop {
            let (active_socket, active_epoch) = {
                let socket = socket.read().await;
                let epoch = *socket_epoch_rx.borrow_and_update();
                (Arc::clone(&socket), epoch)
            };
            socket_epoch_ready.send_replace(active_epoch);
            tokio::select! {
                recv_result = active_socket.recv_from(&mut buf) => {
                    let (len, addr) = match recv_result {
                        Ok(value) => value,
                        Err(err) => {
                            tracing::debug!("[RCLIENT] recv error: {}", err);
                            continue;
                        }
                    };
                    let request_id = match Self::peek_request_id(&buf[..len]) {
                        Some(id) => id,
                        None => {
                            if debug {
                                tracing::debug!("[r-client] drop response from {}: missing request_id", addr);
                            }
                            continue;
                        }
                    };
                    let sender = lock_inflight(&inflight).get(&request_id).cloned();
                    if let Some(sender) = sender {
                        let mut packet = Vec::with_capacity(len);
                        packet.extend_from_slice(&buf[..len]);
                        let _ = sender.send(ResponsePacket { data: packet, addr });
                    } else if debug {
                        tracing::debug!("[r-client] drop response from {}: request_id {} not inflight", addr, request_id);
                    }
                }
                _ = socket_epoch_rx.changed() => {
                    continue;
                }
            }
        }
    }

    async fn apply_steering_feedback(&self, result: &RateLimitResult) -> Result<(), RClientError> {
        if !self.config.api_key.steering_feedback
            || result.steering_feedback
            || self.config.ignore_steering_feedback
        {
            return Ok(());
        }

        // Multiple concurrent responses can carry the same advisory. Coalesce
        // them into one rebind, and wait until all requests using the current
        // socket have drained before changing the source port.
        self.steering_pending.store(true, Ordering::Release);
        let _steering_apply_guard = self.steering_apply_lock.lock().await;
        if !self.steering_pending.load(Ordering::Acquire) {
            return Ok(());
        }
        let _request_activity_guard = self.request_activity.write().await;
        if !self.steering_pending.swap(false, Ordering::AcqRel) {
            return Ok(());
        }

        let mut stats = self.steering_stats.lock().await;
        stats.feedback_zero_count += 1;

        let (current_port, current_is_ipv6) = {
            let socket = self.socket.read().await;
            let address = socket.local_addr()?;
            (address.port(), address.is_ipv6())
        };

        let (new_socket, next_port) =
            Self::bind_next_steering_socket(stats.next_port, current_port, current_is_ipv6)?;
        stats.next_port = next_port;
        let new_socket = Arc::new(new_socket);
        let mut socket_epoch_ready = self.socket_epoch_ready.lock().await;
        let mut socket = self.socket.write().await;
        *socket = new_socket;
        let next_epoch = (*self.socket_epoch.borrow()).wrapping_add(1);
        self.socket_epoch.send_replace(next_epoch);

        let actual_port = socket.local_addr()?.port();
        drop(socket);
        while *socket_epoch_ready.borrow_and_update() != next_epoch {
            socket_epoch_ready.changed().await.map_err(|_| {
                RClientError::Io(std::io::Error::other(
                    "response router stopped during source-port steering",
                ))
            })?;
        }
        if stats.last_port != Some(actual_port) {
            stats.port_changes += 1;
            tracing::debug!(
                "[STEERING] feedback=0 count={}, port_changes={}, old_port={}, new_port={}",
                stats.feedback_zero_count,
                stats.port_changes,
                current_port,
                actual_port
            );
        } else {
            tracing::debug!(
                "[STEERING] WARNING: Port did not change! count={}, port={}",
                stats.feedback_zero_count,
                actual_port
            );
        }
        stats.last_port = Some(actual_port);

        Ok(())
    }

    pub async fn report_latency(
        &self,
        service_latency_reports: &[ServiceLatencyReport],
    ) -> Result<(), RClientError> {
        if service_latency_reports.is_empty() {
            return Ok(());
        }

        if self.last_dns_refresh.lock().await.elapsed().as_secs()
            > self.config.dns_refresh_interval_s
        {
            self._refresh_servers().await?;
        }

        let request_id = Uuid::new_v4();
        let tenant_header = self.build_tenant_header(&request_id);
        let pdu_body = Self::build_latency_report_body(service_latency_reports);
        let pdu_data = Self::build_pdu(crate::protocol::PDU_LATENCY_REPORT, pdu_body.as_ref())?;
        let auth_header_size = Self::auth_header_size(&self.config.api_key.auth_method);

        if TENANT_TLV_LEN + auth_header_size + pdu_data.len() > MAX_PACKET_SIZE {
            return Err(RClientError::Protocol(
                "Packet too large for MTU target".to_string(),
            ));
        }

        let mut packet = bytes::BytesMut::with_capacity(MAX_PACKET_SIZE);
        Self::write_tenant_header(&mut packet, &tenant_header);
        self.append_auth_tlv(&mut packet, pdu_data.as_ref())?;

        let resolved = self.current_targets().await?;
        let targets = resolved.targets;
        let mut delivered = 0usize;
        let mut last_error = None;
        let mut failed_server_ids: Vec<u64> = Vec::new();
        {
            let socket = self.socket.read().await;
            for target in targets.iter() {
                match socket.send_to(&packet, target).await {
                    Ok(_) => delivered += 1,
                    Err(error) => {
                        if let Some(id) = resolved.target_server_ids.get(target) {
                            failed_server_ids.push(*id);
                        }
                        last_error = Some(error);
                    }
                }
            }
        }
        if delivered == 0 {
            if let Some(error) = last_error {
                return Err(RClientError::Io(error));
            }
        } else if delivered < targets.len() {
            self.record_send_failures(&failed_server_ids).await;
        }

        Ok(())
    }
}

impl Drop for CoreClient {
    fn drop(&mut self) {
        self.response_task.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;
    use proptest::prelude::*;

    #[test]
    fn inflight_registration_removes_cancelled_request() {
        let inflight = Arc::new(StdMutex::new(HashMap::new()));
        let request_id = Uuid::new_v4();
        let (sender, _receiver) = mpsc::unbounded_channel();
        lock_inflight(&inflight).insert(request_id, sender);

        let registration = InflightRegistration {
            request_id,
            inflight: Arc::clone(&inflight),
        };
        assert!(lock_inflight(&inflight).contains_key(&request_id));
        drop(registration);
        assert!(!lock_inflight(&inflight).contains_key(&request_id));
    }

    #[tokio::test]
    async fn family_specific_bind_preserves_the_requested_address_family() {
        let ipv4 = RClient::bind_udp_socket_for_family(0, false)
            .expect("IPv4 is available on supported CI runners");
        assert!(ipv4.local_addr().expect("IPv4 local address").is_ipv4());

        let ipv6 = RClient::bind_udp_socket_for_family(0, true)
            .expect("IPv6 is available on supported CI runners");
        assert!(ipv6.local_addr().expect("IPv6 local address").is_ipv6());
    }

    #[test]
    fn steering_ports_advance_monotonically_and_wrap_once_at_the_boundary() {
        assert_eq!(
            RClient::next_steering_port(STEERING_PORT_MIN),
            STEERING_PORT_MIN + 1
        );
        assert_eq!(RClient::next_steering_port(u16::MAX - 1), u16::MAX);
        assert_eq!(RClient::next_steering_port(u16::MAX), STEERING_PORT_MIN);
        assert_eq!(RClient::next_steering_port(40_000), STEERING_PORT_MIN);
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn steering_skips_a_port_owned_by_a_specific_windows_socket() {
        let occupied = UdpSocket::bind(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0))
            .await
            .expect("bind a specific-address blocker");
        let occupied_port = occupied.local_addr().expect("blocker address").port();
        assert!(occupied_port >= STEERING_PORT_MIN);

        let (steered, following_port) =
            RClient::bind_next_steering_socket(occupied_port, occupied_port - 1, true)
                .expect("exclusive steering skips the occupied specific-address port");
        let selected_port = steered.local_addr().expect("steered address").port();

        assert_ne!(selected_port, occupied_port);
        assert_eq!(selected_port, RClient::next_steering_port(occupied_port));
        assert_eq!(following_port, RClient::next_steering_port(selected_port));
    }

    #[test]
    fn metrics_label_tlv_encoding() {
        let mut body = BytesMut::new();
        RClient::append_metrics_label_tlv(&mut body, "api").expect("tlv");

        let expected = [
            0x4D, 0x4C, // TLV type (LE)
            0x0C, 0x00, // TLV size = 12
            0x03, 0x00, // label length = 3
            b'a', b'p', b'i', 0x00, 0x00, 0x00, // padding
        ];
        assert_eq!(&body[..], &expected);
    }

    #[test]
    fn aes_gcm_aad_rejects_tamper() {
        let key = [0x11u8; 32];
        let aad_prefix = [0x22u8; 44];
        let pdu = b"\x52\x54\x0c\x00\x2c\x01\x00\x00";

        let (encrypted_pdu, nonce, auth_tag) = encrypt_pdu(pdu, &key, &aad_prefix);
        let mut aad = aad_prefix.to_vec();
        aad.extend_from_slice(&nonce);

        let decrypted = decrypt_pdu(&encrypted_pdu, &key, &nonce, &auth_tag, &aad).unwrap();
        assert_eq!(decrypted, pdu);

        let mut tampered_aad = aad;
        tampered_aad[4] ^= 0x01;
        assert!(decrypt_pdu(&encrypted_pdu, &key, &nonce, &auth_tag, &tampered_aad).is_err());
    }

    #[test]
    fn rate_window_quota_rejects_the_complete_request() {
        let resources = vec![ResourceRequest {
            bucket_name: "bucket".to_string(),
            window_size_ms: 1_025,
            rate_limit: 100,
            tokens_requested: 1,
        }];
        let error = RClient::validate_rate_windows_against_quota(&resources, Some(1_024))
            .expect_err("window above credential limit must fail");
        assert!(error.to_string().contains("rate_window_size_ms_max"));
    }

    #[test]
    fn latency_report_uses_32_byte_service_blocks() {
        let reports = vec![ServiceLatencyReport {
            latency_tracker_name: "service".to_string(),
            observed_latency: 85,
            ttl_ms: 1_000,
            max_samples: 32,
            min_sample_threshold: 4,
        }];

        let body = RClient::build_latency_report_body(&reports);
        assert_eq!(body.len(), 4 + SERVICE_LATENCY_BLOCK_WIRE_LEN);

        let pdu = RClient::build_pdu(crate::protocol::PDU_LATENCY_REPORT, body.as_ref()).unwrap();
        assert_eq!(pdu.len(), 44);
        assert_eq!(
            u16::from_le_bytes([pdu[0], pdu[1]]),
            crate::protocol::PDU_LATENCY_REPORT
        );
        assert_eq!(u16::from_le_bytes([pdu[2], pdu[3]]), 44);
        assert_eq!(u16::from_le_bytes([pdu[8], pdu[9]]), 1);
        assert_eq!(u32::from_le_bytes([pdu[40], pdu[41], pdu[42], pdu[43]]), 85);
    }

    #[test]
    fn parse_rate_response_ignores_trailing_tlvs() {
        let mut tenant = [0u8; 40];
        let tenant_header = TenantHeader {
            tlv_type: TLV_TENANT,
            tlv_size: 40,
            key_id: 42,
            unique_id: [0u8; 16],
            time_stamp: 0,
            steering_feedback: 1,
            tenant_mgmt_flag: 0,
            padding: [0, 0],
        };
        tenant_header.write_to_buffer(&mut tenant);

        let mut pdu_body = Vec::new();
        pdu_body.extend_from_slice(&0u16.to_le_bytes());
        pdu_body.extend_from_slice(&0u16.to_le_bytes());

        let label = b"x";
        let tlv_body_len = 2 + label.len();
        let padding = (4 - (tlv_body_len % 4)) % 4;
        let tlv_size = 4 + tlv_body_len + padding;
        pdu_body.extend_from_slice(&crate::protocol::TLV_METRICS_LABEL.to_le_bytes());
        pdu_body.extend_from_slice(&(tlv_size as u16).to_le_bytes());
        pdu_body.extend_from_slice(&(label.len() as u16).to_le_bytes());
        pdu_body.extend_from_slice(label);
        if padding > 0 {
            pdu_body.extend_from_slice(&[0u8; 4][..padding]);
        }

        let pdu_size = 8 + pdu_body.len();
        let mut pdu = Vec::new();
        pdu.extend_from_slice(&crate::protocol::PDU_RATE_RESPONSE.to_le_bytes());
        pdu.extend_from_slice(&(pdu_size as u16).to_le_bytes());
        pdu.extend_from_slice(&[0u8; 4]);
        pdu.extend_from_slice(&pdu_body);

        let mut packet = Vec::new();
        packet.extend_from_slice(&tenant);
        packet.extend_from_slice(&crate::protocol::TLV_AUTH_NONE.to_le_bytes());
        packet.extend_from_slice(&4u16.to_le_bytes());
        packet.extend_from_slice(&pdu);

        let parsed = RClient::parse_rate_response_with_auth(&packet, &AuthMethod::None, None, None)
            .expect("parse");
        assert!(parsed.success);
        assert_eq!(parsed.guard_results.len(), 0);
        assert_eq!(parsed.resource_results.len(), 0);
        assert_eq!(parsed.server_id, 42);
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(512))]

        #[test]
        fn arbitrary_untrusted_udp_payload_never_panics(
            packet in proptest::collection::vec(any::<u8>(), 0..=2048),
        ) {
            let cookie = [0x11_u8; 32];
            let aes = [0x22_u8; 32];
            let _ = RClient::parse_rate_response_with_auth(
                &packet,
                &AuthMethod::None,
                None,
                None,
            );
            let _ = RClient::parse_rate_response_with_auth(
                &packet,
                &AuthMethod::Cookie(cookie),
                Some(&cookie),
                None,
            );
            let _ = RClient::parse_rate_response_with_auth(
                &packet,
                &AuthMethod::AesGcm(aes),
                None,
                Some(&aes),
            );
        }
    }

    #[test]
    fn parse_server_id_from_target_prefix() {
        let id = RClient::parse_server_id_from_target("s-1015809.rl.us1.com.");
        assert_eq!(id, Some(1015809));
    }

    #[test]
    fn parse_server_id_from_target_rejects_invalid() {
        assert!(RClient::parse_server_id_from_target("rl.us1.com").is_none());
        assert!(RClient::parse_server_id_from_target("s-.rl.us1.com").is_none());
        assert!(RClient::parse_server_id_from_target("s-x.rl.us1.com").is_none());
        assert!(RClient::parse_server_id_from_target("s-01.rl.us1.com").is_none());
    }
}
