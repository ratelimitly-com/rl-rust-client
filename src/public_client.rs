use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use crate::api_key::ApiKey;
use crate::api_key_codec::ApiKeyLimits;
use crate::client::CoreClient;
use crate::config::{ApiKeyConfig, CoreConfig};
use crate::error::{ConfigurationError, Error};
use crate::model::{
    Decision, GuardResult, LatencyTracker, LatencyTrackerId, Resource, ResourceId, ResourceResult,
    Response, duration_to_u32_ms,
};
use crate::protocol::{LatencyGuard, ResourceRequest, ServiceLatencyReport};
use crate::request_policy::RequestPolicy;

const MAX_METRICS_LABEL_LEN: usize = 65_526;

/// A reusable asynchronous Ratelimitly client.
///
/// Construct a client with [`Client::builder`], then reuse or clone it across
/// concurrent requests. Clones share sockets, discovery state, and the
/// response router. Dropping the last clone stops the background task and
/// releases the client's resources.
#[derive(Clone)]
pub struct Client {
    inner: Arc<CoreClient>,
    service_domain: Arc<str>,
    limits: ApiKeyLimits,
}

impl Client {
    /// Starts a builder using one validated API key.
    pub fn builder(api_key: ApiKey) -> ClientBuilder {
        ClientBuilder {
            service_domain: format!("c-{}.p0.ratelimitly.com", api_key.key_id()),
            api_key,
            request_policy: RequestPolicy::default(),
            dns_server: None,
        }
    }

    /// Returns the DNS domain used for Ratelimitly service discovery.
    pub fn service_domain(&self) -> &str {
        &self.service_domain
    }

    /// Starts one resource request.
    pub fn request(&self) -> RequestBuilder<'_> {
        RequestBuilder {
            client: self,
            resources: Vec::new(),
            guards: Vec::new(),
            metrics_label: None,
        }
    }

    /// Reports one observed service latency to every discovered r-server.
    ///
    /// The operation sends once and does not wait for a server response. The
    /// server bounds tracker storage with the API key's latency-buffer quota;
    /// that storage choice is not part of this report.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] when `observed` is not a positive whole number of
    /// milliseconds, service discovery fails, the datagram cannot be built, or
    /// a local communication operation fails.
    pub async fn report_latency(
        &self,
        tracker: &LatencyTracker,
        observed: Duration,
    ) -> Result<(), Error> {
        let observed_latency = duration_to_u32_ms(observed, "observed latency")?;
        let report = ServiceLatencyReport {
            latency_tracker_name: tracker.name().to_owned(),
            observed_latency,
            ttl_ms: tracker.sample_ttl_ms(),
            max_samples: tracker.max_samples(),
            min_sample_threshold: tracker.min_samples(),
        };
        self.inner
            .report_latency(&[report])
            .await
            .map_err(Error::from)
    }
}

impl fmt::Debug for Client {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Client")
            .field("service_domain", &self.service_domain)
            .finish_non_exhaustive()
    }
}

/// Builder for [`Client`].
pub struct ClientBuilder {
    api_key: ApiKey,
    service_domain: String,
    request_policy: RequestPolicy,
    dns_server: Option<SocketAddr>,
}

impl ClientBuilder {
    /// Overrides the DNS domain used for SRV discovery.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] when the value is not a valid ASCII DNS name.
    pub fn service_domain(mut self, domain: impl Into<String>) -> Result<Self, Error> {
        let domain = domain.into();
        if !valid_dns_name(&domain) {
            return Err(ConfigurationError::InvalidServiceDomain.into());
        }
        self.service_domain = domain;
        Ok(self)
    }

    /// Selects the request retry and completion policy.
    pub fn request_policy(mut self, policy: RequestPolicy) -> Self {
        self.request_policy = policy;
        self
    }

    /// Uses one explicit DNS server instead of the operating-system resolver.
    ///
    /// This is primarily intended for deterministic tests and controlled
    /// development environments. Production clients should normally use the
    /// operating-system resolver so the API-key-derived service domain follows
    /// its configured DNS path.
    pub fn dns_server(mut self, address: SocketAddr) -> Self {
        self.dns_server = Some(address);
        self
    }

    /// Validates the API-key limits and creates the reusable client.
    ///
    /// Construction initializes local communication resources but performs no
    /// service discovery. Discovery occurs on the first non-empty operation.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] when the request-policy horizon exceeds the API key,
    /// the system resolver cannot be initialized, or a local UDP socket cannot
    /// be created.
    pub async fn build(self) -> Result<Client, Error> {
        let limits = self.api_key.limits();
        self.request_policy.horizon_ms(limits.dedup_ttl_ms_max)?;
        let config = CoreConfig {
            api_key: ApiKeyConfig {
                service_domain: self.service_domain.clone(),
                key_id: self.api_key.key_id(),
                auth_method: self.api_key.auth_method(),
                limits: limits.clone(),
                steering_feedback: true,
            },
            dns_refresh_interval_s: 60,
            ignore_steering_feedback: false,
            request_policy: self.request_policy,
            dns_server: self.dns_server,
        };
        let inner = CoreClient::new(config).await?;
        Ok(Client {
            inner: Arc::new(inner),
            service_domain: Arc::from(self.service_domain),
            limits,
        })
    }
}

/// Builder for one logical resource request.
pub struct RequestBuilder<'a> {
    client: &'a Client,
    resources: Vec<ResourceRequest>,
    guards: Vec<LatencyGuard>,
    metrics_label: Option<String>,
}

impl RequestBuilder<'_> {
    /// Attaches a stable label used to group this request in API-key metrics.
    /// An empty label is treated as no label.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] when the UTF-8 label cannot fit in its wire TLV.
    pub fn metrics_label(mut self, label: impl Into<String>) -> Result<Self, Error> {
        let label = label.into();
        if label.len() > MAX_METRICS_LABEL_LEN {
            return Err(ConfigurationError::InvalidMetricsLabel.into());
        }
        self.metrics_label = (!label.is_empty()).then_some(label);
        Ok(self)
    }

    /// Adds one content-defined resource consumption.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] when `tokens` is outside `1..=65535`, the resource
    /// window exceeds the API-key limit, or the request has too many resources.
    pub fn consume(mut self, resource: &Resource, tokens: u32) -> Result<Self, Error> {
        let tokens_requested = u16::try_from(tokens)
            .ok()
            .filter(|tokens| *tokens > 0)
            .ok_or(ConfigurationError::InvalidTokenQuantity)?;
        if resource.window_ms() > self.client.limits.rate_window_size_ms_max {
            return Err(ConfigurationError::ResourceWindowExceedsApiKey.into());
        }
        if self.resources.len() == usize::from(u16::MAX) {
            return Err(ConfigurationError::TooManyRequestEntries { kind: "resources" }.into());
        }
        self.resources.push(ResourceRequest {
            bucket_name: resource.name().to_owned(),
            window_size_ms: resource.window_ms(),
            rate_limit: resource.rate_limit(),
            tokens_requested,
        });
        Ok(self)
    }

    /// Adds one latency guard.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] when the threshold is not a positive whole number of
    /// milliseconds or the request has too many guards.
    pub fn guard(mut self, tracker: &LatencyTracker, threshold: Duration) -> Result<Self, Error> {
        if self.guards.len() == usize::from(u16::MAX) {
            return Err(ConfigurationError::TooManyRequestEntries { kind: "guards" }.into());
        }
        self.guards.push(LatencyGuard {
            latency_tracker_name: tracker.name().to_owned(),
            threshold_ms: duration_to_u32_ms(threshold, "latency threshold")?,
            ttl_ms: tracker.sample_ttl_ms(),
            max_samples: tracker.max_samples(),
            min_sample_threshold: tracker.min_samples(),
        });
        Ok(self)
    }

    /// Sends the request and returns the selected valid response.
    ///
    /// An empty builder returns a local grant. A non-empty request is broadcast
    /// according to the configured HA policy. Dropping or aborting this future
    /// unregisters it from the response router; it does not prove that a server
    /// did not process a datagram already sent.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] for discovery, packet construction, authentication,
    /// communication, protocol, or timeout failures. Grant and rejection are
    /// successful return values distinguished by [`Response::decision`].
    pub async fn send(self) -> Result<Response, Error> {
        let result = self
            .client
            .inner
            .check_rate_limit(&self.resources, &self.guards, self.metrics_label.as_deref())
            .await?;
        Ok(Response {
            decision: if result.success {
                Decision::Granted
            } else {
                Decision::Rejected
            },
            resource_results: result
                .resource_results
                .into_iter()
                .map(|item| ResourceResult {
                    resource_id: ResourceId::from_bytes(item.bucket_id),
                    tokens_deficit: item.tokens_deficit,
                    actual_rate: item.actual_rate,
                })
                .collect(),
            guard_results: result
                .guard_results
                .into_iter()
                .map(|item| GuardResult {
                    tracker_id: LatencyTrackerId::from_bytes(item.latency_tracker_id),
                    threshold_ms: item.threshold_ms,
                    current_latency_ms: item.current_latency_ms,
                    passed: item.passed,
                })
                .collect(),
            selected_server_id: (result.server_id != 0).then_some(result.server_id),
        })
    }
}

fn valid_dns_name(domain: &str) -> bool {
    if domain.is_empty() || domain.len() > 253 || domain.starts_with('.') || domain.ends_with('.') {
        return false;
    }
    domain.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    })
}

#[cfg(test)]
mod tests {
    use super::valid_dns_name;

    #[test]
    fn validates_service_domains() {
        assert!(valid_dns_name("test.ratelimitly.invalid"));
        assert!(!valid_dns_name("-bad.example"));
        assert!(!valid_dns_name("bad..example"));
    }
}
