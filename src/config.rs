use std::net::SocketAddr;

use crate::api_key_codec::ApiKeyLimits;
use crate::request_policy::RequestPolicy;

#[derive(Clone)]
pub(crate) enum AuthMethod {
    None,
    Cookie([u8; 32]),
    AesGcm([u8; 32]),
}

#[derive(Clone)]
pub(crate) struct ApiKeyConfig {
    pub service_domain: String,
    pub key_id: u64,
    pub auth_method: AuthMethod,
    pub limits: ApiKeyLimits,
    pub steering_feedback: bool,
}

pub(crate) struct CoreConfig {
    pub api_key: ApiKeyConfig,
    pub dns_refresh_interval_s: u64,
    pub ignore_steering_feedback: bool,
    pub request_policy: RequestPolicy,
    pub dns_server: Option<SocketAddr>,
}

impl CoreConfig {
    pub(crate) fn effective_request_policy(&self) -> RequestPolicy {
        self.request_policy
    }
}
