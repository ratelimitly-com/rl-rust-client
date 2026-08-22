use std::io;

use thiserror::Error;

use crate::api_key::ApiKeyError;

/// An error returned by the public Ratelimitly client API.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// The supplied API key is invalid or unsupported.
    #[error("invalid Ratelimitly API key")]
    InvalidApiKey(#[source] ApiKeyError),

    /// Client, request, resource, tracker, or policy configuration is invalid.
    #[error("invalid client configuration: {0}")]
    InvalidConfiguration(#[source] ConfigurationError),

    /// No usable Ratelimitly service could be discovered.
    #[error("Ratelimitly service discovery failed")]
    Discovery,

    /// A local communication operation failed.
    #[error("Ratelimitly communication failed")]
    Communication(#[source] io::Error),

    /// The request horizon ended without a usable decision.
    #[error("Ratelimitly request timed out")]
    Timeout,

    /// The request or response did not satisfy the client protocol contract.
    #[error("Ratelimitly protocol error")]
    Protocol,

    /// A local authentication operation failed.
    #[error("Ratelimitly authentication error")]
    Authentication,
}

impl From<ApiKeyError> for Error {
    fn from(error: ApiKeyError) -> Self {
        Self::InvalidApiKey(error)
    }
}

impl From<ConfigurationError> for Error {
    fn from(error: ConfigurationError) -> Self {
        Self::InvalidConfiguration(error)
    }
}

/// A public configuration-validation error.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConfigurationError {
    /// A duration is zero, has sub-millisecond precision, or exceeds the wire
    /// representation.
    #[error("{field} must be a positive whole number of milliseconds that fits in u32")]
    InvalidDuration {
        /// The public field whose value is invalid.
        field: &'static str,
    },

    /// A required latency-tracker field was not configured.
    #[error("latency tracker is missing {field}")]
    MissingTrackerField {
        /// The missing builder field.
        field: &'static str,
    },

    /// A resource or latency-tracker name is empty or too long.
    #[error("{kind} name is invalid")]
    InvalidName {
        /// The named definition kind.
        kind: &'static str,
    },

    /// A latency-tracker numeric field must be positive.
    #[error("latency tracker {field} must be positive")]
    InvalidTrackerValue {
        /// The invalid tracker field.
        field: &'static str,
    },

    /// A resource consumption must request at least one representable token.
    #[error("tokens requested must be between 1 and 65535")]
    InvalidTokenQuantity,

    /// A metrics label cannot be represented by the wire protocol.
    #[error("metrics label is too long")]
    InvalidMetricsLabel,

    /// A resource window exceeds the limit carried by the API key.
    #[error("resource window exceeds the API key limit")]
    ResourceWindowExceedsApiKey,

    /// A latency-tracker buffer exceeds the limit carried by the API key.
    #[error("latency tracker buffer exceeds the API key limit")]
    TrackerBufferExceedsApiKey,

    /// The HA schedule is structurally invalid.
    #[error("request policy schedule is invalid")]
    InvalidRequestPolicy,

    /// The HA schedule exceeds the API key's request-horizon limit.
    #[error("request policy exceeds the API key limit")]
    RequestPolicyExceedsApiKey,

    /// The service-domain override is not a valid DNS name.
    #[error("service domain is invalid")]
    InvalidServiceDomain,

    /// A request contains more entries than the client can represent.
    #[error("request contains too many {kind}")]
    TooManyRequestEntries {
        /// The entry kind whose count overflowed.
        kind: &'static str,
    },

    /// An internal configuration contract rejected the supplied values.
    #[error("configuration is not supported")]
    Unsupported,
}

#[derive(Debug, Error)]
pub(crate) enum CoreError {
    #[error("network I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("request timed out")]
    Timeout,
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("authentication error: {0}")]
    Auth(String),
    #[error("DNS resolution error: {0}")]
    Dns(String),
    #[error("configuration error: {0}")]
    Config(String),
}

impl From<CoreError> for Error {
    fn from(error: CoreError) -> Self {
        match error {
            CoreError::Io(source) => Self::Communication(source),
            CoreError::Timeout => Self::Timeout,
            CoreError::Protocol(_) => Self::Protocol,
            CoreError::Auth(_) => Self::Authentication,
            CoreError::Dns(_) => Self::Discovery,
            CoreError::Config(_) => Self::InvalidConfiguration(ConfigurationError::Unsupported),
        }
    }
}
