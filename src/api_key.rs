use std::fmt;
use std::str::FromStr;
use std::sync::Arc;

use thiserror::Error;

use crate::api_key_codec::{ApiKeyLimits, DecodeError, decode_api_key};
use crate::config::AuthMethod;

#[derive(Clone)]
struct ApiKeyInner {
    key_id: u64,
    auth_method: AuthMethod,
    limits: ApiKeyLimits,
}

/// A validated, opaque Ratelimitly API key.
///
/// Parse an encoded credential with [`str::parse`]. The encoded value and raw
/// authentication material are never exposed through this type's public API or
/// its [`Debug`](fmt::Debug) representation.
#[derive(Clone)]
pub struct ApiKey {
    inner: Arc<ApiKeyInner>,
}

impl ApiKey {
    /// Returns the non-secret identifier carried by this API key.
    ///
    /// The identifier is safe to use when deriving the default service domain;
    /// it is not an authentication secret.
    pub fn key_id(&self) -> u64 {
        self.inner.key_id
    }

    pub(crate) fn auth_method(&self) -> AuthMethod {
        self.inner.auth_method.clone()
    }

    pub(crate) fn limits(&self) -> ApiKeyLimits {
        self.inner.limits.clone()
    }
}

impl FromStr for ApiKey {
    type Err = ApiKeyError;

    fn from_str(encoded: &str) -> Result<Self, Self::Err> {
        let decoded = decode_api_key(encoded).map_err(ApiKeyError::from_decode_error)?;
        let limits = decoded.limits.ok_or(ApiKeyError::UnsupportedCredential)?;
        let auth_method = match decoded.auth_method.as_str() {
            "none" if decoded.auth_secret.is_empty() => AuthMethod::None,
            "cookie" if decoded.auth_secret.len() == 32 => {
                let mut secret = [0u8; 32];
                secret.copy_from_slice(&decoded.auth_secret);
                AuthMethod::Cookie(secret)
            }
            "aes" if decoded.auth_secret.len() == 32 => {
                let mut secret = [0u8; 32];
                secret.copy_from_slice(&decoded.auth_secret);
                AuthMethod::AesGcm(secret)
            }
            _ => return Err(ApiKeyError::UnsupportedCredential),
        };
        Ok(Self {
            inner: Arc::new(ApiKeyInner {
                key_id: decoded.key_id,
                auth_method,
                limits,
            }),
        })
    }
}

impl fmt::Debug for ApiKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApiKey")
            .field("key_id", &self.inner.key_id)
            .field("credential", &"[REDACTED]")
            .finish()
    }
}

/// An API-key validation error that never contains credential material.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ApiKeyError {
    /// The value is not a valid Ratelimitly API-key encoding.
    #[error("invalid API-key encoding")]
    InvalidEncoding,
    /// The API-key format version is not supported by this client.
    #[error("unsupported API-key format version")]
    UnsupportedVersion,
    /// The credential type is not accepted by the resource client.
    #[error("unsupported API-key credential type")]
    UnsupportedCredential,
    /// The API-key limits are invalid.
    #[error("invalid API-key limits")]
    InvalidLimits,
}

impl ApiKeyError {
    fn from_decode_error(error: DecodeError) -> Self {
        match error {
            DecodeError::UnsupportedFormatVersion(_) => Self::UnsupportedVersion,
            DecodeError::UnsupportedAuthMethod(_) | DecodeError::InvalidHrpPrefix => {
                Self::UnsupportedCredential
            }
            DecodeError::InvalidPackedQuota => Self::InvalidLimits,
            _ => Self::InvalidEncoding,
        }
    }
}
