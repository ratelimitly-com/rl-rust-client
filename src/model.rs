use std::fmt;
use std::time::Duration;

use crate::error::{ConfigurationError, Error};
use crate::protocol::{derive_bucket_id, derive_latency_tracker_id};

fn write_hex(bytes: &[u8], formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    for byte in bytes {
        write!(formatter, "{byte:02x}")?;
    }
    Ok(())
}

pub(crate) fn duration_to_u32_ms(duration: Duration, field: &'static str) -> Result<u32, Error> {
    let millis = duration.as_millis();
    if duration.is_zero()
        || !duration.subsec_nanos().is_multiple_of(1_000_000)
        || millis > u128::from(u32::MAX)
    {
        return Err(ConfigurationError::InvalidDuration { field }.into());
    }
    Ok(millis as u32)
}

/// The stable identity of a content-defined rate counter.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResourceId([u8; 16]);

impl ResourceId {
    pub(crate) const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Returns the canonical identity bytes.
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl fmt::Display for ResourceId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_hex(&self.0, formatter)
    }
}

impl fmt::Debug for ResourceId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("ResourceId")
            .field(&self.to_string())
            .finish()
    }
}

/// A content-defined rate-counter configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resource {
    name: String,
    window_ms: u32,
    rate_limit: u32,
    id: ResourceId,
}

impl Resource {
    /// Creates a content-defined rate-counter resource.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] when `name` is empty or `window` is zero, has
    /// sub-millisecond precision, or cannot be represented in the wire format.
    pub fn new(name: impl Into<String>, window: Duration, rate_limit: u32) -> Result<Self, Error> {
        let name = name.into();
        if name.is_empty() || name.len() > u32::MAX as usize {
            return Err(ConfigurationError::InvalidName { kind: "resource" }.into());
        }
        let window_ms = duration_to_u32_ms(window, "resource window")?;
        let id = ResourceId::from_bytes(derive_bucket_id(&name, window_ms, rate_limit));
        Ok(Self {
            name,
            window_ms,
            rate_limit,
            id,
        })
    }

    /// Returns the application-defined resource name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the rate-counter window.
    pub fn window(&self) -> Duration {
        Duration::from_millis(self.window_ms.into())
    }

    /// Returns the number of tokens available in one window.
    pub fn rate_limit(&self) -> u32 {
        self.rate_limit
    }

    /// Returns the content-defined resource identity.
    pub fn id(&self) -> ResourceId {
        self.id
    }

    pub(crate) fn window_ms(&self) -> u32 {
        self.window_ms
    }
}

/// The stable identity of a content-defined latency tracker.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct LatencyTrackerId([u8; 16]);

impl LatencyTrackerId {
    pub(crate) const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Returns the canonical identity bytes.
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl fmt::Display for LatencyTrackerId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_hex(&self.0, formatter)
    }
}

impl fmt::Debug for LatencyTrackerId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("LatencyTrackerId")
            .field(&self.to_string())
            .finish()
    }
}

/// A content-defined latency-tracker configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LatencyTracker {
    name: String,
    sample_ttl_ms: u32,
    max_samples: u32,
    buffer_size: u32,
    min_samples: u32,
    id: LatencyTrackerId,
}

impl LatencyTracker {
    /// Starts a builder for a named latency tracker.
    pub fn builder(name: impl Into<String>) -> LatencyTrackerBuilder {
        LatencyTrackerBuilder {
            name: name.into(),
            sample_ttl: None,
            max_samples: None,
            buffer_size: None,
            min_samples: None,
        }
    }

    /// Returns the application-defined tracker name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the maximum sample lifetime.
    pub fn sample_ttl(&self) -> Duration {
        Duration::from_millis(self.sample_ttl_ms.into())
    }

    /// Returns the maximum number of samples considered.
    pub fn max_samples(&self) -> u32 {
        self.max_samples
    }

    /// Returns the requested tracker storage.
    pub fn buffer_size(&self) -> u32 {
        self.buffer_size
    }

    /// Returns the warm-up population required before guards take effect.
    pub fn min_samples(&self) -> u32 {
        self.min_samples
    }

    /// Returns the content-defined tracker identity.
    pub fn id(&self) -> LatencyTrackerId {
        self.id
    }

    pub(crate) fn sample_ttl_ms(&self) -> u32 {
        self.sample_ttl_ms
    }
}

/// Builder for [`LatencyTracker`].
#[derive(Debug, Clone)]
pub struct LatencyTrackerBuilder {
    name: String,
    sample_ttl: Option<Duration>,
    max_samples: Option<u32>,
    buffer_size: Option<u32>,
    min_samples: Option<u32>,
}

impl LatencyTrackerBuilder {
    /// Sets the maximum sample lifetime.
    pub fn sample_ttl(mut self, sample_ttl: Duration) -> Self {
        self.sample_ttl = Some(sample_ttl);
        self
    }

    /// Sets the maximum number of samples considered.
    pub fn max_samples(mut self, max_samples: u32) -> Self {
        self.max_samples = Some(max_samples);
        self
    }

    /// Sets the requested tracker storage.
    pub fn buffer_size(mut self, buffer_size: u32) -> Self {
        self.buffer_size = Some(buffer_size);
        self
    }

    /// Sets the warm-up population required before guards take effect.
    pub fn min_samples(mut self, min_samples: u32) -> Self {
        self.min_samples = Some(min_samples);
        self
    }

    /// Validates and builds the tracker definition.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] when the name is empty, a required setting is absent,
    /// a count is zero, or the sample lifetime cannot be represented as a
    /// positive whole number of milliseconds.
    pub fn build(self) -> Result<LatencyTracker, Error> {
        if self.name.is_empty() || self.name.len() > u32::MAX as usize {
            return Err(ConfigurationError::InvalidName {
                kind: "latency tracker",
            }
            .into());
        }
        let sample_ttl = self
            .sample_ttl
            .ok_or(ConfigurationError::MissingTrackerField {
                field: "sample lifetime",
            })?;
        let sample_ttl_ms = duration_to_u32_ms(sample_ttl, "sample lifetime")?;
        let max_samples = self
            .max_samples
            .ok_or(ConfigurationError::MissingTrackerField {
                field: "maximum samples",
            })?;
        let buffer_size = self
            .buffer_size
            .ok_or(ConfigurationError::MissingTrackerField {
                field: "buffer size",
            })?;
        let min_samples = self
            .min_samples
            .ok_or(ConfigurationError::MissingTrackerField {
                field: "minimum samples",
            })?;
        for (field, value) in [
            ("maximum samples", max_samples),
            ("buffer size", buffer_size),
            ("minimum samples", min_samples),
        ] {
            if value == 0 {
                return Err(ConfigurationError::InvalidTrackerValue { field }.into());
            }
        }
        let id = LatencyTrackerId::from_bytes(derive_latency_tracker_id(
            &self.name,
            sample_ttl_ms,
            max_samples,
            buffer_size,
            min_samples,
        ));
        Ok(LatencyTracker {
            name: self.name,
            sample_ttl_ms,
            max_samples,
            buffer_size,
            min_samples,
            id,
        })
    }
}

/// A valid Ratelimitly admission decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Every condition passed and requested quantities were consumed.
    Granted,
    /// At least one condition failed and the work is not authorized.
    Rejected,
}

/// One resource's detailed result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceResult {
    pub(crate) resource_id: ResourceId,
    pub(crate) tokens_deficit: u16,
    pub(crate) actual_rate: u32,
}

impl ResourceResult {
    /// Returns the resource identity this result describes.
    pub fn resource_id(&self) -> ResourceId {
        self.resource_id
    }

    /// Returns the quantity the resource could not supply.
    pub fn tokens_deficit(&self) -> u16 {
        self.tokens_deficit
    }

    /// Returns the current consumed-token count reported for the window.
    pub fn actual_rate(&self) -> u32 {
        self.actual_rate
    }
}

/// One latency guard's detailed result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardResult {
    pub(crate) tracker_id: LatencyTrackerId,
    pub(crate) threshold_ms: u32,
    pub(crate) current_latency_ms: u32,
    pub(crate) passed: bool,
}

impl GuardResult {
    /// Returns the latency-tracker identity this result describes.
    pub fn tracker_id(&self) -> LatencyTrackerId {
        self.tracker_id
    }

    /// Returns the guard threshold.
    pub fn threshold(&self) -> Duration {
        Duration::from_millis(self.threshold_ms.into())
    }

    /// Returns the latency observed by the selected server.
    pub fn current_latency(&self) -> Duration {
        Duration::from_millis(self.current_latency_ms.into())
    }

    /// Returns whether the current latency was below the threshold.
    pub fn passed(&self) -> bool {
        self.passed
    }
}

/// A valid response selected for one resource request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub(crate) decision: Decision,
    pub(crate) resource_results: Vec<ResourceResult>,
    pub(crate) guard_results: Vec<GuardResult>,
    pub(crate) selected_server_id: Option<u64>,
}

impl Response {
    /// Returns the grant or rejection decision.
    pub fn decision(&self) -> Decision {
        self.decision
    }

    /// Returns detailed resource results.
    pub fn resource_results(&self) -> &[ResourceResult] {
        &self.resource_results
    }

    /// Returns detailed latency-guard results.
    pub fn guard_results(&self) -> &[GuardResult] {
        &self.guard_results
    }

    /// Returns the selected server ID, or `None` for a local empty request.
    pub fn selected_server_id(&self) -> Option<u64> {
        self.selected_server_id
    }
}
