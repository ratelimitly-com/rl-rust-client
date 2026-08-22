use std::time::Duration;

use crate::error::{ConfigurationError, Error};

pub(crate) const MAX_REPLAY_COUNT: u32 = 65_535;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScheduleKind {
    Fixed,
    Linear,
    Exponential,
}

/// The duration schedule for resource-request transmission rounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Schedule {
    kind: ScheduleKind,
    initial_units: u32,
    max_units: u32,
    growth: u32,
}

impl Schedule {
    /// Uses the same number of time units for every round.
    ///
    /// The value is validated when the containing [`RequestPolicy`] is built.
    pub const fn fixed(units: u32) -> Self {
        Self {
            kind: ScheduleKind::Fixed,
            initial_units: units,
            max_units: units,
            growth: 0,
        }
    }

    /// Increases the round duration by `step_units`, capped at `max_units`.
    ///
    /// The values are validated when the containing [`RequestPolicy`] is built.
    pub const fn linear(initial_units: u32, step_units: u32, max_units: u32) -> Self {
        Self {
            kind: ScheduleKind::Linear,
            initial_units,
            max_units,
            growth: step_units,
        }
    }

    /// Multiplies the round duration by `factor`, capped at `max_units`.
    ///
    /// The values are validated when the containing [`RequestPolicy`] is built.
    pub const fn exponential(initial_units: u32, factor: u32, max_units: u32) -> Self {
        Self {
            kind: ScheduleKind::Exponential,
            initial_units,
            max_units,
            growth: factor,
        }
    }

    pub(crate) fn units(self, round: u32) -> Result<u32, ConfigurationError> {
        if self.initial_units == 0 || self.max_units < self.initial_units {
            return Err(ConfigurationError::InvalidRequestPolicy);
        }
        match self.kind {
            ScheduleKind::Fixed => {
                if self.max_units != self.initial_units || self.growth != 0 {
                    return Err(ConfigurationError::InvalidRequestPolicy);
                }
                Ok(self.initial_units)
            }
            ScheduleKind::Linear => {
                if self.growth == 0 {
                    return Err(ConfigurationError::InvalidRequestPolicy);
                }
                let room = self.max_units - self.initial_units;
                if round > room / self.growth {
                    Ok(self.max_units)
                } else {
                    Ok(self.initial_units + round * self.growth)
                }
            }
            ScheduleKind::Exponential => {
                if self.growth < 2 {
                    return Err(ConfigurationError::InvalidRequestPolicy);
                }
                let mut value = self.initial_units;
                for _ in 0..round {
                    if value >= self.max_units || value > self.max_units / self.growth {
                        return Ok(self.max_units);
                    }
                    value *= self.growth;
                }
                Ok(value.min(self.max_units))
            }
        }
    }
}

/// The sole HA policy used for non-empty resource requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestPolicy {
    pub(crate) unit_ms: u64,
    pub(crate) replay_count: u32,
    pub(crate) replay_gap: Schedule,
    pub(crate) final_receive_units: u32,
    pub(crate) completion_delivery: bool,
}

impl RequestPolicy {
    /// Starts a request-policy builder initialized with the default policy.
    pub fn builder() -> RequestPolicyBuilder {
        RequestPolicyBuilder::default()
    }

    /// Returns the maximum duration of one request under this policy.
    ///
    /// This horizon becomes the request's deduplication lifetime after it is
    /// checked against the API key during [`ClientBuilder::build`](crate::ClientBuilder::build).
    pub fn horizon(self) -> Duration {
        Duration::from_millis(
            self.horizon_ms(u32::MAX)
                .expect("validated RequestPolicy always has a representable horizon")
                .into(),
        )
    }

    pub(crate) fn horizon_ms(self, dedup_ttl_ms_max: u32) -> Result<u32, ConfigurationError> {
        if self.unit_ms == 0 || self.replay_count > MAX_REPLAY_COUNT || dedup_ttl_ms_max == 0 {
            return Err(ConfigurationError::InvalidRequestPolicy);
        }
        let mut total_units = u64::from(self.final_receive_units);
        for round in 0..=self.replay_count {
            total_units = total_units
                .checked_add(u64::from(self.replay_gap.units(round)?))
                .ok_or(ConfigurationError::InvalidRequestPolicy)?;
        }
        let horizon = total_units
            .checked_mul(self.unit_ms)
            .ok_or(ConfigurationError::InvalidRequestPolicy)?;
        if total_units == 0 || horizon > u64::from(u32::MAX) {
            return Err(ConfigurationError::InvalidRequestPolicy);
        }
        if horizon > u64::from(dedup_ttl_ms_max) {
            return Err(ConfigurationError::RequestPolicyExceedsApiKey);
        }
        Ok(horizon as u32)
    }
}

impl Default for RequestPolicy {
    fn default() -> Self {
        Self {
            unit_ms: 20,
            replay_count: 1,
            replay_gap: Schedule::fixed(1),
            final_receive_units: 1,
            completion_delivery: true,
        }
    }
}

/// Builder for [`RequestPolicy`].
#[derive(Debug, Clone, Copy)]
pub struct RequestPolicyBuilder {
    unit: Duration,
    replay_count: u32,
    replay_gap: Schedule,
    final_receive_units: u32,
    completion_delivery: bool,
}

impl Default for RequestPolicyBuilder {
    fn default() -> Self {
        let policy = RequestPolicy::default();
        Self {
            unit: Duration::from_millis(policy.unit_ms),
            replay_count: policy.replay_count,
            replay_gap: policy.replay_gap,
            final_receive_units: policy.final_receive_units,
            completion_delivery: policy.completion_delivery,
        }
    }
}

impl RequestPolicyBuilder {
    /// Sets the base duration used by every policy round.
    pub fn unit(mut self, unit: Duration) -> Self {
        self.unit = unit;
        self
    }

    /// Sets the number of replays after the initial send.
    pub fn replays(mut self, replay_count: u32) -> Self {
        self.replay_count = replay_count;
        self
    }

    /// Sets the duration schedule for transmission rounds.
    pub fn replay_gap(mut self, schedule: Schedule) -> Self {
        self.replay_gap = schedule;
        self
    }

    /// Sets the length of the final receive-only phase, in policy units.
    pub fn final_receive_units(mut self, units: u32) -> Self {
        self.final_receive_units = units;
        self
    }

    /// Enables or disables best-effort delivery to missing servers.
    pub fn completion_delivery(mut self, enabled: bool) -> Self {
        self.completion_delivery = enabled;
        self
    }

    /// Validates and builds the request policy.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] when the unit is not a positive whole number of
    /// milliseconds, a schedule is structurally invalid, or the resulting
    /// horizon overflows the wire representation. The API-key-specific horizon
    /// limit is checked later by [`ClientBuilder::build`](crate::ClientBuilder::build).
    pub fn build(self) -> Result<RequestPolicy, Error> {
        let millis = self.unit.as_millis();
        if self.unit.is_zero()
            || !self.unit.subsec_nanos().is_multiple_of(1_000_000)
            || millis > u128::from(u64::MAX)
        {
            return Err(ConfigurationError::InvalidDuration {
                field: "request policy unit",
            }
            .into());
        }
        let policy = RequestPolicy {
            unit_ms: millis as u64,
            replay_count: self.replay_count,
            replay_gap: self.replay_gap,
            final_receive_units: self.final_receive_units,
            completion_delivery: self.completion_delivery,
        };
        policy.horizon_ms(u32::MAX)?;
        Ok(policy)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_horizon_matches_other_clients() {
        assert_eq!(
            RequestPolicy::default().horizon(),
            Duration::from_millis(60)
        );
    }

    #[test]
    fn schedules_cap_and_final_wait_can_be_disabled() {
        assert_eq!(Schedule::linear(1, 2, 6).units(3), Ok(6));
        assert_eq!(Schedule::exponential(1, 2, 8).units(3), Ok(8));
        let policy = RequestPolicy::builder()
            .unit(Duration::from_millis(25))
            .replays(3)
            .replay_gap(Schedule::fixed(1))
            .final_receive_units(0)
            .completion_delivery(false)
            .build()
            .unwrap();
        assert_eq!(policy.horizon(), Duration::from_millis(100));
    }
}
