use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// Cumulative physical UDP traffic in one direction.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TrafficDirection {
    /// Number of datagrams sent successfully or read from a socket.
    pub datagrams: u64,
    /// UDP payload bytes, including Ratelimitly authentication.
    pub payload_bytes: u64,
    /// Estimated IP bytes: payload plus UDP and base IP headers.
    pub ip_bytes: u64,
}

/// Cumulative traffic since client construction, shared by all its clones.
///
/// DNS is excluded. Physical replays, HA fan-out, and completion delivery are
/// included. Received datagrams count before validation or request matching.
/// IP estimates add 28 bytes for IPv4 (including mapped IPv4) or 48 for IPv6.
/// They exclude IP options/extensions, fragmentation overhead, and link/tunnel
/// headers. Sent bytes mean local socket acceptance, not remote delivery.
///
/// Fields are sampled independently, not as a transaction during concurrent
/// I/O. Reading does not wait for late replies or drain retired sockets.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TrafficStats {
    /// Traffic accepted by local UDP sends.
    pub sent: TrafficDirection,
    /// Traffic actually read by the response router, even if later discarded.
    pub received: TrafficDirection,
    /// Failed or incomplete local datagram sends; these add no sent bytes.
    pub send_failures: u64,
    /// At least one counter saturated; byte totals are then incomplete.
    pub incomplete: bool,
}

#[derive(Default)]
struct DirectionCounters {
    datagrams: AtomicU64,
    payload_bytes: AtomicU64,
    ip_bytes: AtomicU64,
}

// The client can send concurrently from multiple tasks while its response
// router receives. Opt-in atomics avoid introducing a per-packet mutex.
#[derive(Default)]
pub(crate) struct TrafficCounters {
    sent: DirectionCounters,
    received: DirectionCounters,
    send_failures: AtomicU64,
    incomplete: AtomicBool,
}

impl TrafficCounters {
    fn add(&self, counter: &AtomicU64, value: u64) {
        let previous = counter
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |old| {
                Some(old.saturating_add(value))
            })
            .expect("update always succeeds");
        if previous.checked_add(value).is_none() {
            self.incomplete.store(true, Ordering::Relaxed);
        }
    }

    fn record(&self, counters: &DirectionCounters, len: usize, peer: SocketAddr) {
        let headers = match peer {
            SocketAddr::V4(_) => 28,
            SocketAddr::V6(address) if address.ip().to_ipv4_mapped().is_some() => 28,
            SocketAddr::V6(_) => 48,
        };
        self.add(&counters.datagrams, 1);
        self.add(&counters.payload_bytes, len as u64);
        self.add(&counters.ip_bytes, len as u64 + headers);
    }

    pub(crate) fn sent(&self, len: usize, peer: SocketAddr, result: &std::io::Result<usize>) {
        if matches!(result, Ok(sent) if *sent == len) {
            self.record(&self.sent, len, peer);
        } else {
            self.add(&self.send_failures, 1);
        }
    }

    pub(crate) fn received(&self, len: usize, peer: SocketAddr) {
        self.record(&self.received, len, peer);
    }

    pub(crate) fn snapshot(&self) -> TrafficStats {
        fn direction(counters: &DirectionCounters) -> TrafficDirection {
            TrafficDirection {
                datagrams: counters.datagrams.load(Ordering::Relaxed),
                payload_bytes: counters.payload_bytes.load(Ordering::Relaxed),
                ip_bytes: counters.ip_bytes.load(Ordering::Relaxed),
            }
        }
        TrafficStats {
            sent: direction(&self.sent),
            received: direction(&self.received),
            send_failures: self.send_failures.load(Ordering::Relaxed),
            incomplete: self.incomplete.load(Ordering::Relaxed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn headers_empty_datagrams_failures_and_partial_sends() {
        let counters = TrafficCounters::default();
        let mapped = "[::ffff:127.0.0.1]:1234".parse().unwrap();
        counters.sent(0, mapped, &Ok(0));
        counters.received(0, mapped);
        counters.sent(
            100,
            mapped,
            &Err(std::io::ErrorKind::NetworkUnreachable.into()),
        );
        counters.sent(100, mapped, &Ok(99));
        let stats = counters.snapshot();
        assert_eq!(
            stats.sent,
            TrafficDirection {
                datagrams: 1,
                payload_bytes: 0,
                ip_bytes: 28
            }
        );
        assert_eq!(stats.received, stats.sent);
        assert_eq!(stats.send_failures, 2);
        assert!(!stats.incomplete);
    }

    #[test]
    fn saturates_and_remembers_incomplete_totals() {
        let counters = TrafficCounters::default();
        counters
            .sent
            .ip_bytes
            .store(u64::MAX - 1, Ordering::Relaxed);
        counters.sent(1, "127.0.0.1:1".parse().unwrap(), &Ok(1));
        assert_eq!(counters.snapshot().sent.ip_bytes, u64::MAX);
        assert!(counters.snapshot().incomplete);
        counters.sent(1, "127.0.0.1:1".parse().unwrap(), &Ok(1));
        assert_eq!(counters.snapshot().sent.ip_bytes, u64::MAX);
        assert!(counters.snapshot().incomplete);
    }

    #[test]
    fn concurrent_updates_are_not_lost() {
        let counters = TrafficCounters::default();
        std::thread::scope(|scope| {
            for _ in 0..4 {
                scope.spawn(|| {
                    for _ in 0..1000 {
                        counters.sent(10, "[::1]:1".parse().unwrap(), &Ok(10));
                    }
                });
            }
        });
        assert_eq!(
            counters.snapshot().sent,
            TrafficDirection {
                datagrams: 4000,
                payload_bytes: 40000,
                ip_bytes: 232000,
            }
        );
    }
}
