//! Exponential backoff with jitter for transport reconnection (§D.14).

use std::time::Duration;

/// Configuration for exponential backoff.
#[derive(Debug, Clone)]
pub struct BackoffConfig {
    /// Initial delay before the first retry.
    pub initial: Duration,
    /// Maximum delay between retries.
    pub max_delay: Duration,
    /// Maximum number of retries before giving up. `None` = infinite.
    pub max_retries: Option<u32>,
    /// Jitter factor in [0.0, 1.0]. 0.0 = no jitter, 1.0 = full jitter.
    pub jitter: f64,
}

impl Default for BackoffConfig {
    fn default() -> Self {
        Self {
            initial: Duration::from_secs(1),
            max_delay: Duration::from_secs(60),
            max_retries: None,
            jitter: 0.5,
        }
    }
}

/// State tracker for exponential backoff.
#[derive(Debug, Clone)]
pub struct Backoff {
    config: BackoffConfig,
    attempt: u32,
}

impl Backoff {
    pub fn new(config: BackoffConfig) -> Self {
        Self { config, attempt: 0 }
    }

    /// Returns the next delay, or `None` if max retries exceeded.
    pub fn next_delay(&mut self) -> Option<Duration> {
        if let Some(max) = self.config.max_retries {
            if self.attempt >= max {
                return None;
            }
        }

        let base = self.config.initial.as_millis() as f64
            * 2.0f64.powi(self.attempt as i32);
        let capped = base.min(self.config.max_delay.as_millis() as f64);

        // Apply jitter: delay = capped * (1 - jitter + jitter * random)
        let jittered = if self.config.jitter > 0.0 {
            let random: f64 = rand_factor();
            capped * (1.0 - self.config.jitter + self.config.jitter * random)
        } else {
            capped
        };

        self.attempt += 1;
        Some(Duration::from_millis(jittered as u64))
    }

    /// Reset the backoff state (call after a successful connection).
    pub fn reset(&mut self) {
        self.attempt = 0;
    }

    /// Current attempt number.
    pub fn attempt(&self) -> u32 {
        self.attempt
    }
}

/// Simple pseudo-random factor in [0.0, 1.0) using thread-local state.
/// Not cryptographically secure — only used for jitter.
fn rand_factor() -> f64 {
    use std::cell::Cell;
    use std::time::SystemTime;

    thread_local! {
        static STATE: Cell<u64> = Cell::new(
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64
        );
    }

    STATE.with(|s| {
        // xorshift64
        let mut x = s.get();
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        s.set(x);
        (x as f64) / (u64::MAX as f64)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exponential_growth_with_cap() {
        let config = BackoffConfig {
            initial: Duration::from_millis(100),
            max_delay: Duration::from_secs(5),
            max_retries: None,
            jitter: 0.0, // no jitter for deterministic test
        };
        let mut b = Backoff::new(config);

        let d0 = b.next_delay().unwrap();
        assert_eq!(d0, Duration::from_millis(100));

        let d1 = b.next_delay().unwrap();
        assert_eq!(d1, Duration::from_millis(200));

        let d2 = b.next_delay().unwrap();
        assert_eq!(d2, Duration::from_millis(400));

        let d3 = b.next_delay().unwrap();
        assert_eq!(d3, Duration::from_millis(800));

        let d4 = b.next_delay().unwrap();
        assert_eq!(d4, Duration::from_millis(1600));

        let d5 = b.next_delay().unwrap();
        assert_eq!(d5, Duration::from_millis(3200));

        let d6 = b.next_delay().unwrap();
        assert_eq!(d6, Duration::from_secs(5)); // capped
    }

    #[test]
    fn max_retries_respected() {
        let config = BackoffConfig {
            initial: Duration::from_millis(100),
            max_delay: Duration::from_secs(10),
            max_retries: Some(3),
            jitter: 0.0,
        };
        let mut b = Backoff::new(config);

        assert!(b.next_delay().is_some());
        assert!(b.next_delay().is_some());
        assert!(b.next_delay().is_some());
        assert!(b.next_delay().is_none()); // exceeded
    }

    #[test]
    fn reset_restarts_sequence() {
        let config = BackoffConfig {
            initial: Duration::from_millis(100),
            max_delay: Duration::from_secs(10),
            max_retries: Some(2),
            jitter: 0.0,
        };
        let mut b = Backoff::new(config);

        b.next_delay();
        b.next_delay();
        assert!(b.next_delay().is_none());

        b.reset();
        assert_eq!(b.attempt(), 0);
        let d = b.next_delay().unwrap();
        assert_eq!(d, Duration::from_millis(100));
    }

    #[test]
    fn jitter_produces_varied_delays() {
        let config = BackoffConfig {
            initial: Duration::from_millis(1000),
            max_delay: Duration::from_secs(60),
            max_retries: None,
            jitter: 0.5,
        };
        let mut b = Backoff::new(config);

        let delays: Vec<Duration> = (0..10).map(|_| {
            let d = b.next_delay().unwrap();
            b.reset(); // reset to get attempt-0 each time
            d
        }).collect();

        // With jitter, not all delays should be identical
        let first = delays[0];
        let has_variation = delays.iter().any(|d| *d != first);
        assert!(has_variation, "jitter should produce varied delays");
    }
}
