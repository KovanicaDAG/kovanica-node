//! Difficulty retargeting for block `work`.
//!
//! A block's [`work`](crate::Block::work) is its difficulty weight — the thing
//! blue work (and thus chain selection) accumulates. In a proof-of-work network
//! that weight must track how hard blocks actually are to find, so the network
//! holds a steady block rate as hash power changes. [`Retarget`] is that
//! controller: given the timestamps and work of recent blocks, it computes the
//! `work` the *next* block should be mined at.
//!
//! The rule is the classic one, in work terms (work is inversely proportional to
//! the mining target): scale the recent average work by
//! `expected_timespan / actual_timespan`, so blocks arriving **too fast** (actual
//! < expected) raise the work (harder) and blocks arriving **too slow** lower it,
//! with the per-retarget change clamped to a factor and floored at a minimum.
//!
//! This module is the algorithm only. It takes timestamps from the caller — a
//! full node reads them from block headers. Blocks do not yet carry a timestamp
//! field, so *consensus-enforced* difficulty (validating each block's work
//! against the target its past implies) is a follow-up that adds that field;
//! this piece is the retargeting math it will call, tested in isolation.

/// A recent block's timestamp (milliseconds) and the work it was mined at.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TimedWork {
    /// The block's timestamp, in milliseconds.
    pub timestamp_ms: u64,
    /// The work the block was mined at.
    pub work: u128,
}

impl TimedWork {
    /// Construct a sample.
    pub const fn new(timestamp_ms: u64, work: u128) -> Self {
        Self { timestamp_ms, work }
    }
}

/// A difficulty-retargeting policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Retarget {
    /// Desired time between blocks, in milliseconds.
    pub target_interval_ms: u64,
    /// Number of most-recent intervals to average over.
    pub window: usize,
    /// Cap on how much work may change per retarget (e.g. 4 = at most ×4 or ÷4).
    pub max_factor: u32,
    /// Floor on the returned work.
    pub min_work: u128,
}

impl Default for Retarget {
    /// One block per second, a 20-block window, ±4× clamp, floor 1.
    fn default() -> Self {
        Self {
            target_interval_ms: 1_000,
            window: 20,
            max_factor: 4,
            min_work: 1,
        }
    }
}

impl Retarget {
    /// The work the next block should be mined at, given `recent` blocks
    /// (oldest first, timestamps non-decreasing).
    ///
    /// Uses the last `window + 1` samples (giving up to `window` intervals). With
    /// fewer than two samples there is no rate to measure, so it returns
    /// [`min_work`](Self::min_work).
    pub fn next_work(&self, recent: &[TimedWork]) -> u128 {
        // Keep the most recent window+1 samples → `window` intervals.
        let samples = match recent.len().checked_sub(self.window + 1) {
            Some(extra) if extra > 0 => &recent[extra..],
            _ => recent,
        };
        if samples.len() < 2 {
            return self.min_work;
        }

        let intervals = (samples.len() - 1) as u64;
        let expected = intervals.saturating_mul(self.target_interval_ms).max(1);
        let actual = samples[samples.len() - 1]
            .timestamp_ms
            .saturating_sub(samples[0].timestamp_ms)
            .max(1);

        // Average work over the sampled blocks (the base we scale from).
        let sum: u128 = samples
            .iter()
            .fold(0u128, |acc, s| acc.saturating_add(s.work));
        let avg_work = sum / samples.len() as u128;

        // new = avg * expected / actual, clamped to [avg/factor, avg*factor].
        let scaled = avg_work.saturating_mul(u128::from(expected)) / u128::from(actual);
        let factor = u128::from(self.max_factor.max(1));
        let lower = (avg_work / factor).max(self.min_work);
        let upper = avg_work.saturating_mul(factor).max(self.min_work);
        scaled.clamp(lower, upper).max(self.min_work)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `count` samples spaced `interval_ms` apart, each with work `work`.
    fn evenly_spaced(count: usize, interval_ms: u64, work: u128) -> Vec<TimedWork> {
        (0..count)
            .map(|i| TimedWork::new(i as u64 * interval_ms, work))
            .collect()
    }

    #[test]
    fn stable_when_blocks_arrive_at_target() {
        let cfg = Retarget {
            target_interval_ms: 1_000,
            window: 10,
            max_factor: 4,
            min_work: 1,
        };
        let samples = evenly_spaced(11, 1_000, 1_000);
        // Exactly on target → work is unchanged.
        assert_eq!(cfg.next_work(&samples), 1_000);
    }

    #[test]
    fn faster_blocks_raise_work() {
        let cfg = Retarget {
            target_interval_ms: 1_000,
            window: 10,
            max_factor: 4,
            min_work: 1,
        };
        // Half the target interval → roughly double the work.
        let samples = evenly_spaced(11, 500, 1_000);
        assert_eq!(cfg.next_work(&samples), 2_000);
    }

    #[test]
    fn slower_blocks_lower_work() {
        let cfg = Retarget {
            target_interval_ms: 1_000,
            window: 10,
            max_factor: 4,
            min_work: 1,
        };
        // Double the target interval → roughly half the work.
        let samples = evenly_spaced(11, 2_000, 1_000);
        assert_eq!(cfg.next_work(&samples), 500);
    }

    #[test]
    fn change_is_clamped_to_max_factor() {
        let cfg = Retarget {
            target_interval_ms: 1_000,
            window: 10,
            max_factor: 4,
            min_work: 1,
        };
        // Blocks arrive 100× too fast; the raise is capped at ×max_factor.
        let samples = evenly_spaced(11, 10, 1_000);
        assert_eq!(cfg.next_work(&samples), 4_000);

        // 100× too slow; the drop is capped at ÷max_factor.
        let slow = evenly_spaced(11, 100_000, 1_000);
        assert_eq!(cfg.next_work(&slow), 250);
    }

    #[test]
    fn result_is_floored_at_min_work() {
        let cfg = Retarget {
            target_interval_ms: 1_000,
            window: 10,
            max_factor: 4,
            min_work: 600,
        };
        // The ÷4 clamp would give 250, but the floor lifts it to 600.
        let slow = evenly_spaced(11, 100_000, 1_000);
        assert_eq!(cfg.next_work(&slow), 600);
    }

    #[test]
    fn insufficient_history_returns_min_work() {
        let cfg = Retarget::default();
        assert_eq!(cfg.next_work(&[]), cfg.min_work);
        assert_eq!(cfg.next_work(&[TimedWork::new(0, 5)]), cfg.min_work);
    }

    #[test]
    fn only_the_most_recent_window_is_used() {
        let cfg = Retarget {
            target_interval_ms: 1_000,
            window: 2,
            max_factor: 8,
            min_work: 1,
        };
        // Old slow blocks then recent fast ones: only the last window+1 (=3)
        // samples count, so the recent fast cadence drives the raise.
        let mut samples = evenly_spaced(5, 10_000, 1_000); // old, slow
        let base = samples.last().unwrap().timestamp_ms;
        samples.push(TimedWork::new(base + 500, 1_000));
        samples.push(TimedWork::new(base + 1_000, 1_000));
        // Last 3 samples span 1000ms over 2 intervals (expected 2000) → ×2.
        assert_eq!(cfg.next_work(&samples), 2_000);
    }
}
