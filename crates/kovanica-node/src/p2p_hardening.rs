//! P2P hardening: rate limiting, duplicate suppression, peer scoring/banning.
//!
//! This module provides defensive P2P measures to protect against:
//! - **Rate limiting**: Per-peer limits on incoming bytes/messages per time window
//! - **Duplicate suppression**: Track and penalize peers sending already-known blocks/txs
//! - **Peer scoring**: Reward honest behavior, penalize misbehavior
//! - **Banning**: Auto-ban peers whose score falls below threshold
//!
//! All state is deterministic (discrete time) so tests are reproducible.

use kovanica_dag::BlockId;
use kovanica_state::TxId;
use std::collections::{BTreeMap, HashMap};

/// Configuration for P2P hardening parameters.
#[derive(Clone, Debug)]
pub struct P2pHardeningConfig {
    /// Max bytes a peer may send per time window (rate limiting).
    /// 0 = disabled.
    pub max_bytes_per_window: u64,
    /// Time window for rate limiting (in mesh ticks).
    pub rate_window_ticks: u64,
    /// Max messages a peer may send per time window.
    /// 0 = disabled.
    pub max_messages_per_window: u64,
    /// Initial score for new peers.
    pub initial_score: i32,
    /// Score change for a valid, new block received.
    pub score_valid_block: i32,
    /// Score change for a duplicate block received.
    pub score_duplicate_block: i32,
    /// Score change for a valid, new tx received.
    pub score_valid_tx: i32,
    /// Score change for a duplicate tx received.
    pub score_duplicate_tx: i32,
    /// Score change for an invalid block (validation failed).
    pub score_invalid_block: i32,
    /// Score change for an invalid tx (validation failed).
    pub score_invalid_tx: i32,
    /// Score below which a peer is auto-banned.
    pub ban_threshold: i32,
    /// Max score (capped to prevent unbounded growth).
    pub max_score: i32,
    /// Min score (capped).
    pub min_score: i32,
}

impl Default for P2pHardeningConfig {
    fn default() -> Self {
        Self {
            max_bytes_per_window: 1_000_000, // 1 MB per window
            rate_window_ticks: 100,          // 100 ticks
            max_messages_per_window: 1000,   // 1000 msgs per window
            initial_score: 0,
            score_valid_block: 1,
            score_duplicate_block: -5,
            score_valid_tx: 1,
            score_duplicate_tx: -2,
            score_invalid_block: -20,
            score_invalid_tx: -10,
            ban_threshold: -50,
            max_score: 1000,
            min_score: -1000,
        }
    }
}

/// Per-peer rate limiting state.
#[derive(Clone, Debug, Default)]
struct RateLimitState {
    bytes_in_window: u64,
    messages_in_window: u64,
    window_start_tick: u64,
}

impl RateLimitState {
    fn reset(&mut self, tick: u64) {
        self.bytes_in_window = 0;
        self.messages_in_window = 0;
        self.window_start_tick = tick;
    }

    fn check_and_consume(&mut self, tick: u64, config: &P2pHardeningConfig, bytes: u64) -> bool {
        // Reset window if needed
        if tick >= self.window_start_tick + config.rate_window_ticks {
            self.reset(tick);
        }
        // Check limits
        if config.max_bytes_per_window > 0
            && self.bytes_in_window + bytes > config.max_bytes_per_window
        {
            return false;
        }
        if config.max_messages_per_window > 0
            && self.messages_in_window + 1 > config.max_messages_per_window
        {
            return false;
        }
        // Consume
        self.bytes_in_window += bytes;
        self.messages_in_window += 1;
        true
    }
}

/// Per-peer duplicate tracking state.
#[derive(Clone, Debug, Default)]
struct DuplicateState {
    known_blocks: HashMap<BlockId, u64>, // block_id -> tick first seen
    known_txs: HashMap<TxId, u64>,       // tx_id -> tick first seen
}

impl DuplicateState {
    fn is_new_block(&mut self, id: &BlockId, tick: u64) -> bool {
        self.known_blocks.insert(*id, tick).is_none()
    }

    fn is_new_tx(&mut self, id: &TxId, tick: u64) -> bool {
        self.known_txs.insert(*id, tick).is_none()
    }

    /// Prune old entries to prevent unbounded growth.
    fn prune(&mut self, tick: u64, max_age: u64) {
        self.known_blocks.retain(|_, t| tick - *t < max_age);
        self.known_txs.retain(|_, t| tick - *t < max_age);
    }
}

/// Per-peer scoring state.
#[derive(Clone, Debug, Default)]
struct ScoreState {
    score: i32,
    total_valid_blocks: u64,
    total_duplicate_blocks: u64,
    total_valid_txs: u64,
    total_duplicate_txs: u64,
    total_invalid_blocks: u64,
    total_invalid_txs: u64,
    banned: bool,
}

impl ScoreState {
    fn new(initial: i32) -> Self {
        Self {
            score: initial,
            ..Self::default()
        }
    }

    fn apply(&mut self, delta: i32, config: &P2pHardeningConfig) {
        self.score = (self.score + delta).clamp(config.min_score, config.max_score);
    }

    fn is_banned(&self, config: &P2pHardeningConfig) -> bool {
        self.banned || self.score <= config.ban_threshold
    }
}

/// P2P hardening manager for a Mesh.
#[derive(Clone, Debug, Default)]
pub struct P2pHardening {
    config: P2pHardeningConfig,
    rate_limits: HashMap<String, RateLimitState>,
    duplicates: HashMap<String, DuplicateState>,
    scores: HashMap<String, ScoreState>,
    tick: u64,
}

impl P2pHardening {
    /// Create a new hardening manager with default config.
    pub fn new(config: P2pHardeningConfig) -> Self {
        Self {
            config,
            rate_limits: HashMap::new(),
            duplicates: HashMap::new(),
            scores: HashMap::new(),
            tick: 0,
        }
    }

    /// Get the current config.
    pub fn config(&self) -> &P2pHardeningConfig {
        &self.config
    }

    /// Get mutable config (for runtime adjustment).
    pub fn config_mut(&mut self) -> &mut P2pHardeningConfig {
        &mut self.config
    }

    /// Advance time tick.
    pub fn tick(&mut self) {
        self.tick = self.tick.saturating_add(1);
        // Periodic pruning of duplicate state
        if self.tick % 1000 == 0 {
            for dup in self.duplicates.values_mut() {
                dup.prune(self.tick, 10_000); // keep last 10k ticks
            }
        }
    }

    /// Get current tick.
    pub fn now(&self) -> u64 {
        self.tick
    }

    /// Ensure peer state exists.
    fn ensure_peer(&mut self, peer: &str) {
        self.rate_limits.entry(peer.to_string()).or_default();
        self.duplicates.entry(peer.to_string()).or_default();
        self.scores
            .entry(peer.to_string())
            .or_insert_with(|| ScoreState::new(self.config.initial_score));
    }

    /// Check rate limit for a peer sending `bytes`. Returns `true` if allowed.
    pub fn check_rate_limit(&mut self, peer: &str, bytes: u64) -> bool {
        self.ensure_peer(peer);
        let state = self.rate_limits.get_mut(peer).unwrap();
        state.check_and_consume(self.tick, &self.config, bytes)
    }

    /// Record a block received from `peer`. Returns `(is_new, is_banned)`.
    /// If `valid` is false, the block failed validation.
    pub fn on_block(&mut self, peer: &str, block_id: &BlockId, valid: bool) -> (bool, bool) {
        self.ensure_peer(peer);
        let dup = self.duplicates.get_mut(peer).unwrap();
        let score = self.scores.get_mut(peer).unwrap();

        if !valid {
            score.total_invalid_blocks += 1;
            score.apply(self.config.score_invalid_block, &self.config);
            return (false, score.is_banned(&self.config));
        }

        let is_new = dup.is_new_block(block_id, self.tick);
        if is_new {
            score.total_valid_blocks += 1;
            score.apply(self.config.score_valid_block, &self.config);
        } else {
            score.total_duplicate_blocks += 1;
            score.apply(self.config.score_duplicate_block, &self.config);
        }
        (is_new, score.is_banned(&self.config))
    }

    /// Record a tx received from `peer`. Returns `(is_new, is_banned)`.
    /// If `valid` is false, the tx failed validation.
    pub fn on_tx(&mut self, peer: &str, tx_id: &TxId, valid: bool) -> (bool, bool) {
        self.ensure_peer(peer);
        let dup = self.duplicates.get_mut(peer).unwrap();
        let score = self.scores.get_mut(peer).unwrap();

        if !valid {
            score.total_invalid_txs += 1;
            score.apply(self.config.score_invalid_tx, &self.config);
            return (false, score.is_banned(&self.config));
        }

        let is_new = dup.is_new_tx(tx_id, self.tick);
        if is_new {
            score.total_valid_txs += 1;
            score.apply(self.config.score_valid_tx, &self.config);
        } else {
            score.total_duplicate_txs += 1;
            score.apply(self.config.score_duplicate_tx, &self.config);
        }
        (is_new, score.is_banned(&self.config))
    }

    /// Get the current score for a peer.
    pub fn score(&self, peer: &str) -> Option<i32> {
        self.scores.get(peer).map(|s| s.score)
    }

    /// Check if a peer is banned.
    pub fn is_banned(&self, peer: &str) -> bool {
        self.scores
            .get(peer)
            .map(|s| s.is_banned(&self.config))
            .unwrap_or(false)
    }

    /// Manually ban a peer.
    pub fn ban(&mut self, peer: &str) {
        self.ensure_peer(peer);
        self.scores.get_mut(peer).unwrap().banned = true;
    }

    /// Manually unban a peer (resets score to initial).
    pub fn unban(&mut self, peer: &str) {
        self.scores
            .entry(peer.to_string())
            .or_insert_with(|| ScoreState::new(self.config.initial_score));
        if let Some(s) = self.scores.get_mut(peer) {
            s.banned = false;
            s.score = self.config.initial_score;
        }
    }

    /// Get detailed stats for a peer.
    pub fn peer_stats(&self, peer: &str) -> Option<PeerStats> {
        let score = self.scores.get(peer)?;
        let rate = self.rate_limits.get(peer)?;
        let dup = self.duplicates.get(peer)?;
        Some(PeerStats {
            score: score.score,
            banned: score.is_banned(&self.config),
            total_valid_blocks: score.total_valid_blocks,
            total_duplicate_blocks: score.total_duplicate_blocks,
            total_valid_txs: score.total_valid_txs,
            total_duplicate_txs: score.total_duplicate_txs,
            total_invalid_blocks: score.total_invalid_blocks,
            total_invalid_txs: score.total_invalid_txs,
            bytes_in_window: rate.bytes_in_window,
            messages_in_window: rate.messages_in_window,
            known_blocks: dup.known_blocks.len(),
            known_txs: dup.known_txs.len(),
        })
    }

    /// Get all peer stats.
    pub fn all_peer_stats(&self) -> BTreeMap<String, PeerStats> {
        let mut out = BTreeMap::new();
        for peer in self.scores.keys() {
            if let Some(stats) = self.peer_stats(peer) {
                out.insert(peer.clone(), stats);
            }
        }
        out
    }
}

/// Aggregated stats for a peer.
#[derive(Clone, Debug)]
pub struct PeerStats {
    pub score: i32,
    pub banned: bool,
    pub total_valid_blocks: u64,
    pub total_duplicate_blocks: u64,
    pub total_valid_txs: u64,
    pub total_duplicate_txs: u64,
    pub total_invalid_blocks: u64,
    pub total_invalid_txs: u64,
    pub bytes_in_window: u64,
    pub messages_in_window: u64,
    pub known_blocks: usize,
    pub known_txs: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limit_allows_within_budget() {
        let config = P2pHardeningConfig {
            max_bytes_per_window: 100,
            rate_window_ticks: 10,
            max_messages_per_window: 10,
            ..Default::default()
        };
        let mut h = P2pHardening::new(config);
        for _ in 0..5 {
            assert!(h.check_rate_limit("peer1", 10));
            h.tick();
        }
    }

    #[test]
    fn rate_limit_blocks_over_budget() {
        let config = P2pHardeningConfig {
            max_bytes_per_window: 100,
            rate_window_ticks: 10,
            max_messages_per_window: 10,
            ..Default::default()
        };
        let mut h = P2pHardening::new(config);
        // Use 90 bytes
        for _ in 0..9 {
            assert!(h.check_rate_limit("peer1", 10));
            h.tick();
        }
        // Next should be blocked (would exceed 100)
        assert!(!h.check_rate_limit("peer1", 20));
        // Wait for window to reset
        for _ in 0..10 {
            h.tick();
        }
        assert!(h.check_rate_limit("peer1", 10));
    }

    #[test]
    fn duplicate_block_tracked() {
        let mut h = P2pHardening::new(Default::default());
        let block_id = BlockId::from_bytes([1u8; 32]);

        // First time - new
        let (is_new, banned) = h.on_block("peer1", &block_id, true);
        assert!(is_new);
        assert!(!banned);

        // Second time - duplicate
        let (is_new, banned) = h.on_block("peer1", &block_id, true);
        assert!(!is_new);
        assert!(!banned);
    }

    #[test]
    fn duplicate_block_penalized() {
        let config = P2pHardeningConfig {
            score_duplicate_block: -10,
            ban_threshold: -20,
            ..Default::default()
        };
        let mut h = P2pHardening::new(config);
        let block_id = BlockId::from_bytes([2u8; 32]);

        h.on_block("peer1", &block_id, true); // +1
        assert_eq!(h.score("peer1"), Some(1));

        h.on_block("peer1", &block_id, true); // -10
        assert_eq!(h.score("peer1"), Some(-9));

        h.on_block("peer1", &block_id, true); // -10
        assert_eq!(h.score("peer1"), Some(-19));

        h.on_block("peer1", &block_id, true); // -10 -> banned
        assert_eq!(h.score("peer1"), Some(-29));
        assert!(h.is_banned("peer1"));
    }

    #[test]
    fn invalid_block_heavily_penalized() {
        let config = P2pHardeningConfig {
            score_invalid_block: -50,
            ban_threshold: -40,
            ..Default::default()
        };
        let mut h = P2pHardening::new(config);
        let block_id = BlockId::from_bytes([3u8; 32]);

        h.on_block("peer1", &block_id, false); // invalid
        assert!(h.is_banned("peer1"));
    }

    #[test]
    fn duplicate_tx_tracked() {
        let mut h = P2pHardening::new(Default::default());
        let tx_id = TxId::from_bytes([4u8; 32]);

        let (is_new, _) = h.on_tx("peer1", &tx_id, true);
        assert!(is_new);

        let (is_new, _) = h.on_tx("peer1", &tx_id, true);
        assert!(!is_new);
    }

    #[test]
    fn peer_stats_available() {
        let mut h = P2pHardening::new(Default::default());
        let block_id = BlockId::from_bytes([5u8; 32]);
        h.on_block("peer1", &block_id, true);

        let stats = h.peer_stats("peer1").unwrap();
        assert_eq!(stats.score, 1);
        assert_eq!(stats.total_valid_blocks, 1);
        assert!(!stats.banned);
    }

    #[test]
    fn all_peer_stats_sorted() {
        let mut h = P2pHardening::new(Default::default());
        h.on_block("alice", &BlockId::from_bytes([1u8; 32]), true);
        h.on_block("bob", &BlockId::from_bytes([2u8; 32]), true);
        h.on_block("charlie", &BlockId::from_bytes([3u8; 32]), true);

        let all = h.all_peer_stats();
        let names: Vec<_> = all.keys().cloned().collect();
        assert_eq!(names, vec!["alice", "bob", "charlie"]);
    }

    #[test]
    fn manual_ban_unban() {
        let mut h = P2pHardening::new(Default::default());
        h.ban("peer1");
        assert!(h.is_banned("peer1"));
        h.unban("peer1");
        assert!(!h.is_banned("peer1"));
        assert_eq!(h.score("peer1"), Some(0)); // reset to initial
    }
}
