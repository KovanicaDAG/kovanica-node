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
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// On-disk representation of the persisted ban list.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct BansFile {
    /// Banned peer identifier -> optional expiry tick (`None` = permanent).
    bans: BTreeMap<String, Option<u64>>,
}

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
    /// How many ticks a manual ban lasts. 0 = permanent (until explicitly unbanned).
    pub ban_expiry_ticks: u64,
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
            ban_expiry_ticks: 0,
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
    banned_until: Option<u64>,
}

impl ScoreState {
    fn new(initial: i32) -> Self {
        Self {
            score: initial,
            banned_until: None,
            ..Self::default()
        }
    }

    fn apply(&mut self, delta: i32, config: &P2pHardeningConfig) {
        self.score = (self.score + delta).clamp(config.min_score, config.max_score);
    }

    fn is_banned(&self, config: &P2pHardeningConfig, now: u64) -> bool {
        if self.score <= config.ban_threshold {
            return true;
        }
        self.banned && self.banned_until.map_or(true, |until| now < until)
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
    bans_path: Option<PathBuf>,
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
            bans_path: None,
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

    /// Configure a path to persist the ban list to.
    pub fn set_bans_path(&mut self, path: impl Into<PathBuf>) {
        self.bans_path = Some(path.into());
    }

    /// Load the persisted ban list from `path`. Already-expired bans are
    /// dropped; permanent bans (`None`) are kept.
    pub fn load_bans<P: AsRef<Path>>(&mut self, path: P) -> io::Result<()> {
        let bytes = fs::read(path.as_ref())?;
        let file: BansFile = serde_json::from_slice(&bytes)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        self.bans_path = Some(path.as_ref().to_path_buf());
        for (peer, expiry) in file.bans {
            let still_banned = match expiry {
                None => true,
                Some(until) => self.tick < until,
            };
            if still_banned {
                self.ensure_peer(&peer);
                let state = self.scores.get_mut(&peer).unwrap();
                state.banned = true;
                state.banned_until = expiry;
            }
        }
        Ok(())
    }

    /// Persist the current ban set to the configured path.
    pub fn save_bans(&self) -> io::Result<()> {
        let Some(path) = &self.bans_path else {
            return Ok(());
        };
        let bans: BTreeMap<String, Option<u64>> = self
            .scores
            .iter()
            .filter(|(_, s)| s.is_banned(&self.config, self.tick))
            .map(|(peer, s)| (peer.clone(), s.banned_until))
            .collect();
        let file = BansFile { bans };
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, serde_json::to_vec_pretty(&file)?)
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
        // Prune expired bans and persist if the set changed.
        if self.bans_path.is_some() {
            let mut changed = false;
            for state in self.scores.values_mut() {
                if state.banned {
                    if let Some(until) = state.banned_until {
                        if self.tick >= until {
                            state.banned = false;
                            state.banned_until = None;
                            changed = true;
                        }
                    }
                }
            }
            if changed {
                let _ = self.save_bans();
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
        let was_banned = score.is_banned(&self.config, self.tick);

        if !valid {
            score.total_invalid_blocks += 1;
            score.apply(self.config.score_invalid_block, &self.config);
            let banned = score.is_banned(&self.config, self.tick);
            if banned && !was_banned {
                let _ = self.save_bans();
            }
            return (false, banned);
        }

        let is_new = dup.is_new_block(block_id, self.tick);
        if is_new {
            score.total_valid_blocks += 1;
            score.apply(self.config.score_valid_block, &self.config);
        } else {
            score.total_duplicate_blocks += 1;
            score.apply(self.config.score_duplicate_block, &self.config);
        }
        let banned = score.is_banned(&self.config, self.tick);
        if banned && !was_banned {
            let _ = self.save_bans();
        }
        (is_new, banned)
    }

    /// Record a tx received from `peer`. Returns `(is_new, is_banned)`.
    /// If `valid` is false, the tx failed validation.
    pub fn on_tx(&mut self, peer: &str, tx_id: &TxId, valid: bool) -> (bool, bool) {
        self.ensure_peer(peer);
        let dup = self.duplicates.get_mut(peer).unwrap();
        let score = self.scores.get_mut(peer).unwrap();
        let was_banned = score.is_banned(&self.config, self.tick);

        if !valid {
            score.total_invalid_txs += 1;
            score.apply(self.config.score_invalid_tx, &self.config);
            let banned = score.is_banned(&self.config, self.tick);
            if banned && !was_banned {
                let _ = self.save_bans();
            }
            return (false, banned);
        }

        let is_new = dup.is_new_tx(tx_id, self.tick);
        if is_new {
            score.total_valid_txs += 1;
            score.apply(self.config.score_valid_tx, &self.config);
        } else {
            score.total_duplicate_txs += 1;
            score.apply(self.config.score_duplicate_tx, &self.config);
        }
        let banned = score.is_banned(&self.config, self.tick);
        if banned && !was_banned {
            let _ = self.save_bans();
        }
        (is_new, banned)
    }

    /// Get the current score for a peer.
    pub fn score(&self, peer: &str) -> Option<i32> {
        self.scores.get(peer).map(|s| s.score)
    }

    /// Check if a peer is banned.
    pub fn is_banned(&self, peer: &str) -> bool {
        self.scores
            .get(peer)
            .map(|s| s.is_banned(&self.config, self.tick))
            .unwrap_or(false)
    }

    /// Manually ban a peer. Honors [`P2pHardeningConfig::ban_expiry_ticks`].
    pub fn ban(&mut self, peer: &str) {
        self.ban_for(peer, self.config.ban_expiry_ticks);
    }

    /// Manually ban a peer for `expiry_ticks`. 0 ticks means permanent.
    pub fn ban_for(&mut self, peer: &str, expiry_ticks: u64) {
        self.ensure_peer(peer);
        let state = self.scores.get_mut(peer).unwrap();
        state.banned = true;
        state.banned_until = if expiry_ticks == 0 {
            None
        } else {
            Some(self.tick.saturating_add(expiry_ticks))
        };
        let _ = self.save_bans();
    }

    /// Manually unban a peer (resets score to initial).
    pub fn unban(&mut self, peer: &str) {
        self.scores
            .entry(peer.to_string())
            .or_insert_with(|| ScoreState::new(self.config.initial_score));
        if let Some(s) = self.scores.get_mut(peer) {
            s.banned = false;
            s.banned_until = None;
            s.score = self.config.initial_score;
        }
        let _ = self.save_bans();
    }

    /// Get detailed stats for a peer.
    pub fn peer_stats(&self, peer: &str) -> Option<PeerStats> {
        let score = self.scores.get(peer)?;
        let rate = self.rate_limits.get(peer)?;
        let dup = self.duplicates.get(peer)?;
        Some(PeerStats {
            score: score.score,
            banned: score.is_banned(&self.config, self.tick),
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

    #[test]
    fn ban_expires_after_ticks() {
        let config = P2pHardeningConfig {
            ban_expiry_ticks: 5,
            ..Default::default()
        };
        let mut h = P2pHardening::new(config);
        h.ban("peer1");
        assert!(h.is_banned("peer1"));
        for _ in 0..4 {
            h.tick();
            assert!(h.is_banned("peer1"));
        }
        h.tick();
        assert!(!h.is_banned("peer1"));
    }

    #[test]
    fn permanent_ban_never_expires() {
        let mut h = P2pHardening::new(Default::default());
        h.ban("peer1");
        for _ in 0..10_000 {
            h.tick();
        }
        assert!(h.is_banned("peer1"));
    }

    #[test]
    fn save_and_load_bans_roundtrip() {
        let dir = std::env::temp_dir().join(format!("kovanica-bans-test-{}", std::process::id()));
        let path = dir.join("bans.json");
        let mut h = P2pHardening::new(Default::default());
        h.set_bans_path(&path);
        h.ban_for("alice", 100);
        h.ban_for("bob", 0);
        drop(h);

        let mut h2 = P2pHardening::new(Default::default());
        h2.load_bans(&path).unwrap();
        assert!(h2.is_banned("alice"));
        assert!(h2.is_banned("bob"));
        for _ in 0..100 {
            h2.tick();
        }
        assert!(!h2.is_banned("alice"));
        assert!(h2.is_banned("bob"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn auto_ban_is_persisted() {
        let dir =
            std::env::temp_dir().join(format!("kovanica-bans-auto-test-{}", std::process::id()));
        let path = dir.join("bans.json");
        let config = P2pHardeningConfig {
            score_invalid_block: -50,
            ban_threshold: -40,
            ..Default::default()
        };
        let mut h = P2pHardening::new(config);
        h.set_bans_path(&path);
        let block_id = BlockId::from_bytes([9u8; 32]);
        h.on_block("peer1", &block_id, false);
        assert!(h.is_banned("peer1"));
        drop(h);

        let mut h2 = P2pHardening::new(Default::default());
        h2.load_bans(&path).unwrap();
        assert!(h2.is_banned("peer1"));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
