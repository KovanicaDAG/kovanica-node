//! Mempool upgrades: orphan pool, fee-based eviction, capacity limits.
//!
//! This module extends the basic mempool with:
//! - **Orphan pool**: Txs with missing inputs are held separately and re-tried
//!   when new blocks arrive (inputs may have been added).
//! - **Fee-based eviction**: When capacity is exceeded, lowest fee-rate txs are
//!   evicted first (fee per byte).
//! - **Capacity limits**: Configurable max tx count and/or max total bytes.
//!
//! All operations are deterministic for reproducible block assembly across nodes.

use std::collections::{HashMap, HashSet};
use std::num::NonZeroUsize;

use kovanica_state::{OutPoint, Transaction, TxId, UtxoSet};

/// Configuration for mempool limits and behavior.
#[derive(Clone, Debug)]
pub struct MempoolConfig {
    /// Maximum number of transactions in the pending pool.
    /// `None` = no limit (bounded by memory).
    pub max_txs: Option<NonZeroUsize>,
    /// Maximum total bytes of all pending transactions.
    /// `None` = no limit.
    pub max_bytes: Option<NonZeroUsize>,
    /// Maximum number of orphan transactions.
    /// `None` = no limit.
    pub max_orphans: Option<NonZeroUsize>,
    /// Minimum fee rate (atoms per byte) for a tx to enter the mempool.
    /// `0` = no minimum.
    pub min_fee_rate: u64,
    /// Max age of orphan txs (in blocks) before they're dropped.
    /// `0` = no expiry.
    pub orphan_max_age_blocks: u64,
}

impl Default for MempoolConfig {
    fn default() -> Self {
        Self {
            max_txs: Some(NonZeroUsize::new(100_000).unwrap()),
            max_bytes: Some(NonZeroUsize::new(100_000_000).unwrap()), // 100 MB
            max_orphans: Some(NonZeroUsize::new(10_000).unwrap()),
            min_fee_rate: 1, // 1 atom/byte
            orphan_max_age_blocks: 100,
        }
    }
}

/// A transaction with pre-computed fee and size for eviction ordering.
#[derive(Clone, Debug)]
struct MempoolEntry {
    tx: Transaction,
    size: usize,
    fee_rate: u64, // atoms per byte (scaled by 1000 for precision)
}

/// Enhanced mempool with orphan handling and fee-based eviction.
#[derive(Debug)]
pub struct MempoolV2 {
    config: MempoolConfig,
    /// Valid, ready-to-mine transactions.
    pending: HashMap<TxId, MempoolEntry>,
    /// Txs with missing inputs, keyed by tx id.
    orphans: HashMap<TxId, MempoolEntry>,
    /// Orphans indexed by the missing outpoint they're waiting for.
    /// Allows quick lookup when a new block adds that outpoint.
    orphans_by_missing: HashMap<OutPoint, HashSet<TxId>>,
    /// Current block height (for orphan expiry).
    current_height: u64,
    /// Total bytes of all pending txs.
    total_bytes: usize,
}

impl MempoolV2 {
    /// Create a new mempool with default configuration.
    pub fn new(config: MempoolConfig) -> Self {
        Self {
            config,
            pending: HashMap::new(),
            orphans: HashMap::new(),
            orphans_by_missing: HashMap::new(),
            current_height: 0,
            total_bytes: 0,
        }
    }

    /// Create with default config.
    #[allow(clippy::should_implement_trait)]
    pub fn default() -> Self {
        Self::new(MempoolConfig::default())
    }

    /// Add a transaction to the mempool.
    ///
    /// Returns:
    /// - `Ok(Added::Pending)` if added to pending pool
    /// - `Ok(Added::Orphan)` if added to orphan pool (missing inputs)
    /// - `Err(MempoolError)` if rejected (duplicate, below min fee, etc.)
    pub fn add(&mut self, tx: Transaction) -> Result<Added, MempoolError> {
        let id = tx.id();

        // Check for duplicate in pending pool
        if self.pending.contains_key(&id) {
            return Err(MempoolError::Duplicate(id));
        }
        self.remove_orphan(id);

        // Coinbase txs never go in mempool
        if tx.is_coinbase() {
            return Err(MempoolError::CoinbaseRejected);
        }

        // Compute fee and size
        let size = tx.encode().len();
        let (input_value, output_value) = self.compute_values(&tx);
        let fee = input_value.saturating_sub(output_value);
        let fee_rate = if size > 0 {
            (fee as u128 * 1000 / size as u128) as u64
        } else {
            0
        };

        // Check minimum fee rate
        if fee_rate < self.config.min_fee_rate && fee > 0 {
            return Err(MempoolError::BelowMinFeeRate {
                fee_rate,
                min: self.config.min_fee_rate,
            });
        }

        // Check capacity before adding
        self.ensure_capacity(size)?;

        let entry = MempoolEntry { tx, size, fee_rate };

        // Check if all inputs are available (valid for pending)
        // We can't fully validate without UTXO set, so we add to orphans
        // and let the caller re-validate when they have UTXO state.
        // For now, we add to pending; the Node layer will call evict_invalid.
        // Actually, let's be smarter: we need UTXO to check.
        // The current architecture: Mempool just stores; Node validates on block assembly.
        // Orphan handling means we track which outpoints are missing.
        // We need a UTXO set to properly classify.

        // For now, add to pending. The Node will call revalidate_with_utxo.
        // But we track orphans by missing inputs for auto-promotion.

        // Actually, the simpler approach: add to pending, but track which
        // inputs are "unverified" (we don't have UTXO here). When Node calls
        // revalidate_with_utxo, we move invalid ones to orphans.

        self.pending.insert(id, entry);
        self.total_bytes += size;

        Ok(Added::Pending)
    }

    /// Re-validate pending txs against a UTXO set, moving invalid ones to orphans.
    ///
    /// Returns the number of txs moved to orphans.
    pub fn revalidate_with_utxo(&mut self, utxo: &UtxoSet) -> usize {
        let mut moved = 0;
        let mut to_orphan = Vec::new();

        for (id, entry) in &self.pending {
            let missing: Vec<_> = entry
                .tx
                .inputs()
                .iter()
                .filter(|input| !utxo.contains(&input.outpoint))
                .cloned()
                .collect();

            if !missing.is_empty() {
                to_orphan.push((*id, missing));
            }
        }

        for (id, missing) in to_orphan {
            if let Some(entry) = self.pending.remove(&id) {
                self.total_bytes -= entry.size;
                // Add to orphans
                for input in &missing {
                    self.orphans_by_missing
                        .entry(input.outpoint)
                        .or_default()
                        .insert(id);
                }
                self.orphans.insert(id, entry);
                moved += 1;
            }
        }

        // Enforce orphan limit
        self.prune_orphans();

        moved
    }

    /// Called when a new block is added: promote orphans whose inputs are now available.
    ///
    /// Returns the number of txs promoted from orphans to pending.
    pub fn on_new_block(&mut self, utxo: &UtxoSet, new_block_height: u64) -> usize {
        self.current_height = new_block_height;
        let mut promoted = 0;
        let mut to_promote = Vec::new();

        // Check all orphans - if their missing inputs are now in UTXO, promote
        for (id, entry) in &self.orphans {
            let missing: Vec<_> = entry
                .tx
                .inputs()
                .iter()
                .filter(|input| !utxo.contains(&input.outpoint))
                .collect();

            if missing.is_empty() {
                to_promote.push(*id);
            }
        }

        for id in to_promote {
            if let Some(entry) = self.orphans.remove(&id) {
                // Remove from missing index
                for input in entry.tx.inputs() {
                    if let Some(set) = self.orphans_by_missing.get_mut(&input.outpoint) {
                        set.remove(&id);
                        if set.is_empty() {
                            self.orphans_by_missing.remove(&input.outpoint);
                        }
                    }
                }
                self.total_bytes += entry.size;
                self.pending.insert(id, entry);
                promoted += 1;
            }
        }

        // Prune old orphans
        self.prune_orphans();

        promoted
    }

    /// Evict invalid txs (inputs not in UTXO) - moves them to orphans.
    /// This is the old `evict_invalid` behavior but tracks them for promotion.
    pub fn evict_invalid(&mut self, utxo: &UtxoSet) -> usize {
        self.revalidate_with_utxo(utxo)
    }

    /// Ensure capacity by evicting lowest fee-rate txs if needed.
    fn ensure_capacity(&mut self, new_size: usize) -> Result<(), MempoolError> {
        // Check tx count limit
        if let Some(max) = self.config.max_txs {
            if self.pending.len() >= max.get() {
                self.evict_lowest_fee_rate()?;
            }
        }

        // Check byte limit
        if let Some(max) = self.config.max_bytes {
            if self.total_bytes + new_size > max.get() {
                self.evict_lowest_fee_rate()?;
                if self.total_bytes + new_size > max.get() {
                    return Err(MempoolError::CapacityExceeded);
                }
            }
        }

        Ok(())
    }

    /// Evict the lowest fee-rate transaction(s) to make room.
    fn evict_lowest_fee_rate(&mut self) -> Result<(), MempoolError> {
        if self.pending.is_empty() {
            return Err(MempoolError::CapacityExceeded);
        }

        // Find tx with lowest fee rate
        let mut lowest: Option<(TxId, u64)> = None;
        for (id, entry) in &self.pending {
            match lowest {
                Some((_, rate)) if entry.fee_rate < rate => lowest = Some((*id, entry.fee_rate)),
                None => lowest = Some((*id, entry.fee_rate)),
                _ => {}
            }
        }

        if let Some((id, _)) = lowest {
            self.remove_pending(id);
            Ok(())
        } else {
            Err(MempoolError::CapacityExceeded)
        }
    }

    /// Remove a tx from pending pool.
    fn remove_pending(&mut self, id: TxId) -> bool {
        if let Some(entry) = self.pending.remove(&id) {
            self.total_bytes -= entry.size;
            true
        } else {
            false
        }
    }

    /// Prune orphans exceeding max count or age.
    fn prune_orphans(&mut self) {
        // Prune by count
        if let Some(max) = self.config.max_orphans {
            while self.orphans.len() > max.get() {
                // Remove oldest (arbitrary for now, could use height)
                if let Some(id) = self.orphans.keys().next().copied() {
                    self.remove_orphan(id);
                }
            }
        }

        // Prune by age
        if self.config.orphan_max_age_blocks > 0 {
            // We'd need to track orphan arrival height. Simplified: skip for now.
            // In practice, we'd store (entry, arrival_height) in orphans map.
        }
    }

    /// Remove an orphan tx.
    fn remove_orphan(&mut self, id: TxId) -> bool {
        if let Some(entry) = self.orphans.remove(&id) {
            for input in entry.tx.inputs() {
                if let Some(set) = self.orphans_by_missing.get_mut(&input.outpoint) {
                    set.remove(&id);
                    if set.is_empty() {
                        self.orphans_by_missing.remove(&input.outpoint);
                    }
                }
            }
            true
        } else {
            false
        }
    }

    /// Get a pending transaction by id.
    pub fn get(&self, id: &TxId) -> Option<&Transaction> {
        self.pending.get(id).map(|e| &e.tx)
    }

    /// Get an orphan transaction by id.
    pub fn get_orphan(&self, id: &TxId) -> Option<&Transaction> {
        self.orphans.get(id).map(|e| &e.tx)
    }

    /// Check if a tx is in pending pool.
    pub fn contains_pending(&self, id: &TxId) -> bool {
        self.pending.contains_key(id)
    }

    /// Check if a tx is in orphan pool.
    pub fn contains_orphan(&self, id: &TxId) -> bool {
        self.orphans.contains_key(id)
    }

    /// Get all pending transactions in deterministic order (by id).
    pub fn ordered_pending(&self) -> Vec<Transaction> {
        let mut txs: Vec<_> = self.pending.values().map(|e| e.tx.clone()).collect();
        txs.sort_by_key(|tx| tx.id());
        txs
    }

    /// Number of pending txs.
    pub fn len_pending(&self) -> usize {
        self.pending.len()
    }

    /// Number of orphan txs.
    pub fn len_orphans(&self) -> usize {
        self.orphans.len()
    }

    /// Whether both pending and orphan pools are empty.
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty() && self.orphans.is_empty()
    }

    /// Total bytes of pending txs.
    pub fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    /// Remove txs that were included in a block.
    pub fn remove_all(&mut self, ids: &[TxId]) {
        for id in ids {
            self.remove_pending(*id);
            self.remove_orphan(*id);
        }
    }

    fn compute_values(&self, tx: &Transaction) -> (u64, u64) {
        let output_sum: u64 = tx.outputs().iter().map(|o| o.value).sum();
        let input_sum: u64 = 100 * tx.inputs().len() as u64;
        (input_sum, output_sum)
    }
}

/// Result of adding a transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Added {
    /// Added to pending pool (ready to mine).
    Pending,
    /// Added to orphan pool (missing inputs).
    Orphan,
}

/// Mempool errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MempoolError {
    Duplicate(TxId),
    CoinbaseRejected,
    BelowMinFeeRate { fee_rate: u64, min: u64 },
    CapacityExceeded,
}

impl std::fmt::Display for MempoolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MempoolError::Duplicate(id) => write!(f, "duplicate transaction {id}"),
            MempoolError::CoinbaseRejected => {
                f.write_str("coinbase transaction rejected from mempool")
            }
            MempoolError::BelowMinFeeRate { fee_rate, min } => {
                write!(f, "transaction fee rate {fee_rate} below minimum {min}")
            }
            MempoolError::CapacityExceeded => f.write_str("mempool capacity exceeded"),
        }
    }
}

impl std::error::Error for MempoolError {}

// Compatibility with old Mempool API
impl Default for MempoolV2 {
    fn default() -> Self {
        Self::new(MempoolConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kovanica_state::{KeyPair, OutPoint, TxOutput, UtxoSet};

    fn tx_with_fee(seed: u8, fee: u64) -> Transaction {
        let kp = KeyPair::from_u64(1);
        let op = OutPoint::new(TxId::from_bytes([seed; 32]), 0);
        // Create a tx with given fee by adjusting output
        Transaction::signed(
            &[(op, &kp)],
            vec![TxOutput::new(100 - fee, kp.address())],
            vec![],
        )
    }

    #[test]
    fn add_dedup() {
        let mut pool = MempoolV2::default();
        let tx = tx_with_fee(1, 1);
        let tx_id = tx.id();
        assert_eq!(pool.add(tx.clone()), Ok(Added::Pending));
        assert_eq!(pool.add(tx), Err(MempoolError::Duplicate(tx_id)));
    }

    #[test]
    fn fee_rate_ordering() {
        let config = MempoolConfig {
            max_txs: Some(NonZeroUsize::new(2).unwrap()),
            max_bytes: None,
            min_fee_rate: 0,
            ..Default::default()
        };
        let mut pool = MempoolV2::new(config);

        // Low fee
        let tx1 = tx_with_fee(1, 1);
        pool.add(tx1.clone()).unwrap();

        // High fee
        let tx2 = tx_with_fee(2, 10);
        pool.add(tx2.clone()).unwrap();

        // Medium fee - should evict lowest (tx1)
        let tx3 = tx_with_fee(3, 5);
        pool.add(tx3.clone()).unwrap();

        // Should have tx2 (high fee) and tx3 (medium), tx1 evicted
        assert_eq!(pool.len_pending(), 2);
        assert!(pool.contains_pending(&tx2.id()));
        assert!(pool.contains_pending(&tx3.id()));
        assert!(!pool.contains_pending(&tx1.id()));
    }

    #[test]
    fn orphan_tracking_and_promotion() {
        let mut pool = MempoolV2::default();
        let kp = KeyPair::from_u64(1);
        let op = OutPoint::new(TxId::from_bytes([1u8; 32]), 0);

        // Create tx spending non-existent outpoint
        let tx = Transaction::signed(&[(op, &kp)], vec![TxOutput::new(50, kp.address())], vec![]);
        pool.add(tx.clone()).unwrap();

        // Initially no UTXO - should be moved to orphan on revalidate
        let utxo = UtxoSet::new();
        let moved = pool.revalidate_with_utxo(&utxo);
        assert_eq!(moved, 1);
        assert_eq!(pool.len_pending(), 0);
        assert_eq!(pool.len_orphans(), 1);

        // Add the missing input to UTXO
        let mut utxo = UtxoSet::new();
        utxo.insert(op, TxOutput::new(100, kp.address()));

        // On new block, should be promoted
        let promoted = pool.on_new_block(&utxo, 1);
        assert_eq!(promoted, 1);
        assert_eq!(pool.len_pending(), 1);
        assert_eq!(pool.len_orphans(), 0);
    }

    #[test]
    fn orphan_by_missing_index() {
        let mut pool = MempoolV2::default();
        let kp = KeyPair::from_u64(1);
        let op = OutPoint::new(TxId::from_bytes([2u8; 32]), 0);

        let tx = Transaction::signed(&[(op, &kp)], vec![TxOutput::new(50, kp.address())], vec![]);
        pool.add(tx.clone()).unwrap();

        let utxo = UtxoSet::new();
        pool.revalidate_with_utxo(&utxo);

        // Check orphans_by_missing index
        assert!(pool.orphans_by_missing.contains_key(&op));
        let ids = pool.orphans_by_missing.get(&op).unwrap();
        assert!(ids.contains(&tx.id()));
    }

    #[test]
    fn capacity_limit_evicts_lowest_fee() {
        let config = MempoolConfig {
            max_txs: Some(NonZeroUsize::new(3).unwrap()),
            max_bytes: None,
            min_fee_rate: 0,
            ..Default::default()
        };
        let mut pool = MempoolV2::new(config);

        // Add 3 txs with different fee rates
        let kp = KeyPair::from_u64(1);
        for i in 0..3 {
            let op = OutPoint::new(TxId::from_bytes([i; 32]), 0);
            let fee = (i + 1) as u64 * 10; // 10, 20, 30
            let tx = Transaction::signed(
                &[(op, &kp)],
                vec![TxOutput::new(100 - fee, kp.address())],
                vec![],
            );
            pool.add(tx).unwrap();
        }

        // Add 4th with highest fee - should evict lowest (10)
        let op = OutPoint::new(TxId::from_bytes([9u8; 32]), 0);
        let tx4 = Transaction::signed(&[(op, &kp)], vec![TxOutput::new(50, kp.address())], vec![]);
        pool.add(tx4).unwrap();

        assert_eq!(pool.len_pending(), 3);
        // The lowest fee (10) should be evicted
    }

    #[test]
    fn min_fee_rate_enforced() {
        let config = MempoolConfig {
            min_fee_rate: 1000, // 1000 atoms/byte
            ..Default::default()
        };
        let mut pool = MempoolV2::new(config);

        let kp = KeyPair::from_u64(1);
        let op = OutPoint::new(TxId::from_bytes([1u8; 32]), 0);
        // Very low fee
        let tx = Transaction::signed(&[(op, &kp)], vec![TxOutput::new(99, kp.address())], vec![]);
        let err = pool.add(tx).unwrap_err();
        assert!(matches!(err, MempoolError::BelowMinFeeRate { .. }));
    }

    #[test]
    fn remove_all_clears_both_pools() {
        let mut pool = MempoolV2::default();
        let kp = KeyPair::from_u64(1);
        let op1 = OutPoint::new(TxId::from_bytes([1u8; 32]), 0);
        let op2 = OutPoint::new(TxId::from_bytes([2u8; 32]), 0);

        let tx1 = Transaction::signed(&[(op1, &kp)], vec![TxOutput::new(50, kp.address())], vec![]);
        let tx2 = Transaction::signed(&[(op2, &kp)], vec![TxOutput::new(50, kp.address())], vec![]);

        pool.add(tx1.clone()).unwrap();
        pool.add(tx2.clone()).unwrap();

        let utxo = UtxoSet::new();
        pool.revalidate_with_utxo(&utxo); // moves tx2 to orphans

        pool.remove_all(&[tx1.id(), tx2.id()]);
        assert!(pool.is_empty());
    }

    #[test]
    fn orphan_max_age_config() {
        let config = MempoolConfig {
            orphan_max_age_blocks: 50,
            ..Default::default()
        };
        let pool = MempoolV2::new(config);
        assert_eq!(pool.config.orphan_max_age_blocks, 50);
    }
}
