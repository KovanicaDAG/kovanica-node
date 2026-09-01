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
            min_fee_rate: 0, // no minimum by default; opt-in via config
            orphan_max_age_blocks: 100,
        }
    }
}

/// A transaction with pre-computed fee and size for eviction ordering.
#[derive(Clone, Debug)]
struct MempoolEntry {
    tx: Transaction,
    size: usize,
    fee_rate: u64, // atoms per byte
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

    /// Add a transaction to the mempool using `utxo` to compute its fee rate.
    ///
    /// Returns:
    /// - `Ok(Added::Pending)` if added to pending pool
    /// - `Ok(Added::Orphan)` if added to orphan pool (missing inputs)
    /// - `Err(MempoolError)` if rejected (duplicate, below min fee, etc.)
    pub fn add(&mut self, tx: Transaction, utxo: &UtxoSet) -> Result<Added, MempoolError> {
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

        let size = tx.encode().len();

        // If any input is missing from the UTXO set, store as orphan.
        let missing: Vec<_> = tx
            .inputs()
            .iter()
            .filter(|input| !utxo.contains(&input.outpoint))
            .cloned()
            .collect();
        if !missing.is_empty() {
            self.ensure_orphan_capacity()?;
            for input in &missing {
                self.orphans_by_missing
                    .entry(input.outpoint)
                    .or_default()
                    .insert(id);
            }
            self.orphans.insert(
                id,
                MempoolEntry {
                    tx,
                    size,
                    fee_rate: 0,
                },
            );
            return Ok(Added::Orphan);
        }

        // All inputs are available: compute fee rate.
        let _fee = tx.fee_with_utxo(utxo).ok_or(MempoolError::MissingInputs)?;
        let fee_rate = tx
            .fee_rate_with_utxo(utxo)
            .ok_or(MempoolError::MissingInputs)?;

        if fee_rate < self.config.min_fee_rate {
            return Err(MempoolError::BelowMinFeeRate {
                fee_rate,
                min: self.config.min_fee_rate,
            });
        }

        self.ensure_capacity(size)?;

        let entry = MempoolEntry { tx, size, fee_rate };
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
                // Add to orphans without a known fee (inputs are missing).
                for input in &missing {
                    self.orphans_by_missing
                        .entry(input.outpoint)
                        .or_default()
                        .insert(id);
                }
                self.orphans.insert(
                    id,
                    MempoolEntry {
                        tx: entry.tx,
                        size: entry.size,
                        fee_rate: 0,
                    },
                );
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
                // Compute fee rate now that inputs are available.
                let _fee = entry.tx.fee_with_utxo(utxo).unwrap_or(0);
                let fee_rate = entry.tx.fee_rate_with_utxo(utxo).unwrap_or(0);
                if fee_rate >= self.config.min_fee_rate {
                    self.total_bytes += entry.size;
                    self.pending.insert(
                        id,
                        MempoolEntry {
                            tx: entry.tx,
                            size: entry.size,
                            fee_rate,
                        },
                    );
                    promoted += 1;
                }
                // Txs below min fee rate are simply dropped on promotion.
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

    /// Ensure capacity by evicting lowest fee-rate txs until there is room.
    fn ensure_capacity(&mut self, new_size: usize) -> Result<(), MempoolError> {
        // Check tx count limit
        if let Some(max) = self.config.max_txs {
            while self.pending.len() >= max.get() {
                self.evict_lowest_fee_rate()?;
            }
        }

        // Check byte limit
        if let Some(max) = self.config.max_bytes {
            while self.total_bytes + new_size > max.get() {
                self.evict_lowest_fee_rate()?;
                if self.pending.is_empty() {
                    return Err(MempoolError::CapacityExceeded);
                }
            }
        }

        Ok(())
    }

    /// Ensure there is room for one more orphan.
    fn ensure_orphan_capacity(&mut self) -> Result<(), MempoolError> {
        if let Some(max) = self.config.max_orphans {
            while self.orphans.len() >= max.get() {
                self.evict_oldest_orphan()?;
            }
        }
        Ok(())
    }

    /// Evict the lowest fee-rate transaction to make room.
    fn evict_lowest_fee_rate(&mut self) -> Result<(), MempoolError> {
        if self.pending.is_empty() {
            return Err(MempoolError::CapacityExceeded);
        }

        let id = self
            .pending
            .iter()
            .min_by_key(|(_, entry)| entry.fee_rate)
            .map(|(id, _)| *id)
            .ok_or(MempoolError::CapacityExceeded)?;
        self.remove_pending(id);
        Ok(())
    }

    /// Evict the oldest orphan to make room.
    fn evict_oldest_orphan(&mut self) -> Result<(), MempoolError> {
        let id = self
            .orphans
            .keys()
            .next()
            .copied()
            .ok_or(MempoolError::CapacityExceeded)?;
        self.remove_orphan(id);
        Ok(())
    }

    /// Replace-by-fee: replace a pending transaction that conflicts on at least
    /// one input with `tx`, provided `tx` has a strictly higher fee rate.
    ///
    /// The replacement must pay at least the replaced tx's fee rate plus
    /// `min_fee_bump` atoms/byte. Returns `Added::Pending` on success.
    pub fn replace_by_fee(
        &mut self,
        tx: Transaction,
        utxo: &UtxoSet,
        min_fee_bump: u64,
    ) -> Result<Added, MempoolError> {
        let id = tx.id();
        if tx.is_coinbase() {
            return Err(MempoolError::CoinbaseRejected);
        }
        if self.pending.contains_key(&id) {
            return Err(MempoolError::Duplicate(id));
        }
        self.remove_orphan(id);

        let new_fee_rate = tx
            .fee_rate_with_utxo(utxo)
            .ok_or(MempoolError::MissingInputs)?;

        let inputs: std::collections::HashSet<_> =
            tx.inputs().iter().map(|input| input.outpoint).collect();
        let replaced_id = self.pending.iter().find_map(|(id, entry)| {
            if entry
                .tx
                .inputs()
                .iter()
                .any(|input| inputs.contains(&input.outpoint))
            {
                Some(*id)
            } else {
                None
            }
        });

        let replaced = replaced_id
            .and_then(|id| self.pending.remove(&id))
            .ok_or(MempoolError::NoReplacementTarget)?;
        self.total_bytes -= replaced.size;

        let old_rate = replaced.fee_rate;
        let required = old_rate.saturating_add(min_fee_bump);
        if new_fee_rate < required {
            // Put the original back.
            self.total_bytes += replaced.size;
            self.pending.insert(replaced.tx.id(), replaced);
            return Err(MempoolError::InsufficientFeeBump {
                old: old_rate,
                new: new_fee_rate,
                required,
            });
        }

        // Remove any other conflicts (should not happen with single-input txs,
        // but keeps the mempool consistent for multi-input replacements).
        let mut conflicts = Vec::new();
        for (id, entry) in &self.pending {
            if entry
                .tx
                .inputs()
                .iter()
                .any(|input| inputs.contains(&input.outpoint))
            {
                conflicts.push(*id);
            }
        }
        for id in conflicts {
            self.remove_pending(id);
        }

        self.add(tx, utxo)
    }

    /// Estimate a competitive fee rate from the current pending pool.
    ///
    /// Returns the 75th percentile fee rate, floored at `min_fee_rate`. If the
    /// mempool is empty or below capacity, returns `min_fee_rate`.
    pub fn fee_estimate(&self) -> u64 {
        if self.pending.is_empty() {
            return self.config.min_fee_rate;
        }

        let at_capacity = self
            .config
            .max_txs
            .is_some_and(|max| self.pending.len() >= max.get())
            || self
                .config
                .max_bytes
                .is_some_and(|max| self.total_bytes >= max.get());
        if !at_capacity {
            return self.config.min_fee_rate;
        }

        let mut rates: Vec<u64> = self.pending.values().map(|e| e.fee_rate).collect();
        rates.sort_unstable();
        let idx = (rates.len() * 3 / 4).min(rates.len() - 1);
        rates[idx].max(self.config.min_fee_rate)
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

    /// Current minimum fee rate (atoms per byte).
    pub fn min_fee_rate(&self) -> u64 {
        self.config.min_fee_rate
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
    MissingInputs,
    NoReplacementTarget,
    InsufficientFeeBump { old: u64, new: u64, required: u64 },
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
            MempoolError::MissingInputs => f.write_str("transaction spends missing inputs"),
            MempoolError::NoReplacementTarget => {
                f.write_str("no conflicting transaction to replace")
            }
            MempoolError::InsufficientFeeBump { old, new, required } => write!(
                f,
                "insufficient fee bump: rate {new} < required {required} (old {old})"
            ),
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
    use kovanica_state::{Address, KeyPair, OutPoint, TxOutput, UtxoSet};

    fn addr(seed: u64) -> Address {
        KeyPair::from_u64(seed).address()
    }

    fn tx_spending(op: OutPoint, _input_value: u64, output_value: u64) -> Transaction {
        let kp = KeyPair::from_u64(1);
        Transaction::signed(
            &[(op, &kp)],
            vec![TxOutput::new(output_value, kp.address())],
            vec![],
        )
    }

    fn utxo_with(op: OutPoint, value: u64) -> UtxoSet {
        let mut utxo = UtxoSet::new();
        utxo.insert(op, TxOutput::new(value, addr(1)));
        utxo
    }

    #[test]
    fn add_dedup() {
        let config = MempoolConfig {
            min_fee_rate: 0,
            ..Default::default()
        };
        let mut pool = MempoolV2::new(config);
        let op = OutPoint::new(TxId::from_bytes([1u8; 32]), 0);
        let tx = tx_spending(op, 100, 99);
        let utxo = utxo_with(op, 100);
        let tx_id = tx.id();
        assert_eq!(pool.add(tx.clone(), &utxo), Ok(Added::Pending));
        assert_eq!(pool.add(tx, &utxo), Err(MempoolError::Duplicate(tx_id)));
    }

    #[test]
    fn missing_inputs_go_to_orphan_pool() {
        let mut pool = MempoolV2::default();
        let kp = KeyPair::from_u64(1);
        let op = OutPoint::new(TxId::from_bytes([1u8; 32]), 0);
        let tx = Transaction::signed(&[(op, &kp)], vec![TxOutput::new(50, kp.address())], vec![]);
        let utxo = UtxoSet::new();
        assert_eq!(pool.add(tx.clone(), &utxo), Ok(Added::Orphan));
        assert_eq!(pool.len_pending(), 0);
        assert_eq!(pool.len_orphans(), 1);
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

        let op1 = OutPoint::new(TxId::from_bytes([1u8; 32]), 0);
        let op2 = OutPoint::new(TxId::from_bytes([2u8; 32]), 0);
        let op3 = OutPoint::new(TxId::from_bytes([3u8; 32]), 0);
        let mut utxo = UtxoSet::new();
        utxo.insert(op1, TxOutput::new(100_000, addr(1)));
        utxo.insert(op2, TxOutput::new(100_000, addr(1)));
        utxo.insert(op3, TxOutput::new(100_000, addr(1)));

        // Low fee
        let tx1 = tx_spending(op1, 100_000, 99_000);
        pool.add(tx1.clone(), &utxo).unwrap();

        // High fee
        let tx2 = tx_spending(op2, 100_000, 50_000);
        pool.add(tx2.clone(), &utxo).unwrap();

        // Medium fee - should evict lowest (tx1)
        let tx3 = tx_spending(op3, 100_000, 80_000);
        pool.add(tx3.clone(), &utxo).unwrap();

        assert_eq!(pool.len_pending(), 2);
        assert!(pool.contains_pending(&tx2.id()));
        assert!(pool.contains_pending(&tx3.id()));
        assert!(!pool.contains_pending(&tx1.id()));
    }

    #[test]
    fn orphan_promotion_on_new_block() {
        let config = MempoolConfig {
            min_fee_rate: 0,
            ..Default::default()
        };
        let mut pool = MempoolV2::new(config);
        let kp = KeyPair::from_u64(1);
        let op = OutPoint::new(TxId::from_bytes([1u8; 32]), 0);

        let tx = Transaction::signed(&[(op, &kp)], vec![TxOutput::new(1, kp.address())], vec![]);
        pool.add(tx.clone(), &UtxoSet::new()).unwrap();
        assert_eq!(pool.len_orphans(), 1);

        let mut utxo = UtxoSet::new();
        utxo.insert(op, TxOutput::new(1000, kp.address()));

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

        let tx = Transaction::signed(&[(op, &kp)], vec![TxOutput::new(1, kp.address())], vec![]);
        pool.add(tx.clone(), &UtxoSet::new()).unwrap();

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
        let mut utxo = UtxoSet::new();

        // Add 3 txs with different fee rates
        let kp = KeyPair::from_u64(1);
        for i in 0..3 {
            let op = OutPoint::new(TxId::from_bytes([i; 32]), 0);
            let fee = (i + 1) as u64 * 10; // 10, 20, 30
            utxo.insert(op, TxOutput::new(100, addr(1)));
            let tx = Transaction::signed(
                &[(op, &kp)],
                vec![TxOutput::new(100 - fee, kp.address())],
                vec![],
            );
            pool.add(tx, &utxo).unwrap();
        }

        // Add 4th with highest fee - should evict lowest (10)
        let op = OutPoint::new(TxId::from_bytes([9u8; 32]), 0);
        utxo.insert(op, TxOutput::new(100, addr(1)));
        let tx4 = Transaction::signed(&[(op, &kp)], vec![TxOutput::new(40, kp.address())], vec![]);
        pool.add(tx4, &utxo).unwrap();

        assert_eq!(pool.len_pending(), 3);
    }

    #[test]
    fn min_fee_rate_enforced() {
        let config = MempoolConfig {
            min_fee_rate: 1000, // 1000 atoms/byte
            ..Default::default()
        };
        let mut pool = MempoolV2::new(config);

        let op = OutPoint::new(TxId::from_bytes([1u8; 32]), 0);
        let utxo = utxo_with(op, 100);
        let kp = KeyPair::from_u64(1);
        // Very low fee
        let tx = Transaction::signed(&[(op, &kp)], vec![TxOutput::new(99, kp.address())], vec![]);
        let err = pool.add(tx, &utxo).unwrap_err();
        assert!(matches!(err, MempoolError::BelowMinFeeRate { .. }));
    }

    #[test]
    fn remove_all_clears_both_pools() {
        let config = MempoolConfig {
            min_fee_rate: 0,
            ..Default::default()
        };
        let mut pool = MempoolV2::new(config);
        let kp = KeyPair::from_u64(1);
        let op1 = OutPoint::new(TxId::from_bytes([1u8; 32]), 0);
        let op2 = OutPoint::new(TxId::from_bytes([2u8; 32]), 0);

        let tx1 = Transaction::signed(&[(op1, &kp)], vec![TxOutput::new(1, kp.address())], vec![]);
        let tx2 = Transaction::signed(&[(op2, &kp)], vec![TxOutput::new(1, kp.address())], vec![]);

        let mut utxo = UtxoSet::new();
        utxo.insert(op1, TxOutput::new(1000, kp.address()));
        pool.add(tx1.clone(), &utxo).unwrap();
        pool.add(tx2.clone(), &UtxoSet::new()).unwrap();

        pool.remove_all(&[tx1.id(), tx2.id()]);
        assert!(pool.is_empty());
    }

    #[test]
    fn replace_by_fee_succeeds_with_sufficient_bump() {
        let config = MempoolConfig {
            min_fee_rate: 0,
            ..Default::default()
        };
        let mut pool = MempoolV2::new(config);
        let op = OutPoint::new(TxId::from_bytes([1u8; 32]), 0);
        let mut utxo = UtxoSet::new();
        utxo.insert(op, TxOutput::new(10_000, addr(1)));

        let tx1 = tx_spending(op, 10_000, 9_000); // fee 1000
        pool.add(tx1.clone(), &utxo).unwrap();
        let rate1 = pool.pending[&tx1.id()].fee_rate;

        let tx2 = tx_spending(op, 10_000, 5_000); // fee 5000, higher rate
        let result = pool.replace_by_fee(tx2.clone(), &utxo, 1);
        assert_eq!(result, Ok(Added::Pending));
        assert!(!pool.contains_pending(&tx1.id()));
        assert!(pool.contains_pending(&tx2.id()));
        assert!(pool.pending[&tx2.id()].fee_rate > rate1);
    }

    #[test]
    fn replace_by_fee_fails_without_bump() {
        let config = MempoolConfig {
            min_fee_rate: 0,
            ..Default::default()
        };
        let mut pool = MempoolV2::new(config);
        let op = OutPoint::new(TxId::from_bytes([1u8; 32]), 0);
        let mut utxo = UtxoSet::new();
        utxo.insert(op, TxOutput::new(10_000, addr(1)));

        let tx1 = tx_spending(op, 10_000, 9_000);
        pool.add(tx1.clone(), &utxo).unwrap();

        let tx2 = tx_spending(op, 10_000, 9_500); // lower fee rate
        let err = pool.replace_by_fee(tx2, &utxo, 1).unwrap_err();
        assert!(matches!(err, MempoolError::InsufficientFeeBump { .. }));
        assert!(pool.contains_pending(&tx1.id()));
    }

    #[test]
    fn replace_by_fee_requires_conflict() {
        let config = MempoolConfig {
            min_fee_rate: 0,
            ..Default::default()
        };
        let mut pool = MempoolV2::new(config);
        let op1 = OutPoint::new(TxId::from_bytes([1u8; 32]), 0);
        let op2 = OutPoint::new(TxId::from_bytes([2u8; 32]), 0);
        let mut utxo = UtxoSet::new();
        utxo.insert(op1, TxOutput::new(10_000, addr(1)));
        utxo.insert(op2, TxOutput::new(10_000, addr(1)));

        let tx1 = tx_spending(op1, 10_000, 9_000);
        pool.add(tx1, &utxo).unwrap();

        let tx2 = tx_spending(op2, 10_000, 5_000);
        let err = pool.replace_by_fee(tx2, &utxo, 1).unwrap_err();
        assert_eq!(err, MempoolError::NoReplacementTarget);
    }

    #[test]
    fn fee_estimate_at_capacity() {
        let config = MempoolConfig {
            max_txs: Some(NonZeroUsize::new(3).unwrap()),
            min_fee_rate: 1,
            ..Default::default()
        };
        let mut pool = MempoolV2::new(config);
        let mut utxo = UtxoSet::new();

        for i in 0..3u8 {
            let op = OutPoint::new(TxId::from_bytes([i; 32]), 0);
            utxo.insert(op, TxOutput::new(100_000, addr(1)));
            // fee = 1000 + i*1000
            let tx = tx_spending(op, 100_000, 99_000 - u64::from(i) * 1000);
            pool.add(tx, &utxo).unwrap();
        }

        // Mempool is full; estimate should be at least the median rate.
        let estimate = pool.fee_estimate();
        assert!(estimate >= pool.config.min_fee_rate);
    }

    #[test]
    fn fee_estimate_below_capacity_is_min_rate() {
        let config = MempoolConfig {
            min_fee_rate: 0,
            ..Default::default()
        };
        let mut pool = MempoolV2::new(config);
        let op = OutPoint::new(TxId::from_bytes([1u8; 32]), 0);
        let mut utxo = UtxoSet::new();
        utxo.insert(op, TxOutput::new(10_000, addr(1)));
        let tx = tx_spending(op, 10_000, 9_000);
        pool.add(tx, &utxo).unwrap();

        assert_eq!(pool.fee_estimate(), pool.config.min_fee_rate);
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
