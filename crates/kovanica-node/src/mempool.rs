//! The mempool: transactions a node has accepted but not yet packed into a
//! block.
//!
//! It is a de-duplicated set keyed by [`TxId`]. It performs no stateful
//! validation itself — that happens when a block is assembled from it (see
//! [`Node::produce_block`](crate::Node::produce_block)), where each candidate is
//! applied against the current UTXO state and only the ones that hold are
//! included. Ordering for assembly is by id, so block construction is
//! deterministic across nodes.
//!
//! This is the legacy `Mempool` type kept for backward compatibility.
//! New code should use [`MempoolV2`] which adds orphan handling, fee-based
//! eviction, and capacity limits.

use kovanica_state::{Transaction, TxId, UtxoSet};

use crate::mempool_v2::{Added, MempoolV2};

/// A set of pending transactions (legacy API).
#[derive(Debug, Default)]
pub struct Mempool {
    inner: MempoolV2,
}

impl Mempool {
    /// An empty mempool.
    pub fn new() -> Self {
        Self {
            inner: MempoolV2::default(),
        }
    }

    /// Add a transaction. Returns `false` if one with the same id was already
    /// present (a no-op).
    pub fn add(&mut self, tx: Transaction) -> bool {
        matches!(self.inner.add(tx), Ok(Added::Pending))
    }

    /// Whether a transaction with this id is pending.
    pub fn contains(&self, id: &TxId) -> bool {
        self.inner.contains_pending(id)
    }

    /// The pending transaction with this id, if present.
    pub fn get(&self, id: &TxId) -> Option<Transaction> {
        self.inner.get(id).cloned()
    }

    /// Number of pending transactions.
    pub fn len(&self) -> usize {
        self.inner.len_pending()
    }

    /// Whether the mempool is empty.
    pub fn is_empty(&self) -> bool {
        self.inner.len_pending() == 0
    }

    /// The pending transactions in a deterministic order (by id), for
    /// reproducible block assembly.
    pub fn ordered(&self) -> Vec<Transaction> {
        self.inner.ordered_pending()
    }

    /// Remove the given transactions (e.g. after they were included in a block).
    pub fn remove_all(&mut self, ids: &[TxId]) {
        self.inner.remove_all(ids);
    }

    /// Drop transactions that can never be valid against the current selected-tip
    /// UTXO view: any input that is not currently unspent. A tx whose funding
    /// output simply has not arrived yet is also dropped — this slice treats
    /// "missing input" as permanently invalid on *this* branch (a later re-gossip
    /// can re-introduce it after a re-org). Returns how many were removed.
    pub fn evict_invalid(&mut self, utxo: &UtxoSet) -> usize {
        self.inner.evict_invalid(utxo)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kovanica_state::{KeyPair, OutPoint, TxOutput, UtxoSet};

    fn tx(seed: u8) -> Transaction {
        let kp = KeyPair::from_u64(1);
        let op = OutPoint::new(TxId::from_bytes([seed; 32]), 0);
        Transaction::signed(&[(op, &kp)], vec![TxOutput::new(1, kp.address())], vec![])
    }

    #[test]
    fn add_dedups_and_orders() {
        let mut pool = Mempool::new();
        assert!(pool.add(tx(1)));
        assert!(!pool.add(tx(1)), "duplicate is a no-op");
        assert!(pool.add(tx(2)));
        assert_eq!(pool.len(), 2);

        // ordered() is sorted by id and stable.
        assert_eq!(pool.ordered(), pool.ordered());

        let ids: Vec<TxId> = pool.ordered().iter().map(|t| t.id()).collect();
        pool.remove_all(&ids);
        assert!(pool.is_empty());
    }

    #[test]
    fn evict_drops_txs_whose_inputs_are_gone() {
        let mut pool = Mempool::new();
        let t = tx(1);
        let op = t.inputs()[0].outpoint;
        pool.add(t.clone());
        assert_eq!(pool.evict_invalid(&UtxoSet::new()), 1);
        assert!(pool.is_empty());

        pool.add(t);
        let mut utxo = UtxoSet::new();
        utxo.insert(op, TxOutput::new(1, KeyPair::from_u64(1).address()));
        assert_eq!(pool.evict_invalid(&utxo), 0);
        assert_eq!(pool.len(), 1);
    }
}
