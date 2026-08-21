//! The UTXO set: the ledger's state.
//!
//! A [`UtxoSet`] maps every currently-unspent [`OutPoint`] to the [`TxOutput`]
//! it holds. Applying a transaction removes the outputs it spends and inserts
//! the ones it creates (see [`crate::ledger`]). Lookups are by key only, so the
//! backing `HashMap`'s iteration order never affects a consensus-relevant
//! result.

use std::collections::HashMap;

use crate::keys::Address;
use crate::tx::{OutPoint, TxOutput};

/// The set of unspent transaction outputs — the full ledger state at a point in
/// the linearized order.
#[derive(Clone, Debug, Default)]
pub struct UtxoSet {
    map: HashMap<OutPoint, TxOutput>,
}

impl UtxoSet {
    /// An empty UTXO set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Look up the output at `outpoint`, if unspent.
    pub fn get(&self, outpoint: &OutPoint) -> Option<&TxOutput> {
        self.map.get(outpoint)
    }

    /// Whether `outpoint` is currently unspent.
    pub fn contains(&self, outpoint: &OutPoint) -> bool {
        self.map.contains_key(outpoint)
    }

    /// Insert an output, returning any output previously stored at that outpoint.
    pub fn insert(&mut self, outpoint: OutPoint, output: TxOutput) -> Option<TxOutput> {
        self.map.insert(outpoint, output)
    }

    /// Remove and return the output at `outpoint`, if present.
    pub fn remove(&mut self, outpoint: &OutPoint) -> Option<TxOutput> {
        self.map.remove(outpoint)
    }

    /// Number of unspent outputs.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Whether the set is empty.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Iterate over every unspent `(outpoint, output)`. Order is unspecified.
    pub fn iter(&self) -> impl Iterator<Item = (&OutPoint, &TxOutput)> {
        self.map.iter()
    }

    /// Total value of every unspent output. Widened to `u128` so summing many
    /// `u64` outputs cannot overflow.
    pub fn total_value(&self) -> u128 {
        self.map.values().map(|o| u128::from(o.value)).sum()
    }

    /// Spendable balance owned by `owner`: the sum of the unspent outputs locked
    /// to that address.
    pub fn balance(&self, owner: &Address) -> u128 {
        self.map
            .values()
            .filter(|o| &o.owner == owner)
            .map(|o| u128::from(o.value))
            .sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::KeyPair;
    use crate::tx::TxId;

    #[test]
    fn insert_get_remove() {
        let owner = KeyPair::from_u64(1).address();
        let op = OutPoint::new(TxId::from_bytes([1u8; 32]), 0);
        let mut set = UtxoSet::new();
        assert!(set.is_empty());
        set.insert(op, TxOutput::new(10, owner));
        assert_eq!(set.get(&op), Some(&TxOutput::new(10, owner)));
        assert_eq!(set.balance(&owner), 10);
        assert_eq!(set.total_value(), 10);
        assert_eq!(set.remove(&op), Some(TxOutput::new(10, owner)));
        assert!(set.is_empty());
    }
}
