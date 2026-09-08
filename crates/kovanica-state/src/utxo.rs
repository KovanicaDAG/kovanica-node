//! The UTXO set: the ledger's state.
//!
//! A [`UtxoSet`] maps every currently-unspent [`OutPoint`] to the [`TxOutput`]
//! it holds. Applying a transaction removes the outputs it spends and inserts
//! the ones it creates (see [`crate::ledger`]). Lookups are by key only, so the
//! backing `HashMap`'s iteration order never affects a consensus-relevant
//! result.

use std::collections::HashMap;

use crate::keys::Address;
use crate::tx::{AssetId, OutPoint, TxId, TxOutput};

/// The set of unspent transaction outputs — the full ledger state at a point in
/// the linearized order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
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

    /// Spendable balance owned by `owner`: the sum of the unspent **native KVNC**
    /// outputs locked to that address. Asset outputs (RFC-002) are excluded —
    /// query them with [`Self::balance_of_asset`].
    pub fn balance(&self, owner: &Address) -> u128 {
        self.map
            .values()
            .filter(|o| &o.owner == owner && o.asset_id.is_none())
            .map(|o| u128::from(o.value))
            .sum()
    }

    /// Spendable balance owned by `owner` for a specific `asset_id`.
    /// `asset_id = None` means native KVNC.
    pub fn balance_of_asset(&self, owner: &Address, asset_id: Option<AssetId>) -> u128 {
        self.map
            .values()
            .filter(|o| &o.owner == owner && o.asset_id == asset_id)
            .map(|o| u128::from(o.value))
            .sum()
    }

    /// Serialise the UTXO set for checkpoint persistence. Returns a
    /// self-contained byte encoding: count followed by (outpoint, output) pairs,
    /// sorted by outpoint for deterministic encoding.
    /// v4: includes optional asset_id (32 bytes) after owner.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&(self.map.len() as u64).to_le_bytes());
        let mut entries: Vec<_> = self.map.iter().collect();
        entries.sort_by_key(|(op, _)| *op);
        for (op, output) in entries {
            buf.extend_from_slice(op.tx.as_bytes());
            buf.extend_from_slice(&op.index.to_le_bytes());
            buf.extend_from_slice(&output.value.to_le_bytes());
            buf.extend_from_slice(output.owner.as_bytes());
            // asset_id: 0 = native (None), 1 = present + 32 bytes
            if let Some(asset_id) = output.asset_id {
                buf.push(1);
                buf.extend_from_slice(asset_id.as_bytes());
            } else {
                buf.push(0);
            }
            // stealth flag: 0 = ordinary, 1 = stealth + 65-byte extension
            // (R 32B + view_tag 1B + P 32B), mirroring the canonical TxOutput
            // encoding in tx.rs.
            if let Some(stealth) = output.stealth {
                buf.push(1);
                buf.extend_from_slice(&stealth.r);
                buf.push(stealth.view_tag);
                buf.extend_from_slice(&stealth.p);
            } else {
                buf.push(0);
            }
        }
        buf
    }

    /// Returns the length of the encoded UTXO set (for skipping during decode).
    pub fn encoded_len(&self) -> usize {
        8 + self
            .map
            .values()
            .map(|output| {
                let asset = if output.asset_id.is_some() { 1 + 32 } else { 1 };
                let stealth = if output.stealth.is_some() { 1 + 65 } else { 1 };
                32 + 4 + 8 + 33 + asset + stealth
            })
            .sum::<usize>()
    }

    /// Decode a UTXO set from a checkpoint encoding, advancing `bytes` past the
    /// consumed data so the caller can continue parsing.
    /// v4: reads optional asset_id (32 bytes) after owner.
    /// v5: reads optional stealth extension (65 bytes) after the asset_id.
    pub fn decode(bytes: &mut &[u8]) -> Result<Self, UtxoDecodeError> {
        let mut reader = CheckpointReader::new(bytes);
        let count = reader.read_u64()? as usize;
        let mut map = HashMap::with_capacity(count);
        for _ in 0..count {
            let tx = TxId::from_bytes(reader.read_array::<32>()?);
            let index = reader.read_u32()?;
            let value = reader.read_u64()?;
            let owner = Address::from_versioned_bytes(reader.read_array::<33>()?);
            // asset_id flag
            let asset_flag = reader.read_u8()?;
            let asset_id = if asset_flag == 1 {
                Some(AssetId::from_bytes(reader.read_array::<32>()?))
            } else {
                None
            };
            // stealth flag: 0 = ordinary, 1 = stealth + 65-byte extension
            let stealth_flag = reader.read_u8()?;
            let stealth = if stealth_flag == 1 {
                let r = reader.read_array::<32>()?;
                let view_tag = reader.read_u8()?;
                let p = reader.read_array::<32>()?;
                Some(crate::tx::StealthExt { r, view_tag, p })
            } else {
                None
            };
            map.insert(
                OutPoint::new(tx, index),
                TxOutput {
                    value,
                    asset_id,
                    owner,
                    stealth,
                },
            );
        }
        *bytes = &bytes[reader.pos..];
        Ok(Self { map })
    }
}

/// Errors from decoding a UTXO set checkpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UtxoDecodeError {
    /// The input ended before a fully-formed value could be read.
    UnexpectedEof,
    /// Bytes remained after the declared number of entries.
    TrailingBytes,
}

impl core::fmt::Display for UtxoDecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            UtxoDecodeError::UnexpectedEof => f.write_str("unexpected end of checkpoint"),
            UtxoDecodeError::TrailingBytes => f.write_str("trailing bytes after checkpoint"),
        }
    }
}

impl std::error::Error for UtxoDecodeError {}

struct CheckpointReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> CheckpointReader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }
    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], UtxoDecodeError> {
        if self.remaining() < N {
            return Err(UtxoDecodeError::UnexpectedEof);
        }
        let mut out = [0u8; N];
        out.copy_from_slice(&self.buf[self.pos..self.pos + N]);
        self.pos += N;
        Ok(out)
    }
    fn read_u32(&mut self) -> Result<u32, UtxoDecodeError> {
        Ok(u32::from_le_bytes(self.read_array::<4>()?))
    }
    fn read_u64(&mut self) -> Result<u64, UtxoDecodeError> {
        Ok(u64::from_le_bytes(self.read_array::<8>()?))
    }
    fn read_u8(&mut self) -> Result<u8, UtxoDecodeError> {
        if self.remaining() < 1 {
            return Err(UtxoDecodeError::UnexpectedEof);
        }
        let b = self.buf[self.pos];
        self.pos += 1;
        Ok(b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::KeyPair;
    use crate::tx::TxId;

    #[test]
    fn utxo_set_roundtrips() {
        let owner = KeyPair::from_u64(1).address();
        let op = OutPoint::new(TxId::from_bytes([1u8; 32]), 0);
        let mut set = UtxoSet::new();
        set.insert(op, TxOutput::native(10, owner));
        set.insert(
            OutPoint::new(TxId::from_bytes([2u8; 32]), 1),
            TxOutput::native(20, owner),
        );

        let bytes = set.encode();
        let mut slice = &bytes[..];
        let restored = UtxoSet::decode(&mut slice).unwrap();

        assert_eq!(restored.len(), 2);
        assert_eq!(restored.get(&op), Some(&TxOutput::native(10, owner)));
        assert_eq!(restored.total_value(), 30);
    }

    #[test]
    fn empty_utxo_set_roundtrips() {
        let set = UtxoSet::new();
        let bytes = set.encode();
        let mut slice = &bytes[..];
        let restored = UtxoSet::decode(&mut slice).unwrap();
        assert!(restored.is_empty());
    }

    #[test]
    fn insert_get_remove() {
        let owner = KeyPair::from_u64(1).address();
        let op = OutPoint::new(TxId::from_bytes([1u8; 32]), 0);
        let mut set = UtxoSet::new();
        assert!(set.is_empty());
        set.insert(op, TxOutput::native(10, owner));
        assert_eq!(set.get(&op), Some(&TxOutput::native(10, owner)));
        assert_eq!(set.balance(&owner), 10);
        assert_eq!(set.total_value(), 10);
        assert_eq!(set.remove(&op), Some(TxOutput::native(10, owner)));
        assert!(set.is_empty());
    }
}
