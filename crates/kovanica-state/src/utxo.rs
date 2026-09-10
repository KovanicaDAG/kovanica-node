//! The UTXO set: the ledger's state.
//!
//! A [`UtxoSet`] maps every currently-unspent [`OutPoint`] to a [`UtxoEntry`]:
//! the [`TxOutput`] it holds plus the linearized block **height at which it was
//! created** (RFC-005: relative locktime / CSV needs each input's confirming
//! height). Applying a transaction removes the outputs it spends and inserts
//! the ones it creates (see [`crate::ledger`]). Lookups are by key only, so the
//! backing `HashMap`'s iteration order never affects a consensus-relevant
//! result.

use std::collections::HashMap;

use crate::keys::Address;
use crate::tx::{AssetId, OutPoint, TxId, TxOutput};

/// An unspent output together with the linearized block height at which it
/// entered the set. `creation_height` is what relative locktime (BIP-68 /
/// BIP-112 CSV, RFC-005) measures against.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UtxoEntry {
    /// The unspent output itself.
    pub output: TxOutput,
    /// Linearized block height of the block that created this output.
    pub creation_height: u64,
}

impl UtxoEntry {
    /// A legacy entry with no relative-lock age (`creation_height = 0`).
    pub const fn new_legacy(output: TxOutput) -> Self {
        Self {
            output,
            creation_height: 0,
        }
    }
}

/// The set of unspent transaction outputs — the full ledger state at a point in
/// the linearized order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UtxoSet {
    map: HashMap<OutPoint, UtxoEntry>,
}

impl UtxoSet {
    /// An empty UTXO set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Look up the output at `outpoint`, if unspent.
    pub fn get(&self, outpoint: &OutPoint) -> Option<&TxOutput> {
        self.map.get(outpoint).map(|e| &e.output)
    }

    /// Look up the full entry (output + creation height) at `outpoint`.
    pub fn get_entry(&self, outpoint: &OutPoint) -> Option<&UtxoEntry> {
        self.map.get(outpoint)
    }

    /// The creation height of the output at `outpoint`, if unspent.
    pub fn creation_height(&self, outpoint: &OutPoint) -> Option<u64> {
        self.map.get(outpoint).map(|e| e.creation_height)
    }

    /// Whether `outpoint` is currently unspent.
    pub fn contains(&self, outpoint: &OutPoint) -> bool {
        self.map.contains_key(outpoint)
    }

    /// Insert an output with `creation_height = 0` (legacy callers; consensus
    /// paths use [`Self::insert_with_height`]).
    ///
    /// Returns the output previously stored at that outpoint, if any.
    pub fn insert(&mut self, outpoint: OutPoint, output: TxOutput) -> Option<TxOutput> {
        self.insert_with_height(outpoint, output, 0)
    }

    /// Insert an output remembering the block height that created it.
    ///
    /// Returns the output previously stored at that outpoint, if any.
    pub fn insert_with_height(
        &mut self,
        outpoint: OutPoint,
        output: TxOutput,
        creation_height: u64,
    ) -> Option<TxOutput> {
        self.map
            .insert(
                outpoint,
                UtxoEntry {
                    output,
                    creation_height,
                },
            )
            .map(|old| old.output)
    }

    /// Insert a full entry (output + creation height).
    ///
    /// Returns the entry previously stored at that outpoint, if any.
    pub fn insert_entry(&mut self, outpoint: OutPoint, entry: UtxoEntry) -> Option<UtxoEntry> {
        self.map.insert(outpoint, entry)
    }

    /// Remove and return the output at `outpoint`, if present.
    pub fn remove(&mut self, outpoint: &OutPoint) -> Option<TxOutput> {
        self.map.remove(outpoint).map(|e| e.output)
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
        self.map.iter().map(|(op, e)| (op, &e.output))
    }

    /// Iterate over every unspent `(outpoint, entry)` including the creation
    /// height. Order is unspecified.
    pub fn iter_entries(&self) -> impl Iterator<Item = (&OutPoint, &UtxoEntry)> {
        self.map.iter()
    }

    /// Total value of every unspent output. Widened to `u128` so summing many
    /// `u64` outputs cannot overflow.
    pub fn total_value(&self) -> u128 {
        self.map.values().map(|e| u128::from(e.output.value)).sum()
    }

    /// Spendable balance owned by `owner`: the sum of the unspent **native KVNC**
    /// outputs locked to that address. Asset outputs (RFC-002) are excluded —
    /// query them with [`Self::balance_of_asset`].
    pub fn balance(&self, owner: &Address) -> u128 {
        self.map
            .values()
            .map(|e| &e.output)
            .filter(|o| &o.owner == owner && o.asset_id.is_none())
            .map(|o| u128::from(o.value))
            .sum()
    }

    /// Spendable balance owned by `owner` for a specific `asset_id`.
    /// `asset_id = None` means native KVNC.
    pub fn balance_of_asset(&self, owner: &Address, asset_id: Option<AssetId>) -> u128 {
        self.map
            .values()
            .map(|e| &e.output)
            .filter(|o| &o.owner == owner && o.asset_id == asset_id)
            .map(|o| u128::from(o.value))
            .sum()
    }

    /// Serialise the UTXO set for checkpoint persistence. Returns a
    /// self-contained byte encoding: count followed by (outpoint, output) pairs,
    /// sorted by outpoint for deterministic encoding.
    /// v4: includes optional asset_id (32 bytes) after owner.
    /// v5: includes optional stealth extension (65 bytes) after the asset_id.
    /// v6: includes per-entry `creation_height` (8 bytes LE) after the stealth
    ///     flag — the RFC-005 relative-locktime age. Strictly extends v5.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&(self.map.len() as u64).to_le_bytes());
        let mut entries: Vec<_> = self.map.iter().collect();
        entries.sort_by_key(|(op, _)| *op);
        for (op, entry) in entries {
            let output = &entry.output;
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
            // v6: creation height of this output (8 bytes LE).
            buf.extend_from_slice(&entry.creation_height.to_le_bytes());
        }
        buf
    }

    /// Returns the length of the encoded UTXO set (for skipping during decode).
    pub fn encoded_len(&self) -> usize {
        8 + self
            .map
            .values()
            .map(|entry| {
                let output = &entry.output;
                let asset = if output.asset_id.is_some() { 1 + 32 } else { 1 };
                let stealth = if output.stealth.is_some() { 1 + 65 } else { 1 };
                32 + 4 + 8 + 33 + asset + stealth + 8
            })
            .sum::<usize>()
    }

    /// Decode a v6 UTXO set from a checkpoint encoding, advancing `bytes` past
    /// the consumed data so the caller can continue parsing.
    /// v4: reads optional asset_id (32 bytes) after owner.
    /// v5: reads optional stealth extension (65 bytes) after the asset_id.
    /// v6: reads per-entry `creation_height` (8 bytes) after the stealth flag.
    pub fn decode(bytes: &mut &[u8]) -> Result<Self, UtxoDecodeError> {
        Self::decode_impl(bytes, true)
    }

    /// Decode a v5 (or older) checkpoint UTXO set: identical to [`Self::decode`]
    /// except per-entry `creation_height` is absent and therefore defaults to 0.
    ///
    /// This is the safe legacy default — CSV only *delays* spends, never
    /// fast-forwards them, so pre-upgrade outputs that report age 0 are simply
    /// immediately final.
    pub fn decode_v5(bytes: &mut &[u8]) -> Result<Self, UtxoDecodeError> {
        Self::decode_impl(bytes, false)
    }

    fn decode_impl(bytes: &mut &[u8], with_creation_height: bool) -> Result<Self, UtxoDecodeError> {
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
            let creation_height = if with_creation_height {
                reader.read_u64()?
            } else {
                0
            };
            map.insert(
                OutPoint::new(tx, index),
                UtxoEntry {
                    output: TxOutput {
                        value,
                        asset_id,
                        owner,
                        stealth,
                    },
                    creation_height,
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
