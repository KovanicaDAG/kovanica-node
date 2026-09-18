//! Stake registry for **hybrid PoW + VRF-staked validation** (the phone-friendly
//! issuance role).
//!
//! Full nodes may continue producing proof-of-work blocks (see
//! [`kovanica_dag::pow`]); independently, any holder who *bonds* coins can
//! attempt VRF-based block production: each block slot, a bonded producer is
//! eligible iff its VRF output (already committed in the block — see
//! `Dag::set_vrf`) beats a threshold proportional to its bonded stake. This is
//! stake-weighted sortition in the style of **Algorand** (Chen & Micali) and the
//! VRF slot lottery of **Ouroboros Praos** (David et al.): winning is private,
//! verifiable, and grinding-resistant up to the unpredictability of the VRF
//! input (currently the parent tips; an epoch randomness beacon is future work).
//!
//! ## How stake is represented
//!
//! Stake is tracked as a **registry overlay** on the ordinary UTXO set — no new
//! transaction types, only tag conventions (the `tag` bytes are already
//! committed by [`Transaction::sighash`](crate::tx::Transaction::sighash)):
//!
//! * **Bond** — a signed transaction whose tag is
//!   [`BOND_PREFIX`] followed by the 32-byte asset_id (or 32 zero bytes for native KVNC)
//!   and the validator's 32-byte VRF public key, with exactly one output paid
//!   back to the spender itself. That output stays a normal UTXO but becomes
//!   **frozen**: registered in the [`StakeState`] against the (asset_id, VRF key)
//!   pair, and unspendable except by an unbond transaction. Value bonded = the
//!   output's value.
//! * **Unbond** — a signed transaction whose tag is [`UNBOND_PREFIX`],
//!   spending only frozen outpoints owned (and signed) by the same key holder.
//!   Each spent frozen output unlocks after [`UNBOND_MATURITY`] blocks (blue
//!   height), freeing its value back to ordinary circulation.
//!
//! Regular transactions that try to spend a frozen outpoint are rejected with
//! [`StakeError::FrozenInput`]; unbond transactions that touch anything not
//! frozen are rejected with [`StakeError::UnbondNotFrozen`].
//!
//! The registry is deterministic: it is updated inside the ledger's atomic
//! block application ([`crate::ledger`]), so every node derives the identical
//! stake state per block, exactly like the UTXO set.

use core::fmt;

use kovanica_dag::VrfOutput;

use crate::tx::{AssetId, OutPoint};

/// Blocks (blue height) a bond must age before its outpoint may be unbonded.
///
/// Mirrors the light-touch maturity philosophy of the coinbase rule: long
/// enough to make fast bond/unbond cycling around slot boundaries impractical,
/// short enough for testnet ergonomics.
pub const UNBOND_MATURITY: u64 = 100;

/// Tag prefix marking a **bond** transaction, followed by 32-byte asset_id and 32 VRF-pk bytes.
/// For native KVNC, asset_id is 32 zero bytes.
pub const BOND_PREFIX: &[u8] = b"KVB1";
/// Tag prefix marking an **unbond** transaction.
pub const UNBOND_PREFIX: &[u8] = b"KVU1";

/// Native KVNC asset_id (32 zero bytes).
pub const NATIVE_ASSET_ID: AssetId = AssetId::native();

/// Build a bond transaction tag: `KVB1 || asset_id || vrf_pk`.
pub fn bond_tag(asset_id: AssetId, vrf_pk: &[u8; 32]) -> Vec<u8> {
    let mut tag = BOND_PREFIX.to_vec();
    tag.extend_from_slice(asset_id.as_bytes());
    tag.extend_from_slice(vrf_pk);
    tag
}

/// Parse a bond tag into its (asset_id, VRF public-key bytes), or `None` if `tag` is not a
/// well-formed bond tag.
pub fn parse_bond_tag(tag: &[u8]) -> Option<(AssetId, [u8; 32])> {
    if tag.len() != BOND_PREFIX.len() + 32 + 32 || !tag.starts_with(BOND_PREFIX) {
        return None;
    }
    let asset_bytes: [u8; 32] = tag[BOND_PREFIX.len()..BOND_PREFIX.len() + 32]
        .try_into()
        .expect("32 bytes");
    let vrf_pk: [u8; 32] = tag[BOND_PREFIX.len() + 32..]
        .try_into()
        .expect("32 bytes");
    Some((AssetId::from_bytes(asset_bytes), vrf_pk))
}

/// Whether `tag` marks an unbond transaction.
pub fn is_unbond_tag(tag: &[u8]) -> bool {
    tag == UNBOND_PREFIX
}

/// Why a transaction could not be applied against the stake registry.
///
/// Variants deliberately omit the offending transaction id — the ledger wraps
/// them in [`crate::ledger::LedgerError::Stake`], which already carries it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StakeError {
    /// A bond transaction did not have exactly one output paid back to its
    /// input owner (or drew inputs from multiple owners).
    BondShape,
    /// A regular transaction tried to spend a frozen (bonded) outpoint.
    FrozenInput { outpoint: OutPoint },
    /// An unbond transaction spent an outpoint that is not frozen.
    UnbondNotFrozen { outpoint: OutPoint },
    /// An unbond tried to unlock before [`UNBOND_MATURITY`] elapsed.
    UnbondImmature {
        outpoint: OutPoint,
        matures_at_height: u64,
        height: u64,
    },
}

impl fmt::Display for StakeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StakeError::BondShape => {
                f.write_str("bond must pay one output back to its own input owner")
            }
            StakeError::FrozenInput { outpoint } => {
                write!(f, "spends bonded (frozen) outpoint {outpoint:?}")
            }
            StakeError::UnbondNotFrozen { outpoint } => {
                write!(f, "unbond spends non-frozen outpoint {outpoint:?}")
            }
            StakeError::UnbondImmature {
                outpoint,
                matures_at_height,
                height,
            } => write!(
                f,
                "unbond: outpoint {outpoint:?} matures at height {matures_at_height} (now {height})"
            ),
        }
    }
}

impl std::error::Error for StakeError {}

/// A frozen (bonded) outpoint: which asset and VRF key it backs, the height it bonded at,
/// and its value (cached for unlocked accounting).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Freeze {
    /// The asset the bonded value backs.
    pub asset_id: AssetId,
    /// The VRF public key the bonded value backs.
    pub vrf_pk: [u8; 32],
    /// Blue height of the block whose application froze the outpoint.
    pub bond_height: u64,
    /// Bonded value (the output's value).
    pub value: u64,
}

/// The stake registry: frozen bonds plus per-(asset,key) locked totals.
///
/// Deterministic and derived entirely from applying blocks in GHOSTDAG order;
/// kept alongside the [`crate::utxo::UtxoSet`] per block by
/// [`crate::ledger::Ledger`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StakeState {
    frozen: std::collections::HashMap<OutPoint, Freeze>,
    // Key is (asset_id, vrf_pk) - using a tuple as key
    locked: std::collections::HashMap<(AssetId, [u8; 32]), u64>,
}

impl StakeState {
    /// An empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Total value currently bonded to `vrf_pk` for a specific `asset_id`.
    pub fn stake_of(&self, asset_id: AssetId, vrf_pk: &[u8; 32]) -> u64 {
        self.locked.get(&(asset_id, *vrf_pk)).copied().unwrap_or(0)
    }

    /// Total value currently bonded to `vrf_pk` across all assets.
    pub fn stake_of_any_asset(&self, vrf_pk: &[u8; 32]) -> u64 {
        self.locked
            .iter()
            .filter(|((_, pk), _)| pk == vrf_pk)
            .map(|(_, v)| *v)
            .sum()
    }

    /// Sum of all bonded value across every validator for a specific asset.
    pub fn total_stake(&self, asset_id: AssetId) -> u64 {
        self.locked
            .iter()
            .filter(|((aid, _), _)| *aid == asset_id)
            .map(|(_, v)| *v)
            .sum()
    }

    /// Sum of all bonded value across every validator and every asset.
    pub fn total_stake_all_assets(&self) -> u64 {
        self.locked.values().sum()
    }

    /// Number of active bonds.
    pub fn bond_count(&self) -> usize {
        self.frozen.len()
    }

    /// Iterate `(outpoint, freeze)` pairs (checkpoint encoding order).
    pub fn iter_frozen(&self) -> impl Iterator<Item = (&OutPoint, &Freeze)> {
        self.frozen.iter()
    }

    /// Whether `outpoint` is currently frozen (bonded).
    pub fn is_frozen(&self, outpoint: &OutPoint) -> bool {
        self.frozen.contains_key(outpoint)
    }

    /// Register a newly created bond outpoint. Called by the ledger when a
    /// bond-shaped transaction applies: the output `(txid, index)` of `value`
    /// becomes frozen backing `vrf_pk` for `asset_id` from `height`.
    ///
    /// Internal to the ledger rules; exposed for tests and tooling.
    pub fn freeze(&mut self, outpoint: OutPoint, asset_id: AssetId, vrf_pk: [u8; 32], value: u64, height: u64) {
        let entry = self.frozen.entry(outpoint).or_insert(Freeze {
            asset_id,
            vrf_pk,
            bond_height: height,
            value,
        });
        *entry = Freeze {
            asset_id,
            vrf_pk,
            bond_height: height,
            value,
        };
        *self.locked.entry((asset_id, vrf_pk)).or_insert(0) += value;
    }

    /// Read-only counterpart of [`Self::unfreeze_spend`]: verify that
    /// `outpoint` could be released at `height` without mutating anything.
    /// Used by the ledger so that by the time it mutates, no later rule can
    /// fail (atomicity).
    pub fn check_unbond(&self, outpoint: OutPoint, height: u64) -> Result<(), StakeError> {
        let Some(freeze) = self.frozen.get(&outpoint).copied() else {
            return Err(StakeError::UnbondNotFrozen { outpoint });
        };
        let matures_at = freeze.bond_height.saturating_add(UNBOND_MATURITY);
        if height < matures_at {
            return Err(StakeError::UnbondImmature {
                outpoint,
                matures_at_height: matures_at,
                height,
            });
        }
        Ok(())
    }

    /// Release a frozen outpoint being spent by an unbond transaction at
    /// `height`. Returns the unlocked value. Errors if the outpoint is not
    /// frozen or is still within [`UNBOND_MATURITY`].
    pub fn unfreeze_spend(&mut self, outpoint: OutPoint, height: u64) -> Result<u64, StakeError> {
        self.check_unbond(outpoint, height)?;
        let freeze = self.frozen.remove(&outpoint).expect("checked above");
        let key = (freeze.asset_id, freeze.vrf_pk);
        let locked = self.locked.entry(key).or_insert(0);
        *locked = locked.saturating_sub(freeze.value);
        if *locked == 0 {
            self.locked.remove(&key);
        }
        Ok(freeze.value)
    }

    /// The stake-weighted eligibility threshold for a block slot, as a
    /// 64-bit VRF-output cutoff.
    ///
    /// A bonded producer holding `stake` of a `total` bonded supply wins a
    /// slot with probability ≈ `stake/total × rate_num/rate_den`: it is
    /// eligible iff its VRF output's first 8 bytes (see
    /// [`VrfOutput::as_u64`]) are strictly below the returned threshold. The
    /// math is fixed-point in u128: `threshold = (stake << 64) / total ×
    /// num / den`, clamped to `u64::MAX`.
    ///
    /// `rate_num/rate_den` scales how many slots per block the average staker
    /// wins (e.g. `1/1` = one expected win per block per whole-stake; `1/10`
    /// = ten times rarer, useful when PoW blocks dominate issuance).
    pub fn eligibility_threshold(stake: u64, total: u64, rate_num: u64, rate_den: u64) -> u64 {
        if total == 0 || stake == 0 {
            return 0;
        }
        // Fixed-point share in 2^64: fits because stake < 2^64 ⇒ stake << 64 < 2^128.
        let share = ((stake as u128) << 64) / total as u128;
        let scaled = share.saturating_mul(rate_num as u128) / rate_den.max(1) as u128;
        scaled.min(u64::MAX as u128) as u64
    }

    /// Whether `output` beats the [`Self::eligibility_threshold`] — i.e. the
    /// holder of `stake` out of `total` is eligible to produce a VRF-staked
    /// block carrying this output at the given rate.
    pub fn is_eligible(
        output: &VrfOutput,
        stake: u64,
        total: u64,
        rate_num: u64,
        rate_den: u64,
    ) -> bool {
        output.as_u64() < Self::eligibility_threshold(stake, total, rate_num, rate_den)
    }

    /// Canonical encoding (checkpoint format v8): frozen bonds then locked totals,
    /// each length-prefixed, entries sorted for determinism.
    /// Format: [n_bonds][bonds...][n_totals][totals...]
    /// Bond: [txid(32)][index(4)][asset_id(32)][vrf_pk(32)][bond_height(8)][value(8)]
    /// Total: [asset_id(32)][vrf_pk(32)][amount(8)]
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        let mut bonds: Vec<(&OutPoint, &Freeze)> = self.frozen.iter().collect();
        bonds.sort_by_key(|(op, _)| **op);
        buf.extend_from_slice(&(bonds.len() as u64).to_le_bytes());
        for (op, frz) in bonds {
            buf.extend_from_slice(op.tx.as_bytes());
            buf.extend_from_slice(&op.index.to_le_bytes());
            buf.extend_from_slice(frz.asset_id.as_bytes());
            buf.extend_from_slice(&frz.vrf_pk);
            buf.extend_from_slice(&frz.bond_height.to_le_bytes());
            buf.extend_from_slice(&frz.value.to_le_bytes());
        }
        let mut totals: Vec<(AssetId, [u8; 32], u64)> = self
            .locked
            .iter()
            .map(|((aid, pk), v)| (*aid, *pk, *v))
            .collect();
        totals.sort_unstable();
        buf.extend_from_slice(&(totals.len() as u64).to_le_bytes());
        for (aid, pk, amount) in totals {
            buf.extend_from_slice(aid.as_bytes());
            buf.extend_from_slice(&pk);
            buf.extend_from_slice(&amount.to_le_bytes());
        }
        buf
    }

    /// Decode a registry produced by [`Self::encode`]. Deterministic: duplicate
    /// entries are rejected rather than summed.
    pub fn decode(bytes: &[u8]) -> Result<Self, StakeDecodeError> {
        let mut pos = 0usize;
        let need = |pos: usize, n: usize, len: usize| -> Result<(), StakeDecodeError> {
            if len.saturating_sub(pos) < n {
                Err(StakeDecodeError::UnexpectedEof)
            } else {
                Ok(())
            }
        };
        need(pos, 8, bytes.len())?;
        let n_bonds = u64::from_le_bytes(bytes[pos..pos + 8].try_into().unwrap()) as usize;
        pos += 8;
        let mut frozen = std::collections::HashMap::new();
        for _ in 0..n_bonds {
            need(pos, 32 + 4 + 32 + 32 + 8 + 8, bytes.len())?;
            let tx = crate::tx::TxId::from_bytes(bytes[pos..pos + 32].try_into().unwrap());
            pos += 32;
            let index = u32::from_le_bytes(bytes[pos..pos + 4].try_into().unwrap());
            pos += 4;
            let asset_id = AssetId::from_bytes(bytes[pos..pos + 32].try_into().unwrap());
            pos += 32;
            let vrf_pk = bytes[pos..pos + 32].try_into().unwrap();
            pos += 32;
            let bond_height = u64::from_le_bytes(bytes[pos..pos + 8].try_into().unwrap());
            pos += 8;
            let value = u64::from_le_bytes(bytes[pos..pos + 8].try_into().unwrap());
            pos += 8;
            let op = OutPoint::new(tx, index);
            if frozen
                .insert(
                    op,
                    Freeze {
                        asset_id,
                        vrf_pk,
                        bond_height,
                        value,
                    },
                )
                .is_some()
            {
                return Err(StakeDecodeError::DuplicateEntry);
            }
        }
        need(pos, 8, bytes.len())?;
        let n_totals = u64::from_le_bytes(bytes[pos..pos + 8].try_into().unwrap()) as usize;
        pos += 8;
        let mut locked = std::collections::HashMap::new();
        for _ in 0..n_totals {
            need(pos, 32 + 32 + 8, bytes.len())?;
            let asset_id = AssetId::from_bytes(bytes[pos..pos + 32].try_into().unwrap());
            pos += 32;
            let pk = bytes[pos..pos + 32].try_into().unwrap();
            pos += 32;
            let amount = u64::from_le_bytes(bytes[pos..pos + 8].try_into().unwrap());
            pos += 8;
            if locked.insert((asset_id, pk), amount).is_some() {
                return Err(StakeDecodeError::DuplicateEntry);
            }
        }
        if pos != bytes.len() {
            return Err(StakeDecodeError::TrailingBytes);
        }
        Ok(Self { frozen, locked })
    }
}

/// Why a [`StakeState`] could not be decoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StakeDecodeError {
    /// The input ended before a fully-formed value could be read.
    UnexpectedEof,
    /// The same outpoint or key appeared twice.
    DuplicateEntry,
    /// Bytes remained after decoding the declared entries.
    TrailingBytes,
}

impl fmt::Display for StakeDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StakeDecodeError::UnexpectedEof => f.write_str("unexpected end of stake state"),
            StakeDecodeError::DuplicateEntry => f.write_str("duplicate stake entry"),
            StakeDecodeError::TrailingBytes => f.write_str("trailing bytes after stake state"),
        }
    }
}

impl std::error::Error for StakeDecodeError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn pk(seed: u8) -> [u8; 32] {
        let mut b = [seed; 32];
        b[31] = seed;
        b
    }

    fn op(seed: u8) -> OutPoint {
        OutPoint::new(crate::tx::TxId::from_bytes([seed; 32]), 0)
    }

    #[test]
    fn bond_tags_roundtrip() {
        let key = pk(7);
        let native = NATIVE_ASSET_ID;
        assert_eq!(parse_bond_tag(&bond_tag(native, &key)), Some((native, key)));
        assert_eq!(parse_bond_tag(b"KVB1"), None);
        assert_eq!(parse_bond_tag(b"KVX1"), None);
        assert!(is_unbond_tag(b"KVU1"));
        assert!(!is_unbond_tag(&bond_tag(native, &key)));
    }

    #[test]
    fn freeze_and_mature_unbond_accounting() {
        let mut st = StakeState::new();
        let native = NATIVE_ASSET_ID;
        st.freeze(op(1), native, pk(9), 500, 10);
        assert_eq!(st.stake_of(native, &pk(9)), 500);
        assert_eq!(st.total_stake(native), 500);
        assert!(st.is_frozen(&op(1)));

        // Immature until bond_height + UNBOND_MATURITY.
        assert_eq!(
            st.unfreeze_spend(op(1), 10 + UNBOND_MATURITY - 1),
            Err(StakeError::UnbondImmature {
                outpoint: op(1),
                matures_at_height: 10 + UNBOND_MATURITY,
                height: 10 + UNBOND_MATURITY - 1,
            })
        );

        assert_eq!(st.unfreeze_spend(op(1), 10 + UNBOND_MATURITY).unwrap(), 500);
        assert_eq!(st.stake_of(native, &pk(9)), 0);
        assert_eq!(st.total_stake(native), 0);
        assert!(!st.is_frozen(&op(1)));
    }

    #[test]
    fn unfreeze_unknown_outpoint_rejected() {
        let mut st = StakeState::new();
        assert_eq!(
            st.unfreeze_spend(op(2), 999),
            Err(StakeError::UnbondNotFrozen { outpoint: op(2) })
        );
    }

    #[test]
    fn multiple_bonds_accumulate_per_key() {
        let mut st = StakeState::new();
        let native = NATIVE_ASSET_ID;
        st.freeze(op(1), native, pk(3), 100, 0);
        st.freeze(op(2), native, pk(3), 250, 5);
        st.freeze(op(3), native, pk(4), 50, 7);
        assert_eq!(st.stake_of(native, &pk(3)), 350);
        assert_eq!(st.total_stake(native), 400);
        assert_eq!(st.bond_count(), 3);

        st.unfreeze_spend(op(2), 5 + UNBOND_MATURITY).unwrap();
        assert_eq!(st.stake_of(native, &pk(3)), 100);
        assert_eq!(st.total_stake(native), 150);
    }

    #[test]
    fn eligibility_math_matches_probability_model() {
        // Whole stake of the whole supply at rate 1: threshold ≈ 2^64.
        assert_eq!(
            StakeState::eligibility_threshold(1_000, 1_000, 1, 1),
            u64::MAX
        );
        // Half the supply: exactly 2^63 ((500 << 64) / 1000).
        let half = StakeState::eligibility_threshold(500, 1_000, 1, 1);
        assert_eq!(half as u128, 1u128 << 63);
        // Zero stake or zero supply: never eligible.
        assert_eq!(StakeState::eligibility_threshold(0, 1_000, 1, 1), 0);
        assert_eq!(StakeState::eligibility_threshold(100, 0, 1, 1), 0);
        // Rate scaling: 1/10 the rate ⇒ ≈1/10 the threshold.
        let tenth = StakeState::eligibility_threshold(500, 1_000, 1, 10);
        assert!(tenth < half / 5 && tenth > 0);

        // Winner determination is a strict less-than on the top 64 bits.
        let lo = VrfOutput::from_bytes([0u8; 32]);
        let hi = VrfOutput::from_bytes([0xFF; 32]);
        assert!(StakeState::is_eligible(&lo, 500, 1_000, 1, 1));
        assert!(!StakeState::is_eligible(&hi, 500, 1_000, 1, 1));
    }

    #[test]
    fn eligibility_distribution_is_statistically_sound() {
        // With 25% stake at rate 1, over many uniform outputs the fraction
        // eligible must approximate 25%. Guards against off-by-scaling bugs.
        let trials = 20_000;
        let mut wins = 0u32;
        for i in 0..trials {
            let mut bytes = [0u8; 32];
            bytes[..8]
                .copy_from_slice(&((i as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15)).to_be_bytes());
            if StakeState::is_eligible(&VrfOutput::from_bytes(bytes), 25, 100, 1, 1) {
                wins += 1;
            }
        }
        let expected = trials / 4;
        let tolerance = trials / 20; // ±5%
        assert!(
            (wins as i64 - expected as i64).abs() < tolerance as i64,
            "wins {wins} vs expected ~{expected}"
        );
    }

    #[test]
    fn encode_decode_roundtrip() {
        let mut st = StakeState::new();
        let native = NATIVE_ASSET_ID;
        st.freeze(op(1), native, pk(3), 100, 12);
        st.freeze(op(2), native, pk(4), 900, 77);
        let decoded = StakeState::decode(&st.encode()).unwrap();
        assert_eq!(decoded, st);
        // Empty roundtrip.
        assert_eq!(
            StakeState::decode(&StakeState::new().encode()).unwrap(),
            StakeState::new()
        );
    }

    #[test]
    fn decode_rejects_corruption() {
        let mut st = StakeState::new();
        let native = NATIVE_ASSET_ID;
        st.freeze(op(1), native, pk(3), 100, 0);
        let bytes = st.encode();
        assert_eq!(
            StakeState::decode(&bytes[..bytes.len() - 1]),
            Err(StakeDecodeError::UnexpectedEof)
        );
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert_eq!(
            StakeState::decode(&trailing),
            Err(StakeDecodeError::TrailingBytes)
        );
    }
}
