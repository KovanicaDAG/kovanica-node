//! Applying transactions to the UTXO set — the ledger's state-transition rules.
//!
//! Two layers live here:
//!
//! * [`apply_block`] — the strict, atomic state transition for one block's
//!   worth of transactions against a [`UtxoSet`]. It validates every spend
//!   (existence, no double-spend within the block, signature, value
//!   conservation) and the coinbase (issuance ≤ subsidy + fees), then commits.
//!   On *any* error the UTXO set is left untouched.
//! * [`apply_dag`] — the bridge to consensus. It walks
//!   `kovanica_dag::Dag::linearize()` (the deterministic GHOSTDAG total order),
//!   decodes each block's payload into transactions, and applies them in that
//!   order. This is what makes the ledger a *DAG* ledger: parallel blocks are
//!   ordered by GHOSTDAG, and a conflicting spend loses simply because the block
//!   that wins the linearization spent the output first.
//!
//! ## Rules, precisely
//!
//! For a non-coinbase transaction against the current UTXO set:
//! 1. it has at least one input and one output;
//! 2. no outpoint is spent twice within the same transaction;
//! 3. every spent outpoint is currently unspent (exists in the set);
//! 4. every input's signature verifies against the spent output's owner over the
//!    transaction's [`sighash`](crate::tx::Transaction::sighash);
//! 5. every output value is non-zero;
//! 6. outputs do not exceed inputs; the difference is the fee.
//!
//! A block may begin with a single coinbase (input-less) transaction. Regular
//! transactions are applied first, in list order, accumulating fees; then the
//! coinbase's outputs are validated to sum to **at most** `subsidy + fees` and
//! applied last. Because the coinbase is applied last, its outputs are not
//! spendable within the same block (a light-touch maturity rule).
//!
//! ## Deliberate first-slice simplifications
//!
//! * `subsidy` is a single per-block constant passed in, not a halving schedule.
//! * No coinbase maturity beyond "not in the same block"; no fee floor; no tx
//!   size/weight limits.
//! * [`apply_dag`] applies against a fresh state each call (the batch view). The
//!   incremental [`Ledger`] follows the selected tip, so re-orgs above the
//!   finality point are implicit (no revert), and [`Ledger::with_finality`] prunes
//!   the stored state of final blocks and rejects blocks built on final history.
//!   Pruning is of the per-block *state* only; the DAG itself is still append-only.

use std::collections::{HashMap, HashSet};

use kovanica_dag::{
    decode_snapshot, Block, BlockId, BlockPreview, Dag, DagError, KParam, Retarget, SnapshotError,
};

use crate::keys::{verify, Address};
use crate::multisig::{verify_threshold_signatures, MultisigScript};
use crate::stake::{is_unbond_tag, parse_bond_tag, StakeError, StakeState};

/// Default blue-score threshold for RFC-001 multisig activation.
pub const MULTISIG_ACTIVATION_SCORE: u64 = 0;

/// Halving schedule for block subsidy.
///
/// The subsidy starts at `genesis_subsidy` and halves every `halving_era` blocks
/// along the selected-parent chain. Genesis (height 0) gets the full subsidy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HalvingSchedule {
    /// Subsidy at genesis (height 0).
    pub genesis_subsidy: u64,
    /// Number of blocks per halving era.
    pub halving_era: u64,
}

impl HalvingSchedule {
    /// Create a new halving schedule.
    pub const fn new(genesis_subsidy: u64, halving_era: u64) -> Self {
        Self {
            genesis_subsidy,
            halving_era,
        }
    }

    /// Compute the subsidy for a block at `height` (height 0 = genesis).
    pub fn subsidy_at(&self, height: u64) -> u64 {
        let era = height / self.halving_era;
        if era >= 63 {
            0
        } else {
            self.genesis_subsidy >> era
        }
    }
}

/// Default halving era: 1000 blocks.
pub const DEFAULT_HALVING_ERA: u64 = 500_000;

/// The VRF bundle a bonded validator attaches to a staked block: the public key
/// the bonded stake is registered under, the ECVRF proof over the block's
/// parent-tip input, and the resulting output (the sortition draw).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StakedVrf {
    /// The validator's VRF public key (32 bytes, Ed25519/Ristretto255).
    pub vrf_pk: [u8; 32],
    /// ECVRF proof `(Γ, c, s)` over [`Dag::vrf_input(parents)`](kovanica_dag::Dag::vrf_input).
    pub proof: kovanica_dag::VrfProof,
    /// The VRF output — compared against the stake-proportional threshold.
    pub output: kovanica_dag::VrfOutput,
}

/// Hybrid admission policy: blocks enter the DAG either by **proof-of-work**
/// (hash target met, work pinned to the retargeting policy's implication) or by
/// **stake-weighted VRF sortition** ([`StakedVrf`], eligibility proportional to
/// bonded stake). See [`Ledger::set_hybrid`] and [`Ledger::insert_with_vrf`].
#[derive(Clone, Debug)]
pub struct HybridConfig {
    /// Sortition rate numerator: a validator holding the *whole* bonded supply
    /// wins with probability ≈ `rate_num/rate_den` per block. `1/1` = every
    /// slot; `1/10` = ten times rarer (useful when PoW issuance dominates).
    pub rate_num: u64,
    /// Sortition rate denominator (see [`Self::rate_num`]).
    pub rate_den: u64,
    /// The exact `work` value staked-VRF blocks are pinned to. Kept tiny so
    /// staked blocks never dominate blue-work accumulation regardless of how
    /// many a winner emits; chain selection stays PoW-dominated.
    pub stake_nominal_work: u128,
    /// Retargeting policy for PoW-path work pinning. `None` disables the pin
    /// (PoW blocks then only need their hash to meet their claimed target —
    /// useful for tests; production should set this).
    pub retarget: Option<Retarget>,
}

impl Default for HybridConfig {
    /// One expected win per block per whole-stake at nominal work 1, with the
    /// default retargeting policy (1 s target interval, 20-block window).
    fn default() -> Self {
        Self {
            rate_num: 1,
            rate_den: 1,
            stake_nominal_work: 1,
            retarget: Some(Retarget::default()),
        }
    }
}
use crate::tx::{
    decode_block_payload, encode_block_payload, DecodeError, OutPoint, Transaction, TxId,
};
use crate::utxo::UtxoSet;
use crate::validation::TxStructureValidator;

/// Why a transaction or block could not be applied.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LedgerError {
    /// A spent outpoint is not in the UTXO set (missing, already spent, or —
    /// for a same-block coinbase output — not yet mature).
    MissingInput(OutPoint),
    /// The same outpoint is spent twice within one transaction.
    DuplicateInput(OutPoint),
    /// A created output's outpoint already exists (id collision / replay).
    OutputAlreadyExists(OutPoint),
    /// An input's signature did not verify against the spent output's owner.
    BadSignature { tx: TxId, input: usize },
    /// A transaction's outputs exceed its inputs (it would mint value).
    ValueNotConserved { tx: TxId, inputs: u64, outputs: u64 },
    /// A value sum overflowed `u64`.
    ValueOverflow,
    /// A non-coinbase transaction had no inputs, or a coinbase had no outputs to
    /// carry any value — i.e. a structurally empty transaction where the model
    /// requires content.
    EmptyTransaction(TxId),
    /// An output has zero value.
    ZeroValueOutput(TxId),
    /// A coinbase (input-less) transaction appeared somewhere other than first.
    MisplacedCoinbase(TxId),
    /// The coinbase claims more than `subsidy + fees` allows.
    CoinbaseOverspend { claimed: u64, allowed: u64 },
    /// A block's payload could not be decoded into transactions.
    Payload(DecodeError),
    /// The transaction violated a stake-registry rule (bond shape/ownership,
    /// frozen-input spend, or immature/non-frozen unbond).
    Stake { tx: TxId, reason: StakeError },

    // Multisig & Witness Upgrade Variants
    /// Witness stack does not match address requirements (e.g. count != 1 for V0 or != 1+M for V1)
    InvalidWitnessCount {
        tx: TxId,
        input: usize,
        expected: usize,
        actual: usize,
    },
    /// Script hash does not match the P2SH address hash
    ScriptHashMismatch { tx: TxId, input: usize },
    /// Malformed Redeem Script (invalid M/N ratio, length mismatch, or M=0)
    InvalidRedeemScript {
        tx: TxId,
        input: usize,
        reason: &'static str,
    },
    /// Witness item has invalid signature length
    BadSignatureSize {
        tx: TxId,
        input: usize,
        len: usize,
    },
    /// Duplicate signature found in witness stack
    DuplicateSignature { tx: TxId, input: usize },
    /// Multisig transaction submitted prior to consensus activation blue score
    PreActivationMultisig {
        tx: TxId,
        blue_score: u64,
        activation_score: u64,
    },
}

impl core::fmt::Display for LedgerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            LedgerError::MissingInput(op) => write!(f, "missing/spent input {op:?}"),
            LedgerError::DuplicateInput(op) => write!(f, "duplicate input {op:?}"),
            LedgerError::OutputAlreadyExists(op) => write!(f, "output already exists {op:?}"),
            LedgerError::BadSignature { tx, input } => {
                write!(f, "bad signature on input {input} of {tx}")
            }
            LedgerError::ValueNotConserved {
                tx,
                inputs,
                outputs,
            } => write!(
                f,
                "value not conserved in {tx}: in {inputs} < out {outputs}"
            ),
            LedgerError::ValueOverflow => f.write_str("value sum overflowed"),
            LedgerError::EmptyTransaction(tx) => write!(f, "empty transaction {tx}"),
            LedgerError::ZeroValueOutput(tx) => write!(f, "zero-value output in {tx}"),
            LedgerError::MisplacedCoinbase(tx) => write!(f, "misplaced coinbase {tx}"),
            LedgerError::CoinbaseOverspend { claimed, allowed } => {
                write!(
                    f,
                    "coinbase overspend: claimed {claimed} > allowed {allowed}"
                )
            }
            LedgerError::Payload(e) => write!(f, "payload decode: {e}"),
            LedgerError::Stake { tx, reason } => write!(f, "stake rule violated in {tx}: {reason}"),
            LedgerError::InvalidWitnessCount {
                tx,
                input,
                expected,
                actual,
            } => write!(
                f,
                "invalid witness count on input {input} of {tx}: expected {expected}, got {actual}"
            ),
            LedgerError::ScriptHashMismatch { tx, input } => {
                write!(f, "script hash mismatch on input {input} of {tx}")
            }
            LedgerError::InvalidRedeemScript { tx, input, reason } => {
                write!(f, "invalid redeem script on input {input} of {tx}: {reason}")
            }
            LedgerError::BadSignatureSize { tx, input, len } => {
                write!(
                    f,
                    "bad signature size {len} (expected 64) on input {input} of {tx}"
                )
            }
            LedgerError::DuplicateSignature { tx, input } => {
                write!(f, "duplicate signature in witness on input {input} of {tx}")
            }
            LedgerError::PreActivationMultisig {
                tx,
                blue_score,
                activation_score,
            } => write!(
                f,
                "multisig tx {tx} rejected before activation: blue score {blue_score} <= activation {activation_score}"
            ),
        }
    }
}

impl std::error::Error for LedgerError {}

/// What a successfully applied block moved: total fees collected from its
/// transactions and total value minted by its coinbase.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct BlockSummary {
    /// Sum of `inputs − outputs` across the block's non-coinbase transactions.
    pub fees: u64,
    /// Total value claimed by the block's coinbase (0 if none).
    pub minted: u64,
}

/// Apply one block's transactions to `utxo`, atomically.
///
/// `txs` is the block's transaction list; if the first has no inputs it is the
/// coinbase. `subsidy` is the issuance allowance for this block. Returns a
/// [`BlockSummary`] on success. On any error, `utxo` is left exactly as it was.
///
/// Stake rules are not enforced by this function — use
/// [`apply_block_with_stake`] when the block's view has a
/// [`StakeState`] (i.e. always, through [`Ledger`]).
/// Apply one block's transactions to `utxo`, atomically.
///
/// `txs` is the block's transaction list; if the first has no inputs it is the
/// coinbase. `subsidy` is the issuance allowance for this block. Returns a
/// [`BlockSummary`] on success. On any error, `utxo` is left exactly as it was.
///
/// Stake rules are not enforced by this function — use
/// [`apply_block_with_stake`] when the block's view has a
/// [`StakeState`] (i.e. always, through [`Ledger`]).
pub fn apply_block(
    utxo: &mut UtxoSet,
    txs: &[Transaction],
    subsidy: u64,
) -> Result<BlockSummary, LedgerError> {
    apply_block_inner(
        utxo,
        None,
        txs,
        subsidy,
        0,
        u64::MAX,
        MULTISIG_ACTIVATION_SCORE,
    )
}

/// Like [`apply_block`], but additionally enforces the **stake registry**
/// rules against (and updates) `stake`, at blue `height`:
///
/// * regular transactions may not spend frozen (bonded) outpoints;
/// * a bond transaction (`KVB1 || vrf_pk` tag) must pay its single output back
///   to its own input owner — that output becomes frozen backing `vrf_pk`;
/// * an unbond transaction (`KVU1` tag) may only spend matured frozen outpoints
///   owned by its signer, releasing their value from the registry.
///
/// Atomicity covers both structures: on any error neither `utxo` nor `stake`
/// changes.
pub fn apply_block_with_stake(
    utxo: &mut UtxoSet,
    stake: &mut StakeState,
    txs: &[Transaction],
    subsidy: u64,
    height: u64,
) -> Result<BlockSummary, LedgerError> {
    apply_block_inner(
        utxo,
        Some(stake),
        txs,
        subsidy,
        height,
        u64::MAX,
        MULTISIG_ACTIVATION_SCORE,
    )
}

/// Shared implementation behind [`apply_block`] / [`apply_block_with_stake`].
fn apply_block_inner(
    utxo: &mut UtxoSet,
    mut stake: Option<&mut StakeState>,
    txs: &[Transaction],
    subsidy: u64,
    height: u64,
    blue_score: u64,
    activation_score: u64,
) -> Result<BlockSummary, LedgerError> {
    // Stage all changes on a copy; only commit if the whole block validates, so
    // a rejected block has no effect (atomicity).
    let mut staging = utxo.clone();

    let mut coinbase: Option<&Transaction> = None;
    let mut total_fees: u64 = 0;

    for (i, tx) in txs.iter().enumerate() {
        if tx.is_coinbase() {
            if i != 0 {
                return Err(LedgerError::MisplacedCoinbase(tx.id()));
            }
            coinbase = Some(tx);
            continue; // applied last, after fees are known
        }
        let fee = apply_regular(
            &mut staging,
            tx,
            stake.as_deref_mut(),
            height,
            blue_score,
            activation_score,
        )?;
        total_fees = total_fees
            .checked_add(fee)
            .ok_or(LedgerError::ValueOverflow)?;
    }

    let allowed = subsidy
        .checked_add(total_fees)
        .ok_or(LedgerError::ValueOverflow)?;
    let minted = match coinbase {
        Some(cb) => apply_coinbase(&mut staging, cb, allowed, blue_score, activation_score)?,
        None => 0,
    };

    *utxo = staging;
    Ok(BlockSummary {
        fees: total_fees,
        minted,
    })
}

/// Validate and apply a regular (non-coinbase) transaction, returning its fee.
///
/// When `stake` is present the transaction must also satisfy the registry
/// rules (see [`apply_block_with_stake`]); bond/unbond transactions update it.
fn apply_regular(
    staging: &mut UtxoSet,
    tx: &Transaction,
    stake: Option<&mut StakeState>,
    height: u64,
    blue_score: u64,
    activation_score: u64,
) -> Result<u64, LedgerError> {
    if tx.inputs().is_empty() || tx.outputs().is_empty() {
        return Err(LedgerError::EmptyTransaction(tx.id()));
    }

    // Pre-activation gating on outputs:
    if blue_score <= activation_score {
        for output in tx.outputs() {
            if output.owner.is_p2sh() {
                return Err(LedgerError::PreActivationMultisig {
                    tx: tx.id(),
                    blue_score,
                    activation_score,
                });
            }
        }
    }

    // Tag-driven stake roles. A tag that matches neither convention is an
    // ordinary transfer and only faces the frozen-input rule.
    let bond_pk = parse_bond_tag(tx.tag());
    let unbond = is_unbond_tag(tx.tag());

    let sighash = tx.sighash();
    let mut seen: HashSet<OutPoint> = HashSet::with_capacity(tx.inputs().len());
    let mut sum_in: u64 = 0;
    // Owner of the first input's spent output — a bond must pay back to it.
    let mut first_owner: Option<Address> = None;
    // Read-only registry view for every validation-phase rule; the mutating
    // borrow is taken once, after validation, below.
    let stake_view: Option<&StakeState> = stake.as_deref();
    for (i, input) in tx.inputs().iter().enumerate() {
        if !seen.insert(input.outpoint) {
            return Err(LedgerError::DuplicateInput(input.outpoint));
        }
        let prev = staging
            .get(&input.outpoint)
            .ok_or(LedgerError::MissingInput(input.outpoint))?;

        // Pre-activation gating on spends:
        if blue_score <= activation_score && (prev.owner.is_p2sh() || input.witness.len() > 1) {
            return Err(LedgerError::PreActivationMultisig {
                tx: tx.id(),
                blue_score,
                activation_score,
            });
        }

        // Branch on address version:
        if prev.owner.is_p2pk() {
            if input.witness.len() != 1 {
                return Err(LedgerError::InvalidWitnessCount {
                    tx: tx.id(),
                    input: i,
                    expected: 1,
                    actual: input.witness.len(),
                });
            }
            let sig_bytes = &input.witness[0];
            if sig_bytes.len() != 64 {
                return Err(LedgerError::BadSignatureSize {
                    tx: tx.id(),
                    input: i,
                    len: sig_bytes.len(),
                });
            }
            let mut sig_arr = [0u8; 64];
            sig_arr.copy_from_slice(sig_bytes);
            if !verify(&prev.owner, &sighash, &sig_arr) {
                return Err(LedgerError::BadSignature {
                    tx: tx.id(),
                    input: i,
                });
            }
        } else if prev.owner.is_p2sh() {
            if input.witness.is_empty() {
                return Err(LedgerError::InvalidWitnessCount {
                    tx: tx.id(),
                    input: i,
                    expected: 1,
                    actual: 0,
                });
            }
            let redeem_script_bytes = &input.witness[0];
            let script_hash = *blake3::hash(redeem_script_bytes).as_bytes();
            if script_hash != *prev.owner.payload() {
                return Err(LedgerError::ScriptHashMismatch {
                    tx: tx.id(),
                    input: i,
                });
            }
            let script = MultisigScript::parse(redeem_script_bytes).map_err(|reason| {
                LedgerError::InvalidRedeemScript {
                    tx: tx.id(),
                    input: i,
                    reason,
                }
            })?;
            let expected_witness_count = 1 + script.m as usize;
            if input.witness.len() != expected_witness_count {
                return Err(LedgerError::InvalidWitnessCount {
                    tx: tx.id(),
                    input: i,
                    expected: expected_witness_count,
                    actual: input.witness.len(),
                });
            }
            let signatures = &input.witness[1..];
            for sig in signatures {
                if sig.len() != 64 {
                    return Err(LedgerError::BadSignatureSize {
                        tx: tx.id(),
                        input: i,
                        len: sig.len(),
                    });
                }
            }
            verify_threshold_signatures(&script, signatures, &sighash).map_err(|err_str| {
                if err_str == "duplicate signature in witness" {
                    LedgerError::DuplicateSignature {
                        tx: tx.id(),
                        input: i,
                    }
                } else if err_str == "signature must be 64 bytes" {
                    LedgerError::BadSignatureSize {
                        tx: tx.id(),
                        input: i,
                        len: 0,
                    }
                } else {
                    LedgerError::BadSignature {
                        tx: tx.id(),
                        input: i,
                    }
                }
            })?;
        } else {
            return Err(LedgerError::BadSignature {
                tx: tx.id(),
                input: i,
            });
        }

        if let Some(st) = stake_view {
            // Frozen value moves only through an unbond transaction; an unbond
            // may move *only* frozen value (checked after validation below).
            if !unbond && st.is_frozen(&input.outpoint) {
                return Err(LedgerError::Stake {
                    tx: tx.id(),
                    reason: StakeError::FrozenInput {
                        outpoint: input.outpoint,
                    },
                });
            }
        }
        if first_owner.is_none() {
            first_owner = Some(prev.owner);
        } else if bond_pk.is_some() && Some(&prev.owner) != first_owner.as_ref() {
            // A bond must draw all its value from one owner so the bonded
            // output unambiguously backs the signer's own VRF key.
            return Err(LedgerError::Stake {
                tx: tx.id(),
                reason: StakeError::BondShape,
            });
        }
        sum_in = sum_in
            .checked_add(prev.value)
            .ok_or(LedgerError::ValueOverflow)?;
    }

    let mut sum_out: u64 = 0;
    for output in tx.outputs() {
        if output.value == 0 {
            return Err(LedgerError::ZeroValueOutput(tx.id()));
        }
        sum_out = sum_out
            .checked_add(output.value)
            .ok_or(LedgerError::ValueOverflow)?;
    }

    if sum_out > sum_in {
        return Err(LedgerError::ValueNotConserved {
            tx: tx.id(),
            inputs: sum_in,
            outputs: sum_out,
        });
    }

    // Remaining stake-shape rules (still before any mutation, so errors stay
    // atomic).
    if let Some(st) = stake_view {
        if unbond {
            for input in tx.inputs() {
                st.check_unbond(input.outpoint, height)
                    .map_err(|reason| LedgerError::Stake {
                        tx: tx.id(),
                        reason,
                    })?;
            }
        } else if bond_pk.is_some()
            && (tx.outputs().len() != 1 || Some(&tx.outputs()[0].owner) != first_owner.as_ref())
        {
            return Err(LedgerError::Stake {
                tx: tx.id(),
                reason: StakeError::BondShape,
            });
        }
    }

    // Validation passed; mutate the staging set. (Any error above returned
    // before this point, so partial mutation cannot leak — and `apply_block`
    // discards `staging` unless the whole block succeeds.)
    let txid = tx.id();
    for input in tx.inputs() {
        staging.remove(&input.outpoint);
    }
    add_outputs(staging, txid, tx)?;

    // Stake mutations come last and are infallible by now: every rule they
    // enforce was pre-checked against the same inputs above.
    if let Some(st) = stake {
        if unbond {
            for input in tx.inputs() {
                st.unfreeze_spend(input.outpoint, height)
                    .expect("unbond pre-checked above");
            }
        } else if let Some(vrf_pk) = bond_pk {
            let value = tx.outputs()[0].value;
            st.freeze(OutPoint::new(txid, 0), vrf_pk, value, height);
        }
    }

    Ok(sum_in - sum_out)
}

/// Validate and apply a coinbase transaction, returning the value minted.
fn apply_coinbase(
    staging: &mut UtxoSet,
    cb: &Transaction,
    allowed: u64,
    blue_score: u64,
    activation_score: u64,
) -> Result<u64, LedgerError> {
    if blue_score <= activation_score {
        for output in cb.outputs() {
            if output.owner.is_p2sh() {
                return Err(LedgerError::PreActivationMultisig {
                    tx: cb.id(),
                    blue_score,
                    activation_score,
                });
            }
        }
    }
    let mut claimed: u64 = 0;
    for output in cb.outputs() {
        if output.value == 0 {
            return Err(LedgerError::ZeroValueOutput(cb.id()));
        }
        claimed = claimed
            .checked_add(output.value)
            .ok_or(LedgerError::ValueOverflow)?;
    }
    if claimed > allowed {
        return Err(LedgerError::CoinbaseOverspend { claimed, allowed });
    }
    add_outputs(staging, cb.id(), cb)?;
    Ok(claimed)
}

/// Insert every output of `tx` into `staging`, keyed by `(txid, index)`,
/// rejecting any outpoint that already exists.
fn add_outputs(staging: &mut UtxoSet, txid: TxId, tx: &Transaction) -> Result<(), LedgerError> {
    for (i, output) in tx.outputs().iter().enumerate() {
        let outpoint = OutPoint::new(txid, i as u32);
        if staging.insert(outpoint, *output).is_some() {
            return Err(LedgerError::OutputAlreadyExists(outpoint));
        }
    }
    Ok(())
}

/// The result of applying a whole DAG's worth of blocks in linearized order.
#[derive(Clone, Debug, Default)]
pub struct LedgerRun {
    /// The final UTXO set after applying every accepted block.
    pub utxo: UtxoSet,
    /// Blocks that applied cleanly, in linearization order.
    pub accepted: Vec<BlockId>,
    /// Blocks rejected as invalid, each with the reason. A block is rejected —
    /// not fatal — so a conflicting/invalid block never halts the ledger; it
    /// simply has no effect. Determined entirely by the GHOSTDAG order.
    pub rejected: Vec<(BlockId, LedgerError)>,
}

/// Apply an entire DAG: linearize it with GHOSTDAG, then apply each block's
/// transactions in that order against a fresh UTXO set.
///
/// This is a pure function of the DAG and `subsidy`: the linearization is
/// deterministic, and so is every state transition, so two nodes holding the
/// same DAG derive the identical [`LedgerRun`]. Conflicting spends across
/// parallel blocks are resolved by the linearization — the earlier block spends
/// the output; the later one is rejected with [`LedgerError::MissingInput`].
pub fn apply_dag(dag: &Dag, subsidy: u64) -> LedgerRun {
    let mut run = LedgerRun::default();
    for id in dag.linearize() {
        let payload = dag
            .block(&id)
            .expect("linearized id is present in the DAG")
            .payload();
        let blue_score = dag.ghostdag(&id).map_or(0, |g| g.blue_score);
        match decode_block_payload(payload) {
            Ok(txs) => match apply_block_inner(
                &mut run.utxo,
                None,
                &txs,
                subsidy,
                0,
                blue_score,
                MULTISIG_ACTIVATION_SCORE,
            ) {
                Ok(_) => run.accepted.push(id),
                Err(e) => run.rejected.push((id, e)),
            },
            Err(e) => run.rejected.push((id, LedgerError::Payload(e))),
        }
    }
    run
}

/// Why [`Ledger::insert`] could not add a block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LedgerInsertError {
    /// The DAG rejected the block on structure (missing/duplicate parents, or an
    /// installed structural validator).
    Dag(DagError),
    /// The block's transactions are invalid against its view's UTXO state
    /// (a stateful rule: a missing/already-spent input, a bad signature, value
    /// not conserved, or coinbase overspend).
    State(LedgerError),
    /// A raw block's payload did not decode into transactions
    /// ([`Ledger::insert_raw_block`]).
    Payload(DecodeError),
    /// A staked-VRF block was offered but hybrid admission is not enabled.
    HybridDisabled,
    /// The staked block's VRF proof did not verify (bad key, bad proof, or the
    /// recovered output did not match the claimed one).
    BadStakeProof { vrf_pk: [u8; 32] },
    /// The staked producer's sortition draw missed: its output is at or above
    /// the threshold its bonded stake implies.
    NotEligible {
        vrf_pk: [u8; 32],
        threshold: u64,
        output: u64,
        stake: u64,
        total: u64,
    },
    /// A staked block carried a `work` other than
    /// [`HybridConfig::stake_nominal_work`].
    StakeWorkMismatch {
        expected_nominal: u128,
        actual: u128,
    },
    /// This validator already has an accepted staked block on this selected
    /// parent — sibling spam guard ([`Ledger::insert_with_vrf`] rule 4).
    DuplicateStakedBlock {
        vrf_pk: [u8; 32],
        selected_parent: BlockId,
    },
    /// Hybrid PoW-path block whose id does not meet its `work` target.
    PowTargetNotMet { id: BlockId, work: u128 },
    /// Hybrid PoW-path block whose claimed work differs from the retargeting
    /// policy's implication for its past.
    WorkTargetMismatch { work: u128, expected: u128 },
    /// The block's timestamp precedes one of its parents' (hybrid paths carry
    /// the monotonicity rule dag-level difficulty used to enforce).
    TimestampRegression {
        timestamp_ms: u64,
        parent_max_ms: u64,
    },
    /// The block builds on final history — its selected parent's blue score is
    /// below the finality point, so it is rejected (a deep re-org).
    Finality {
        parent_score: u64,
        finality_score: u64,
    },
}

impl From<DagError> for LedgerInsertError {
    fn from(e: DagError) -> Self {
        LedgerInsertError::Dag(e)
    }
}

impl From<LedgerError> for LedgerInsertError {
    fn from(e: LedgerError) -> Self {
        LedgerInsertError::State(e)
    }
}

impl core::fmt::Display for LedgerInsertError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            LedgerInsertError::Dag(e) => write!(f, "dag rejected block: {e}"),
            LedgerInsertError::State(e) => write!(f, "invalid block state: {e}"),
            LedgerInsertError::Payload(e) => write!(f, "block payload undecodable: {e}"),
            LedgerInsertError::HybridDisabled => {
                f.write_str("staked-VRF insert requires hybrid mode (Ledger::set_hybrid)")
            }
            LedgerInsertError::BadStakeProof { vrf_pk } => write!(
                f,
                "staked block VRF proof invalid for key {}",
                hex::encode(vrf_pk)
            ),
            LedgerInsertError::NotEligible {
                threshold,
                output,
                stake,
                total,
                vrf_pk,
            } => write!(
                f,
                "staked producer {} not eligible: output {output} ≥ threshold {threshold} (stake {stake} / {total})",
                hex::encode(vrf_pk)
            ),
            LedgerInsertError::StakeWorkMismatch {
                expected_nominal,
                actual,
            } => write!(
                f,
                "staked block work {actual} ≠ nominal {expected_nominal}"
            ),
            LedgerInsertError::DuplicateStakedBlock {
                vrf_pk,
                selected_parent,
            } => write!(
                f,
                "validator {} already staked a block on selected parent {selected_parent}",
                hex::encode(vrf_pk)
            ),
            LedgerInsertError::PowTargetNotMet { id, work } => {
                write!(f, "block {id} does not meet its PoW target (work {work})")
            }
            LedgerInsertError::WorkTargetMismatch { work, expected } => {
                write!(f, "PoW block work {work} ≠ retarget target {expected}")
            }
            LedgerInsertError::TimestampRegression {
                timestamp_ms,
                parent_max_ms,
            } => write!(
                f,
                "block timestamp {timestamp_ms} precedes a parent's ({parent_max_ms})"
            ),
            LedgerInsertError::Finality {
                parent_score,
                finality_score,
            } => write!(
                f,
                "finality violation: selected parent blue score {parent_score} < finality {finality_score}"
            ),
        }
    }
}

impl std::error::Error for LedgerInsertError {}

/// A DAG together with the **per-block UTXO state** each block induces.
///
/// [`apply_dag`] is the batch view: it (re)linearizes a finished DAG and folds
/// every transaction from scratch. A `Ledger` is the *incremental* view. It owns
/// a [`Dag`] and, for every block `B`, stores the UTXO set of `B`'s own view —
/// the state after applying, in the recursive GHOSTDAG order, every transaction
/// in `past(B) ∪ {B}`. That state is built cheaply from `B`'s selected parent:
///
/// ```text
/// state(B) = apply( state(selected_parent(B)),
///                   mergeset(B) blocks' transactions (in order),
///                   B's own transactions )
/// ```
///
/// Because `B`'s transactions are checked against this pre-state *before* the
/// block is committed (via [`Dag::preview`]), a block that is invalid in its own
/// view — it double-spends an ancestor's output, carries a bad signature, mints
/// value, or overspends its coinbase — is rejected at insert and never enters
/// the DAG. (Two *parallel* blocks that spend the same output are each valid in
/// their own view and both admitted; their conflict is resolved only in the view
/// of a block that merges them, exactly as GHOSTDAG intends.)
///
/// The structural [`TxStructureValidator`] is also installed on the underlying
/// DAG, so malformed blocks are rejected even if the DAG is used directly.
///
/// State is kept per block in full (mirroring the crate's other O(n²) first-slice
/// simplifications); storing compact per-block diffs is a later optimisation.
///
/// ## Finality and pruning
///
/// A `Ledger` built with [`Ledger::with_finality`] treats blocks more than
/// `finality_depth` blue score below the selected tip as **final**: no new block
/// may build on them (their selected parent being final is a
/// [`LedgerInsertError::Finality`]), so their stored per-block state is no longer
/// needed and is **pruned**, bounding memory. This also makes the selected chain
/// stable below the finality point — a deep re-org is rejected rather than
/// applied. Above the finality point, re-orgs are implicit: [`Ledger::ledger_state`]
/// always follows the current selected tip, so a heavier branch takes over with no
/// explicit revert. [`Ledger::new`] uses an unbounded depth — it never prunes and
/// never rejects on finality.
///
/// ## Payload pruning
///
/// Independently of the ledger's finality pruning, the underlying [`Dag`]
/// supports **payload pruning** via [`Dag::set_payload_pruning_depth`]. This
/// evicts the opaque transaction payloads of blocks whose blue score is more than
/// `payload_pruning_depth` below the selected tip. The payload pruning depth is
/// typically set larger than the finality depth so that a node can serve block
/// bodies for blocks that are final (and thus immutable) but no longer needed for
/// validation. See [`kovanica_dag::Dag`] for details.
pub struct Ledger {
    dag: Dag,
    schedule: HalvingSchedule,
    genesis: BlockId,
    /// Blocks this far in blue score below the selected tip are final; their
    /// state is pruned and they cannot be built on. `u64::MAX` = never.
    finality_depth: u64,
    /// Payload pruning depth for the underlying DAG: blocks this far in blue
    /// score below the selected tip have their payloads evicted. `u64::MAX` = never.
    payload_pruning_depth: u64,
    /// Per-block view UTXO state: `states[&b]` is the ledger state in `b`'s view.
    /// Final blocks (below the finality point) are pruned from this map.
    states: HashMap<BlockId, UtxoSet>,
    /// Per-block stake registry, mirroring [`Self::states`]: `stakes[&b]` is the
    /// bonded-stake state in `b`'s own view.
    stakes: HashMap<BlockId, StakeState>,
    /// Hybrid PoW/staked-VRF admission policy; `None` = legacy behaviour (VRF
    /// fields on incoming blocks are ignored/stripped).
    hybrid: Option<HybridConfig>,
    /// Accepted staked blocks by `(vrf_pk, selected_parent)` — the sibling-spam
    /// guard's memory. Entries whose selected parent falls below finality are
    /// pruned alongside per-block state.
    staked_seen: HashMap<([u8; 32], BlockId), BlockId>,
    /// Block heights: `heights[&b]` is the height of block `b` in the selected chain.
    heights: HashMap<BlockId, u64>,
    /// Blue score activation threshold for Version 0x01 multisig transactions.
    multisig_activation_score: u64,
}

impl Ledger {
    /// Create a ledger whose genesis block carries `genesis_txs` (typically a
    /// single coinbase minting the initial supply). `k` is the GHOSTDAG
    /// parameter and `schedule` the halving schedule for per-block issuance.
    ///
    /// Fails if `genesis_txs` are not a valid block on an empty UTXO set.
    pub fn new(
        k: KParam,
        schedule: HalvingSchedule,
        genesis_txs: &[Transaction],
    ) -> Result<Self, LedgerError> {
        let genesis_subsidy = schedule.subsidy_at(0);
        let mut state = UtxoSet::new();
        apply_block(&mut state, genesis_txs, genesis_subsidy)?;

        let genesis = Block::genesis(1, 0, 0, encode_block_payload(genesis_txs));
        let genesis_id = genesis.id();
        let mut dag = Dag::with_validator(k, genesis, Box::new(TxStructureValidator));
        dag.set_payload_pruning_depth(u64::MAX);

        let mut states = HashMap::new();
        states.insert(genesis_id, state);
        let mut stakes = HashMap::new();
        stakes.insert(genesis_id, StakeState::new());
        let mut heights = HashMap::new();
        heights.insert(genesis_id, 0);
        Ok(Self {
            dag,
            schedule,
            genesis: genesis_id,
            finality_depth: u64::MAX,
            payload_pruning_depth: u64::MAX,
            states,
            stakes,
            hybrid: None,
            staked_seen: HashMap::new(),
            heights,
            multisig_activation_score: MULTISIG_ACTIVATION_SCORE,
        })
    }

    /// Set the blue-score activation threshold for Version 0x01 multisig transactions.
    pub fn set_multisig_activation_score(&mut self, score: u64) {
        self.multisig_activation_score = score;
    }

    /// The blue-score activation threshold for Version 0x01 multisig transactions.
    pub fn multisig_activation_score(&self) -> u64 {
        self.multisig_activation_score
    }

    /// Like [`Ledger::new`], but with a finite finality depth: blocks more than
    /// `finality_depth` blue score below the selected tip become final — they may
    /// not be built on, and their per-block state is pruned. See the type docs.
    pub fn with_finality(
        k: KParam,
        schedule: HalvingSchedule,
        genesis_txs: &[Transaction],
        finality_depth: u64,
    ) -> Result<Self, LedgerError> {
        let mut ledger = Self::new(k, schedule, genesis_txs)?;
        ledger.finality_depth = finality_depth;
        Ok(ledger)
    }

    /// Like [`Ledger::new`], but with a finite payload pruning depth for the
    /// underlying DAG: blocks more than `payload_pruning_depth` blue score below
    /// the selected tip have their payloads evicted. This is independent of the
    /// ledger's finality pruning (which prunes per-block UTXO state and rejects
    /// blocks built on final history). Typically `payload_pruning_depth >=
    /// finality_depth` so that final blocks' bodies can still be served for sync.
    pub fn with_payload_pruning(
        k: KParam,
        schedule: HalvingSchedule,
        genesis_txs: &[Transaction],
        payload_pruning_depth: u64,
    ) -> Result<Self, LedgerError> {
        let mut ledger = Self::new(k, schedule, genesis_txs)?;
        ledger.payload_pruning_depth = payload_pruning_depth;
        ledger.dag.set_payload_pruning_depth(payload_pruning_depth);
        Ok(ledger)
    }

    /// Like [`Ledger::with_finality`], but with both finality depth and payload
    /// pruning depth specified.
    pub fn with_finality_and_payload_pruning(
        k: KParam,
        schedule: HalvingSchedule,
        genesis_txs: &[Transaction],
        finality_depth: u64,
        payload_pruning_depth: u64,
    ) -> Result<Self, LedgerError> {
        let mut ledger = Self::new(k, schedule, genesis_txs)?;
        ledger.finality_depth = finality_depth;
        ledger.payload_pruning_depth = payload_pruning_depth;
        ledger.dag.set_payload_pruning_depth(payload_pruning_depth);
        Ok(ledger)
    }

    /// Borrow the underlying DAG (for consensus queries: tips, ghostdag,
    /// `linearize`, `selected_chain`, …).
    pub fn dag(&self) -> &Dag {
        &self.dag
    }

    /// Enable consensus-enforced difficulty on the underlying DAG with policy
    /// `retarget`: every subsequent [`Ledger::insert`] additionally requires the
    /// block's `work` to equal [`Dag::next_work_target`] and its timestamp not to
    /// precede any parent's. See [`Dag::set_difficulty`].
    pub fn set_difficulty(&mut self, retarget: Retarget) {
        self.dag.set_difficulty(retarget);
    }

    /// Enable (or disable) consensus-enforced proof-of-work on the underlying
    /// DAG: every subsequent [`Ledger::insert`] additionally requires the block's
    /// id to meet its `work` target — i.e. the block must have been mined (its
    /// `nonce` chosen so the hash is small enough). See
    /// [`Dag::set_proof_of_work`] and [`kovanica_dag::pow`]. Off by default.
    pub fn set_proof_of_work(&mut self, enabled: bool) {
        self.dag.set_proof_of_work(enabled);
    }

    /// The finality depth (blue score below the selected tip). `u64::MAX` means
    /// finality/pruning is disabled.
    pub fn finality_depth(&self) -> u64 {
        self.finality_depth
    }

    /// The blue-score threshold below which blocks are final: blocks with a blue
    /// score `< finality_score()` are pruned and may not be built on. `0` when
    /// finality is disabled or the DAG is not yet `finality_depth` deep.
    pub fn finality_score(&self) -> u64 {
        if self.finality_depth == u64::MAX {
            return 0;
        }
        let tip = self.dag.selected_tip();
        let max = self.dag.ghostdag(&tip).map_or(0, |g| g.blue_score);
        max.saturating_sub(self.finality_depth)
    }

    /// The payload pruning depth for the underlying DAG. `u64::MAX` means pruning
    /// is disabled.
    pub fn payload_pruning_depth(&self) -> u64 {
        self.payload_pruning_depth
    }

    /// The selected tip's blue score — the chain height a block building on the
    /// current tips will approximately reach (the ledger assigns each new block
    /// its selected parent's height + 1).
    pub fn tip_blue_score(&self) -> u64 {
        let tip = self.dag.selected_tip();
        self.dag.ghostdag(&tip).map_or(0, |g| g.blue_score)
    }

    /// The blue-score threshold below which blocks' payloads are pruned in the
    /// underlying DAG. Returns `0` when pruning is disabled or the DAG is not yet
    /// deep enough. See [`Dag::payload_pruning_score`].
    pub fn payload_pruning_score(&self) -> u64 {
        self.dag.payload_pruning_score()
    }

    /// Set the payload pruning depth on the underlying DAG.
    pub fn set_payload_pruning_depth(&mut self, depth: u64) {
        self.payload_pruning_depth = depth;
        self.dag.set_payload_pruning_depth(depth);
    }

    /// The genesis block id.
    pub fn genesis(&self) -> BlockId {
        self.genesis
    }

    /// The subsidy for the next block (based on the selected tip's height).
    pub fn subsidy(&self) -> u64 {
        let tip = self.dag.selected_tip();
        let height = self.heights.get(&tip).copied().unwrap_or(0);
        self.schedule.subsidy_at(height + 1)
    }

    /// The halving schedule.
    pub fn schedule(&self) -> HalvingSchedule {
        self.schedule
    }

    /// The UTXO state in `block`'s own view, if `block` is present.
    pub fn state(&self, block: &BlockId) -> Option<&UtxoSet> {
        self.states.get(block)
    }

    /// The stake registry in `block`'s own view, if `block` is present.
    pub fn stake_state(&self, block: &BlockId) -> Option<&StakeState> {
        self.stakes.get(block)
    }

    /// Enable hybrid PoW / staked-VRF admission with policy `config`.
    ///
    /// This takes over block-admission from the underlying DAG's own checks:
    /// dag-level proof-of-work, difficulty pinning, and VRF threshold are
    /// cleared, and both paths are enforced here instead (see
    /// [`HybridConfig`] and [`Ledger::insert_with_vrf`]). Restoring a
    /// snapshot/checkpoint that contains staked blocks requires hybrid to be
    /// re-enabled before replay.
    pub fn set_hybrid(&mut self, config: HybridConfig) {
        // The ledger owns admission now.
        self.dag.set_proof_of_work(false);
        self.dag.clear_difficulty();
        self.dag.disable_vrf();
        self.hybrid = Some(config);
    }

    /// Whether hybrid PoW / staked-VRF admission is enabled.
    pub fn hybrid_enabled(&self) -> bool {
        self.hybrid.is_some()
    }

    /// The active hybrid policy, if any ([`Ledger::set_hybrid`]).
    pub fn hybrid_config(&self) -> Option<HybridConfig> {
        self.hybrid.clone()
    }

    /// The work target the hybrid retargeting policy implies for a block with
    /// these parents — what a miner should mine at (`None` when hybrid is off,
    /// or no retargeting policy is configured).
    pub fn expected_work(&self, parents: &[BlockId]) -> Option<u128> {
        let cfg = self.hybrid.as_ref()?;
        let rt = cfg.retarget.as_ref()?;
        Some(self.dag.work_target_with(parents, rt))
    }

    /// Insert a block referencing `parents`, carrying `work`, `timestamp_ms`,
    /// `nonce`, and `txs`.
    ///
    /// Validates `txs` against the block's view UTXO state and, on success, adds
    /// the block to the DAG and stores its per-block state. On any error the
    /// ledger and DAG are left unchanged and the block is not added. When
    /// proof-of-work is enforced (see [`Ledger::set_proof_of_work`]), `nonce`
    /// must have been chosen so the block's id meets its `work` target — i.e. the
    /// caller mined the block (see [`kovanica_dag::pow::mine`]); with PoW off,
    /// `nonce` is unconstrained (pass `0`).
    ///
    /// When hybrid admission is enabled ([`Ledger::set_hybrid`]), this inserts a
    /// **PoW-path** block: its id must meet the hash target for `work`, and — if
    /// the hybrid config carries a [`Retarget`] policy — `work` must equal the
    /// target that policy implies. Staked-VRF blocks go through
    /// [`Ledger::insert_with_vrf`] instead.
    pub fn insert(
        &mut self,
        parents: Vec<BlockId>,
        work: u128,
        timestamp_ms: u64,
        nonce: u64,
        txs: &[Transaction],
    ) -> Result<BlockId, LedgerInsertError> {
        let block = Block::new(
            parents,
            work,
            timestamp_ms,
            nonce,
            encode_block_payload(txs),
        );
        self.apply_new_block(block, txs, None)
    }

    /// Insert a **staked-VRF block**: a block admitted by stake-weighted VRF
    /// sortition instead of proof-of-work (hybrid mode only).
    ///
    /// The block's `work` is pinned to
    /// [`HybridConfig::stake_nominal_work`] — deliberately tiny so staked
    /// blocks never out-compete mined blocks in blue-work accumulation, no
    /// matter how a validator grinds parent combinations. Admission requires:
    ///
    /// 1. a valid ECVRF proof over [`Dag::vrf_input(parents)`](kovanica_dag::Dag::vrf_input);
    /// 2. eligibility — `output < threshold(stake_of(pk), total_stake, rate)`
    ///    evaluated against the **selected parent's** stake view (pre-state, so
    ///    bonds inside the block itself do not count for it);
    /// 3. `timestamp_ms` not below any parent's;
    /// 4. at most one accepted staked block per `(vrf_pk, selected_parent)` —
    ///    without this an eligible winner could emit unlimited sibling variants.
    ///
    /// Requires [`Ledger::set_hybrid`] first; otherwise returns
    /// [`LedgerInsertError::HybridDisabled`].
    pub fn insert_with_vrf(
        &mut self,
        parents: Vec<BlockId>,
        timestamp_ms: u64,
        staked_vrf: StakedVrf,
        txs: &[Transaction],
    ) -> Result<BlockId, LedgerInsertError> {
        let work = self
            .hybrid
            .as_ref()
            .ok_or(LedgerInsertError::HybridDisabled)?
            .stake_nominal_work;
        let block = Block::new_with_vrf(
            parents,
            work,
            timestamp_ms,
            0,
            kovanica_dag::VrfPublicKey::from_bytes(&staked_vrf.vrf_pk).map_err(|_| {
                LedgerInsertError::BadStakeProof {
                    vrf_pk: staked_vrf.vrf_pk,
                }
            })?,
            staked_vrf.proof.clone(),
            staked_vrf.output,
            encode_block_payload(txs),
        );
        self.apply_new_block(block, txs, Some(staked_vrf))
    }

    /// Insert an already-assembled `block` whose payload decodes to `txs`.
    ///
    /// This is the identity-preserving path: the block's id (including any VRF
    /// fields) is taken as given, so peers and snapshot/checkpoint replays can
    /// re-admit exactly the block they received. All admission rules — stateful
    /// transaction validation, hybrid PoW/stake checks — still run; only the
    /// re-encoding of parents/work/timestamp into a fresh template is skipped.
    pub fn insert_prepared_block(
        &mut self,
        block: Block,
        txs: &[Transaction],
    ) -> Result<BlockId, LedgerInsertError> {
        let staked = block
            .vrf_public_key()
            .zip(block.vrf_proof())
            .zip(block.vrf_output())
            .map(|((pk, proof), output)| StakedVrf {
                vrf_pk: *pk.as_bytes(),
                proof: proof.clone(),
                output: *output,
            });
        self.apply_new_block(block, txs, staked)
    }

    /// Like [`Ledger::insert_prepared_block`], but the transactions are decoded
    /// from the block's own payload. Used by snapshot/checkpoint replays.
    pub fn insert_raw_block(&mut self, block: Block) -> Result<BlockId, LedgerInsertError> {
        let txs = decode_block_payload(block.payload()).map_err(LedgerInsertError::Payload)?;
        self.insert_prepared_block(block, &txs)
    }

    /// Shared admission pipeline behind every public insert entry point.
    fn apply_new_block(
        &mut self,
        mut block: Block,
        txs: &[Transaction],
        mut staked: Option<StakedVrf>,
    ) -> Result<BlockId, LedgerInsertError> {
        // Legacy shim: before hybrid mode existed, a prepared/raw block's VRF
        // fields were silently dropped by template re-encoding (`insert` built a
        // fresh `Block::new`). Preserve that behaviour for replays of old
        // snapshots rather than rejecting history that was legal then.
        if staked.is_some() && self.hybrid.is_none() {
            staked = None;
            block = Block::new(
                block.parents().to_vec(),
                block.work(),
                block.timestamp_ms(),
                block.nonce(),
                block.payload().to_vec(),
            );
        }

        // Build the block's view pre-state: its selected parent's state with the
        // mergeset blocks' transactions applied in order. Previewing gets the
        // selected parent and mergeset without mutating the DAG.
        let preview = self.dag.preview(&block)?;

        // Finality: a block may not build on final history. Its selected parent
        // being final means its state has been pruned, so this check also
        // guarantees the state lookup below succeeds.
        let parent_score = self
            .dag
            .ghostdag(&preview.selected_parent)
            .map_or(0, |g| g.blue_score);
        let finality_score = self.finality_score();
        if parent_score < finality_score {
            return Err(LedgerInsertError::Finality {
                parent_score,
                finality_score,
            });
        }

        // Hybrid admission (before any state mutation, so errors stay atomic).
        // Eligibility reads the SELECTED PARENT's stake view — a bond carried in
        // this very block must not vote for its own producer.
        let sp = preview.selected_parent;
        if let Some(cfg) = self.hybrid.as_ref() {
            let pre_stake = self.stakes.get(&sp).cloned().unwrap_or_default();
            self.hybrid_admit(&block, &preview, staked.as_ref(), cfg, &pre_stake)?;
        }

        let parent_height = self.heights.get(&sp).copied().unwrap_or(0);
        let new_height = parent_height + 1;
        let block_blue_score = parent_score + 1;

        let mut state = self
            .states
            .get(&sp)
            .expect("non-final selected parent always has a stored state")
            .clone();
        let mut stake = self.stakes.get(&sp).cloned().unwrap_or_default();
        for merged in &preview.mergeset {
            let merged_height = self.heights.get(merged).copied().unwrap_or(0);
            let merged_blue_score = self.dag.ghostdag(merged).map_or(0, |g| g.blue_score);
            let payload = self
                .dag
                .block(merged)
                .expect("mergeset block is in the DAG")
                .payload();
            if let Ok(merged_txs) = decode_block_payload(payload) {
                // A merged block that conflicts in this view simply does not
                // apply — its transactions were valid in their own view, not
                // necessarily here. This mirrors apply_dag's per-block reject.
                let _ = apply_block_inner(
                    &mut state,
                    Some(&mut stake),
                    &merged_txs,
                    self.schedule.subsidy_at(merged_height),
                    merged_height,
                    merged_blue_score,
                    self.multisig_activation_score,
                );
            }
        }

        // Stateful validation: the block's own transactions must be valid against
        // its view pre-state. Failure rejects the block before it enters the DAG.
        apply_block_inner(
            &mut state,
            Some(&mut stake),
            txs,
            self.schedule.subsidy_at(new_height),
            new_height,
            block_blue_score,
            self.multisig_activation_score,
        )?;

        // Commit: add to the DAG (structural checks run here) and store the state.
        let id = self.dag.insert(block)?;
        if let Some(s) = staked {
            self.staked_seen.insert((s.vrf_pk, sp), id);
        }
        self.states.insert(id, state);
        self.stakes.insert(id, stake);
        self.heights.insert(id, new_height);
        self.prune();
        Ok(id)
    }

    /// Hybrid admission rules shared by both paths (PoW and staked-VRF). Runs
    /// with `&self` only — pure read checks before anything mutates.
    fn hybrid_admit(
        &self,
        block: &Block,
        preview: &BlockPreview,
        staked: Option<&StakedVrf>,
        cfg: &HybridConfig,
        pre_stake: &StakeState,
    ) -> Result<(), LedgerInsertError> {
        // Timestamp monotonicity (the rule dag-level difficulty used to carry):
        // a block may not precede any of its parents.
        let max_parent_ts = block
            .parents()
            .iter()
            .filter_map(|p| self.dag.block(p))
            .map(|b| b.timestamp_ms())
            .max()
            .unwrap_or(0);
        if block.timestamp_ms() < max_parent_ts {
            return Err(LedgerInsertError::TimestampRegression {
                timestamp_ms: block.timestamp_ms(),
                parent_max_ms: max_parent_ts,
            });
        }

        match staked {
            Some(s) => {
                // 1+2. Verifiable sortition: proof must verify and beat the
                // stake-proportional threshold under the pre-state registry.
                let key = kovanica_dag::VrfPublicKey::from_bytes(&s.vrf_pk)
                    .map_err(|_| LedgerInsertError::BadStakeProof { vrf_pk: s.vrf_pk })?;
                let input = Dag::vrf_input(block.parents());
                let verified = kovanica_dag::vrf::vrf_verify(&key, &input, &s.proof)
                    .ok()
                    .filter(|out| *out == s.output);
                let Some(_) = verified else {
                    return Err(LedgerInsertError::BadStakeProof { vrf_pk: s.vrf_pk });
                };
                let total = pre_stake.total_stake();
                let mine = pre_stake.stake_of(&s.vrf_pk);
                let threshold =
                    StakeState::eligibility_threshold(mine, total, cfg.rate_num, cfg.rate_den);
                if s.output.as_u64() >= threshold {
                    return Err(LedgerInsertError::NotEligible {
                        vrf_pk: s.vrf_pk,
                        threshold,
                        output: s.output.as_u64(),
                        stake: mine,
                        total,
                    });
                }
                // Defensive pin (insert_with_vrf already enforces this).
                if block.work() != cfg.stake_nominal_work {
                    return Err(LedgerInsertError::StakeWorkMismatch {
                        expected_nominal: cfg.stake_nominal_work,
                        actual: block.work(),
                    });
                }
                // 4. One staked block per (key, selected parent): kills sibling
                // spam while leaving honest parallel production untouched.
                if self
                    .staked_seen
                    .contains_key(&(s.vrf_pk, preview.selected_parent))
                {
                    return Err(LedgerInsertError::DuplicateStakedBlock {
                        vrf_pk: s.vrf_pk,
                        selected_parent: preview.selected_parent,
                    });
                }
            }
            None => {
                // PoW path: the hash target must actually be met...
                if !kovanica_dag::pow::meets_target(&block.id(), block.work()) {
                    return Err(LedgerInsertError::PowTargetNotMet {
                        id: block.id(),
                        work: block.work(),
                    });
                }
                // ...and, when a retargeting policy is configured, the claimed
                // work must be exactly what that policy implies — no cheaply
                // inflated blue weight.
                if let Some(rt) = &cfg.retarget {
                    let expected = self.dag.work_target_with(block.parents(), rt);
                    if block.work() != expected {
                        return Err(LedgerInsertError::WorkTargetMismatch {
                            work: block.work(),
                            expected,
                        });
                    }
                }
            }
        }
        Ok(())
    }

    /// Drop the stored state of every block that is now final (below
    /// [`Ledger::finality_score`]). Finality only rises, so a pruned block stays
    /// prunable; and only final blocks are dropped, which are never a future
    /// block's selected parent (that is a finality violation) nor needed by
    /// [`Ledger::ledger_state`] (which starts from the selected tip).
    fn prune(&mut self) {
        let threshold = self.finality_score();
        if threshold == 0 {
            return;
        }
        let stale: Vec<BlockId> = self
            .states
            .keys()
            .copied()
            .filter(|id| {
                self.dag
                    .ghostdag(id)
                    .is_some_and(|g| g.blue_score < threshold)
            })
            .collect();
        for id in stale {
            self.states.remove(&id);
            self.stakes.remove(&id);
            self.heights.remove(&id);
        }
        // The sibling-spam guard only needs to remember staked blocks whose
        // selected parent is still non-final; older windows are free again.
        let stale_seen: Vec<([u8; 32], BlockId)> = self
            .staked_seen
            .keys()
            .copied()
            .filter(|(_, sp)| {
                self.dag
                    .ghostdag(sp)
                    .is_some_and(|g| g.blue_score < threshold)
            })
            .collect();
        for key in stale_seen {
            self.staked_seen.remove(&key);
        }
    }

    /// The full current ledger state: every block applied in linearized order.
    ///
    /// Built incrementally as the selected tip's view state plus the side blocks
    /// under the other tips (the linearization's tail).
    pub fn ledger_state(&self) -> UtxoSet {
        let order = self.dag.linearize();
        let selected_tip = self.dag.selected_tip();
        let tip_pos = order
            .iter()
            .position(|b| *b == selected_tip)
            .expect("selected tip is in the order");

        let mut state = self
            .states
            .get(&selected_tip)
            .expect("selected tip has a stored state")
            .clone();
        for block in &order[tip_pos + 1..] {
            let height = self.heights.get(block).copied().unwrap_or(0);
            let payload = self
                .dag
                .block(block)
                .expect("block is in the DAG")
                .payload();
            if let Ok(txs) = decode_block_payload(payload) {
                let _ = apply_block(&mut state, &txs, self.schedule.subsidy_at(height));
            }
        }
        state
    }

    /// Serialise the ledger to a self-contained snapshot: the halving schedule plus the
    /// underlying DAG's replay log (see [`Dag::write_snapshot`]). Per-block UTXO
    /// state is *not* stored — it is recomputed on load by replaying blocks
    /// through [`Ledger::insert`], so nothing derived is trusted from disk.
    ///
    /// The snapshot also stores the runtime `finality_depth` and `payload_pruning_depth`
    /// so they are restored automatically.
    pub fn write_snapshot(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&LEDGER_MAGIC);
        buf.extend_from_slice(&LEDGER_VERSION.to_le_bytes());
        buf.extend_from_slice(&self.schedule.genesis_subsidy.to_le_bytes());
        buf.extend_from_slice(&self.schedule.halving_era.to_le_bytes());
        buf.extend_from_slice(&self.finality_depth.to_le_bytes());
        buf.extend_from_slice(&self.payload_pruning_depth.to_le_bytes());
        buf.extend_from_slice(&self.dag.write_snapshot());
        buf
    }

    /// Rebuild a ledger from a snapshot by replaying its blocks. The full state
    /// (and each block's view state) is recomputed, so the restored ledger is
    /// identical to the original — except that it restores at **unbounded
    /// finality** (the snapshot stores blocks, not the runtime finality policy);
    /// re-apply [`Ledger::with_finality`]'s depth after loading if wanted.
    ///
    /// For snapshots that contain **staked-VRF blocks**, use
    /// [`Ledger::read_snapshot_with_hybrid`] — replay must run under the same
    /// admission rules that produced those ids.
    pub fn read_snapshot(bytes: &[u8]) -> Result<Ledger, LedgerSnapshotError> {
        Self::read_snapshot_impl(bytes, None)
    }

    /// Like [`Ledger::read_snapshot`], but hybrid admission (with `config`) is
    /// active during replay, so staked-VRF blocks re-admit with their original
    /// ids intact. Required for any snapshot produced in hybrid mode.
    pub fn read_snapshot_with_hybrid(
        bytes: &[u8],
        config: HybridConfig,
    ) -> Result<Ledger, LedgerSnapshotError> {
        Self::read_snapshot_impl(bytes, Some(config))
    }

    fn read_snapshot_impl(
        bytes: &[u8],
        hybrid: Option<HybridConfig>,
    ) -> Result<Ledger, LedgerSnapshotError> {
        if bytes.len() < 4 || bytes[..4] != LEDGER_MAGIC {
            return Err(LedgerSnapshotError::BadMagic);
        }
        if bytes.len() < 38 {
            // magic(4) + version(2) + genesis_subsidy(8) + halving_era(8) + finality_depth(8) + payload_pruning_depth(8) = 38
            return Err(LedgerSnapshotError::Dag(SnapshotError::UnexpectedEof));
        }
        let version = u16::from_le_bytes([bytes[4], bytes[5]]);
        if version != LEDGER_VERSION {
            return Err(LedgerSnapshotError::UnsupportedVersion(version));
        }
        let genesis_subsidy =
            u64::from_le_bytes(bytes[6..14].try_into().expect("14 - 6 == 8 bytes"));
        let halving_era = u64::from_le_bytes(bytes[14..22].try_into().expect("22 - 14 == 8 bytes"));
        let finality_depth =
            u64::from_le_bytes(bytes[22..30].try_into().expect("30 - 22 == 8 bytes"));
        let payload_pruning_depth =
            u64::from_le_bytes(bytes[30..38].try_into().expect("38 - 30 == 8 bytes"));
        let schedule = HalvingSchedule::new(genesis_subsidy, halving_era);

        let snapshot = decode_snapshot(&bytes[38..]).map_err(LedgerSnapshotError::Dag)?;
        let mut blocks = snapshot.blocks.into_iter();
        let genesis = blocks.next().ok_or(LedgerSnapshotError::Empty)?;
        let genesis_txs =
            decode_block_payload(genesis.payload()).map_err(LedgerSnapshotError::Payload)?;
        let mut ledger = Ledger::new(snapshot.k, schedule, &genesis_txs)
            .map_err(LedgerSnapshotError::Genesis)?;
        ledger.finality_depth = finality_depth;
        ledger.payload_pruning_depth = payload_pruning_depth;
        ledger.dag.set_payload_pruning_depth(payload_pruning_depth);
        if let Some(config) = hybrid {
            ledger.set_hybrid(config);
        }
        for block in blocks {
            // Identity-preserving replay: VRF-era snapshots must re-admit the
            // exact block ids their children reference.
            ledger
                .insert_raw_block(block)
                .map_err(LedgerSnapshotError::Rebuild)?;
        }
        Ok(ledger)
    }

    /// Serialise a **finality checkpoint**: the UTXO set at the finality boundary
    /// plus the blocks above it (the "tip segment"). On load, the checkpoint UTXO
    /// set is applied directly and only the tip segment is replayed, avoiding a
    /// full replay from genesis.
    ///
    /// The checkpoint is only meaningful when `finality_depth` is finite. If
    /// finality is disabled (`finality_depth == u64::MAX`), this returns an error.
    /// The checkpoint also stores the runtime `finality_depth` and
    /// `payload_pruning_depth` so they are restored automatically.
    pub fn write_checkpoint(&self) -> Result<Vec<u8>, LedgerCheckpointError> {
        if self.finality_depth == u64::MAX {
            return Err(LedgerCheckpointError::FinalityDisabled);
        }
        let finality_score = self.finality_score();
        let genesis_height = self.heights.get(&self.genesis).copied().unwrap_or(0);
        if finality_score == 0 && genesis_height == 0 {
            return Err(LedgerCheckpointError::FinalityNotActive);
        }

        // Find the checkpoint block: the highest block whose blue score is
        // >= finality_score but whose selected parent (if any) is below it.
        let order = self.dag.linearize();
        let mut checkpoint_block = self.genesis;
        for id in &order {
            let gd = self.dag.ghostdag(id).unwrap();
            if gd.blue_score >= finality_score {
                checkpoint_block = *id;
                break;
            }
        }

        // The checkpoint UTXO set is the state in the checkpoint block's view.
        let checkpoint_state = self
            .states
            .get(&checkpoint_block)
            .ok_or(LedgerCheckpointError::MissingCheckpointState)?;

        // The checkpoint block's height in the selected chain (for subsidy calculation).
        let checkpoint_height = self.heights.get(&checkpoint_block).copied().unwrap_or(0);

        // The tip segment: the checkpoint block plus blocks in linearized order
        // whose blue score is strictly above the finality score (i.e. not final).
        // The checkpoint block is included so it can serve as the trusted genesis
        // on restore, with its original ID preserved via Block::new_pruned.
        let mut tip_segment = Vec::new();
        let cp_block = self
            .dag
            .block(&checkpoint_block)
            .expect("checkpoint block is present");
        let pruned_cp = kovanica_dag::Block::new_pruned_with_vrf(
            cp_block.parents().to_vec(),
            cp_block.work(),
            cp_block.timestamp_ms(),
            cp_block.nonce(),
            cp_block.vrf_public_key().cloned(),
            cp_block.vrf_proof().cloned(),
            cp_block.vrf_output().cloned(),
            cp_block.id(),
        );
        tip_segment.push(pruned_cp);
        for id in &order {
            let gd = self.dag.ghostdag(id).unwrap();
            if gd.blue_score > finality_score {
                let block = self.dag.block(id).expect("linearized id is present");
                tip_segment.push(block.clone());
            }
        }

        let mut buf = Vec::new();
        buf.extend_from_slice(&CHECKPOINT_MAGIC);
        buf.extend_from_slice(&CHECKPOINT_VERSION.to_le_bytes());
        buf.extend_from_slice(&self.dag.k().to_le_bytes());
        buf.extend_from_slice(&self.schedule.genesis_subsidy.to_le_bytes());
        buf.extend_from_slice(&self.schedule.halving_era.to_le_bytes());
        buf.extend_from_slice(&self.finality_depth.to_le_bytes());
        buf.extend_from_slice(&self.payload_pruning_depth.to_le_bytes());
        buf.extend_from_slice(&checkpoint_height.to_le_bytes());
        buf.extend_from_slice(&checkpoint_state.encode());
        // v3: the stake registry as of the checkpoint block's view, applied
        // directly on load (the tip-segment replay then extends it).
        let stake_bytes = self
            .stakes
            .get(&checkpoint_block)
            .cloned()
            .unwrap_or_default()
            .encode();
        buf.extend_from_slice(&(stake_bytes.len() as u64).to_le_bytes());
        buf.extend_from_slice(&stake_bytes);
        // Tip segment (checkpoint block + blocks above finality boundary)
        buf.extend_from_slice(&(tip_segment.len() as u64).to_le_bytes());
        for block in &tip_segment {
            kovanica_dag::encode_block(block, &mut buf);
        }
        Ok(buf)
    }

    /// Rebuild a ledger from a finality checkpoint. Applies the checkpoint UTXO
    /// set directly, then replays only the tip segment blocks (those above the
    /// finality boundary). Returns the restored ledger with the same
    /// `finality_depth` and `payload_pruning_depth` as when the checkpoint was
    /// written.
    ///
    /// For checkpoints whose tip segment contains staked-VRF blocks, use
    /// [`Ledger::read_checkpoint_with_hybrid`].
    pub fn read_checkpoint(bytes: &[u8]) -> Result<Ledger, LedgerCheckpointError> {
        Self::read_checkpoint_impl(bytes, None)
    }

    /// Like [`Ledger::read_checkpoint`], but hybrid admission runs during
    /// tip-segment replay so staked-VRF blocks keep their original ids.
    pub fn read_checkpoint_with_hybrid(
        bytes: &[u8],
        config: HybridConfig,
    ) -> Result<Ledger, LedgerCheckpointError> {
        Self::read_checkpoint_impl(bytes, Some(config))
    }

    fn read_checkpoint_impl(
        bytes: &[u8],
        hybrid: Option<HybridConfig>,
    ) -> Result<Ledger, LedgerCheckpointError> {
        if bytes.len() < 4 || bytes[..4] != CHECKPOINT_MAGIC {
            return Err(LedgerCheckpointError::BadMagic);
        }
        let min_header = 4 + 2 + 2 + 8 + 8 + 8 + 8 + 8; // magic + version + k + 5*u64
        if bytes.len() < min_header {
            return Err(LedgerCheckpointError::UnexpectedEof);
        }
        let version = u16::from_le_bytes([bytes[4], bytes[5]]);
        if version != CHECKPOINT_VERSION {
            return Err(LedgerCheckpointError::UnsupportedVersion(version));
        }
        let mut pos = 6;
        let k = u16::from_le_bytes(bytes[pos..pos + 2].try_into().unwrap());
        pos += 2;
        let genesis_subsidy = u64::from_le_bytes(bytes[pos..pos + 8].try_into().unwrap());
        pos += 8;
        let halving_era = u64::from_le_bytes(bytes[pos..pos + 8].try_into().unwrap());
        pos += 8;
        let finality_depth = u64::from_le_bytes(bytes[pos..pos + 8].try_into().unwrap());
        pos += 8;
        let payload_pruning_depth = u64::from_le_bytes(bytes[pos..pos + 8].try_into().unwrap());
        pos += 8;
        let checkpoint_height = u64::from_le_bytes(bytes[pos..pos + 8].try_into().unwrap());
        pos += 8;

        // Decode checkpoint UTXO set
        let mut remaining = &bytes[pos..];
        let checkpoint_state = UtxoSet::decode(&mut remaining)
            .map_err(|_| LedgerCheckpointError::Payload(DecodeError::UnexpectedEof))?;
        pos = bytes.len() - remaining.len();

        // v3: length-prefixed stake registry blob.
        if bytes.len() < pos + 8 {
            return Err(LedgerCheckpointError::UnexpectedEof);
        }
        let stake_len = u64::from_le_bytes(bytes[pos..pos + 8].try_into().unwrap()) as usize;
        pos += 8;
        if bytes.len() < pos + stake_len {
            return Err(LedgerCheckpointError::UnexpectedEof);
        }
        let checkpoint_stake = StakeState::decode(&bytes[pos..pos + stake_len])
            .map_err(|_| LedgerCheckpointError::UnexpectedEof)?;
        pos += stake_len;

        if bytes.len() < pos + 8 {
            return Err(LedgerCheckpointError::UnexpectedEof);
        }
        let tip_count = u64::from_le_bytes(bytes[pos..pos + 8].try_into().unwrap()) as usize;
        pos += 8;

        let schedule = HalvingSchedule::new(genesis_subsidy, halving_era);

        // Read tip segment blocks (each encoded with kovanica_dag::encode_block)
        // The first block is the checkpoint block; we must reconstruct it with
        // its original ID using Block::new_pruned.
        let mut blocks = Vec::new();
        let mut block_pos = pos;
        for i in 0..tip_count {
            if block_pos + 32 > bytes.len() {
                return Err(LedgerCheckpointError::UnexpectedEof);
            }
            // Read the stored block ID (first 32 bytes of encode_block output)
            let stored_id =
                BlockId::from_bytes(bytes[block_pos..block_pos + 32].try_into().unwrap());
            block_pos += 32;
            let (mut block, consumed) = decode_checkpoint_block(&bytes[block_pos..])?;
            block_pos += consumed;

            // For the first block (checkpoint block), reconstruct with original ID
            if i == 0 {
                block = Block::new_pruned(
                    block.parents().to_vec(),
                    block.work(),
                    block.timestamp_ms(),
                    block.nonce(),
                    stored_id,
                );
            }
            blocks.push(block);
        }

        // The first block in tip_segment is the checkpoint block; use it as genesis.
        let mut blocks_iter = blocks.into_iter();
        let checkpoint_block = blocks_iter
            .next()
            .ok_or(LedgerCheckpointError::UnexpectedEof)?;

        // Create DAG with checkpoint block as genesis (trusted, bypasses parent check).
        // The checkpoint block may have parents that don't exist in the restored DAG;
        // we trust it as the finality boundary.
        let checkpoint_id = checkpoint_block.id();
        let mut dag = Dag::with_validator(k, checkpoint_block, Box::new(TxStructureValidator));
        dag.set_payload_pruning_depth(payload_pruning_depth);

        // Build ledger with the checkpoint state applied directly.
        let mut ledger = Ledger {
            dag,
            schedule,
            genesis: checkpoint_id,
            finality_depth,
            payload_pruning_depth,
            states: HashMap::new(),
            stakes: HashMap::new(),
            hybrid: None,
            staked_seen: HashMap::new(),
            heights: HashMap::new(),
            multisig_activation_score: MULTISIG_ACTIVATION_SCORE,
        };
        // Apply checkpoint state as the ledger's current state and the checkpoint block's view state.
        ledger
            .states
            .insert(checkpoint_id, checkpoint_state.clone());
        ledger.stakes.insert(checkpoint_id, checkpoint_stake);
        ledger.heights.insert(checkpoint_id, checkpoint_height);
        if let Some(config) = hybrid {
            ledger.set_hybrid(config);
        }

        // Replay remaining tip segment blocks (those strictly above finality).
        for block in blocks_iter {
            let txs =
                decode_block_payload(block.payload()).map_err(LedgerCheckpointError::Payload)?;
            let mapped_parents: Vec<_> = block
                .parents()
                .iter()
                .map(|p| {
                    if ledger.dag().ghostdag(p).is_some() {
                        *p
                    } else {
                        checkpoint_id
                    }
                })
                .collect();
            // Preserve VRF identity through the rewind; only parents are
            // remapped (a block whose parents were rewired legitimately gets a
            // new id — pre-existing checkpoint semantics).
            let rebuilt = match (
                block.vrf_public_key(),
                block.vrf_proof(),
                block.vrf_output(),
            ) {
                (Some(pk), Some(proof), Some(output)) => Block::new_with_vrf(
                    mapped_parents,
                    block.work(),
                    block.timestamp_ms(),
                    block.nonce(),
                    *pk,
                    proof.clone(),
                    *output,
                    block.payload().to_vec(),
                ),
                _ => Block::new(
                    mapped_parents,
                    block.work(),
                    block.timestamp_ms(),
                    block.nonce(),
                    block.payload().to_vec(),
                ),
            };
            ledger
                .insert_prepared_block(rebuilt, &txs)
                .map_err(LedgerCheckpointError::Rebuild)?;
        }

        Ok(ledger)
    }
}

/// Decode a single block from the checkpoint tip segment format.
/// Returns the block and the number of bytes consumed.
fn decode_checkpoint_block(bytes: &[u8]) -> Result<(Block, usize), LedgerCheckpointError> {
    // Blocks in checkpoint are stored using kovanica_dag::encode_block format
    // (without the DAG magic/version header, just the block data).
    // The format: parents_len + parents + work + timestamp_ms + nonce + payload_len + payload
    let mut reader = CheckpointReader::new(bytes);
    let n_parents = reader.read_count(32)? as usize;
    let mut parents = Vec::with_capacity(n_parents);
    for _ in 0..n_parents {
        if reader.remaining() < 32 {
            return Err(LedgerCheckpointError::UnexpectedEof);
        }
        parents.push(BlockId::from_bytes(reader.read_array::<32>()?));
    }
    let work = reader.read_u128()?;
    let timestamp_ms = reader.read_u64()?;
    let nonce = reader.read_u64()?;

    // VRF fields (v5+)
    let has_vrf = reader.read_u8()?;
    let (vrf_public_key, vrf_proof, vrf_output) = if has_vrf == 1 {
        let pk_bytes: [u8; 32] = reader.read_array::<32>()?;
        let pk = kovanica_dag::VrfPublicKey::from_bytes(&pk_bytes)
            .map_err(|_| LedgerCheckpointError::UnexpectedEof)?;
        let proof_bytes: [u8; 96] = reader.read_array::<96>()?;
        let proof = kovanica_dag::VrfProof::from_bytes(&proof_bytes)
            .map_err(|_| LedgerCheckpointError::UnexpectedEof)?;
        let output_bytes: [u8; 32] = reader.read_array::<32>()?;
        let output = kovanica_dag::VrfOutput::from_bytes(output_bytes);
        (Some(pk), Some(proof), Some(output))
    } else {
        (None, None, None)
    };

    let payload_len = reader.read_count(1)? as usize;
    if payload_len == 0 {
        let block = Block::new_pruned_with_vrf(
            parents,
            work,
            timestamp_ms,
            nonce,
            vrf_public_key,
            vrf_proof,
            vrf_output,
            BlockId::from_bytes([0u8; 32]),
        );
        let consumed = reader.pos;
        return Ok((block, consumed));
    }
    if reader.remaining() < payload_len {
        return Err(LedgerCheckpointError::UnexpectedEof);
    }
    let payload = reader.read_bytes(payload_len)?;
    let block = if let Some(pk) = vrf_public_key {
        Block::new_with_vrf(
            parents,
            work,
            timestamp_ms,
            nonce,
            pk,
            vrf_proof.unwrap(),
            vrf_output.unwrap(),
            payload,
        )
    } else {
        Block::new(parents, work, timestamp_ms, nonce, payload)
    };
    let consumed = reader.pos;
    Ok((block, consumed))
}

/// Local reader for checkpoint block decoding.
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

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], LedgerCheckpointError> {
        if self.remaining() < N {
            return Err(LedgerCheckpointError::UnexpectedEof);
        }
        let mut out = [0u8; N];
        out.copy_from_slice(&self.buf[self.pos..self.pos + N]);
        self.pos += N;
        Ok(out)
    }

    fn read_u8(&mut self) -> Result<u8, LedgerCheckpointError> {
        let b = self.read_array::<1>()?;
        Ok(b[0])
    }

    fn read_u64(&mut self) -> Result<u64, LedgerCheckpointError> {
        Ok(u64::from_le_bytes(self.read_array::<8>()?))
    }
    fn read_u128(&mut self) -> Result<u128, LedgerCheckpointError> {
        Ok(u128::from_le_bytes(self.read_array::<16>()?))
    }
    fn read_count(&mut self, min_element_bytes: usize) -> Result<u64, LedgerCheckpointError> {
        let n = self.read_u64()? as usize;
        if min_element_bytes > 0 && n > self.remaining() / min_element_bytes {
            return Err(LedgerCheckpointError::UnexpectedEof);
        }
        Ok(n as u64)
    }
    fn read_bytes(&mut self, len: usize) -> Result<Vec<u8>, LedgerCheckpointError> {
        if self.remaining() < len {
            return Err(LedgerCheckpointError::UnexpectedEof);
        }
        let out = self.buf[self.pos..self.pos + len].to_vec();
        self.pos += len;
        Ok(out)
    }
}

/// Magic prefix identifying a Kovanica ledger checkpoint (`"KVCP"`).
const CHECKPOINT_MAGIC: [u8; 4] = *b"KVCP";
/// Checkpoint format version. v2 adds checkpoint block height; v3 adds the
/// length-prefixed stake registry of the checkpoint block's view.
const CHECKPOINT_VERSION: u16 = 3;

/// Why a ledger checkpoint could not be encoded or decoded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LedgerCheckpointError {
    /// The bytes did not start with the expected magic prefix.
    BadMagic,
    /// The checkpoint version is not supported by this build.
    UnsupportedVersion(u16),
    /// The input ended before a fully-formed value could be read.
    UnexpectedEof,
    /// Bytes remained after the declared number of entries.
    TrailingBytes,
    /// Finality is disabled (unbounded), so no checkpoint can be written.
    FinalityDisabled,
    /// Finality depth is set but the DAG isn't deep enough yet.
    FinalityNotActive,
    /// The checkpoint block's state is missing (should not happen).
    MissingCheckpointState,
    /// A block's payload was not valid transaction encoding.
    Payload(DecodeError),
    /// The embedded DAG block could not be decoded.
    Dag(SnapshotError),
    /// Applying the genesis transactions failed.
    Genesis(LedgerError),
    /// Replaying a block through `insert` failed.
    Rebuild(LedgerInsertError),
    /// The checkpoint state at the boundary does not match the replayed state.
    StateMismatch,
}

impl core::fmt::Display for LedgerCheckpointError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            LedgerCheckpointError::BadMagic => f.write_str("not a kovanica ledger checkpoint"),
            LedgerCheckpointError::UnsupportedVersion(v) => {
                write!(f, "unsupported checkpoint version {v}")
            }
            LedgerCheckpointError::UnexpectedEof => f.write_str("unexpected end of checkpoint"),
            LedgerCheckpointError::TrailingBytes => f.write_str("trailing bytes after checkpoint"),
            LedgerCheckpointError::FinalityDisabled => {
                f.write_str("cannot checkpoint: finality is disabled (unbounded)")
            }
            LedgerCheckpointError::FinalityNotActive => {
                f.write_str("cannot checkpoint: DAG not deep enough for finality")
            }
            LedgerCheckpointError::MissingCheckpointState => {
                f.write_str("checkpoint block state missing")
            }
            LedgerCheckpointError::Payload(e) => write!(f, "payload decode: {e}"),
            LedgerCheckpointError::Dag(e) => write!(f, "dag block: {e}"),
            LedgerCheckpointError::Genesis(e) => write!(f, "genesis: {e}"),
            LedgerCheckpointError::Rebuild(e) => write!(f, "replaying block: {e}"),
            LedgerCheckpointError::StateMismatch => {
                f.write_str("checkpoint state mismatch at boundary")
            }
        }
    }
}

impl std::error::Error for LedgerCheckpointError {}

impl From<DecodeError> for LedgerCheckpointError {
    fn from(e: DecodeError) -> Self {
        LedgerCheckpointError::Payload(e)
    }
}

impl From<SnapshotError> for LedgerCheckpointError {
    fn from(e: SnapshotError) -> Self {
        LedgerCheckpointError::Dag(e)
    }
}

impl From<LedgerError> for LedgerCheckpointError {
    fn from(e: LedgerError) -> Self {
        LedgerCheckpointError::Genesis(e)
    }
}

impl From<LedgerInsertError> for LedgerCheckpointError {
    fn from(e: LedgerInsertError) -> Self {
        LedgerCheckpointError::Rebuild(e)
    }
}

/// Magic prefix identifying a Kovanica ledger snapshot (`"KVLG"`).
const LEDGER_MAGIC: [u8; 4] = *b"KVLG";
/// Ledger snapshot format version. v2 added `finality_depth` and `payload_pruning_depth`.
const LEDGER_VERSION: u16 = 2;

/// Why a ledger snapshot could not be decoded or replayed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LedgerSnapshotError {
    /// The bytes did not start with the expected magic prefix.
    BadMagic,
    /// The snapshot version is not supported by this build.
    UnsupportedVersion(u16),
    /// The embedded DAG snapshot could not be decoded.
    Dag(SnapshotError),
    /// A block's payload was not valid transaction encoding.
    Payload(DecodeError),
    /// Applying the genesis transactions failed.
    Genesis(LedgerError),
    /// Replaying a block through `insert` failed.
    Rebuild(LedgerInsertError),
    /// The snapshot contained no genesis block.
    Empty,
}

impl core::fmt::Display for LedgerSnapshotError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            LedgerSnapshotError::BadMagic => f.write_str("not a kovanica ledger snapshot"),
            LedgerSnapshotError::UnsupportedVersion(v) => {
                write!(f, "unsupported ledger snapshot version {v}")
            }
            LedgerSnapshotError::Dag(e) => write!(f, "dag snapshot: {e}"),
            LedgerSnapshotError::Payload(e) => write!(f, "payload decode: {e}"),
            LedgerSnapshotError::Genesis(e) => write!(f, "genesis: {e}"),
            LedgerSnapshotError::Rebuild(e) => write!(f, "replaying block: {e}"),
            LedgerSnapshotError::Empty => f.write_str("snapshot has no genesis block"),
        }
    }
}

impl std::error::Error for LedgerSnapshotError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::KeyPair;
    use crate::tx::{TxId, TxOutput};

    // A funded outpoint owned by `kp`, seeded directly into a UTXO set so unit
    // tests need no coinbase plumbing.
    fn funded(set: &mut UtxoSet, kp: &KeyPair, value: u64, seed: u8) -> OutPoint {
        let op = OutPoint::new(TxId::from_bytes([seed; 32]), 0);
        set.insert(op, TxOutput::new(value, kp.address()));
        op
    }

    #[test]
    fn transfer_conserves_value_and_pays_fee() {
        let alice = KeyPair::from_u64(1);
        let bob = KeyPair::from_u64(2);
        let mut utxo = UtxoSet::new();
        let op = funded(&mut utxo, &alice, 100, 1);

        let tx = Transaction::signed(
            &[(op, &alice)],
            vec![TxOutput::new(90, bob.address())],
            vec![],
        );
        let summary = apply_block(&mut utxo, &[tx], 0).unwrap();

        assert_eq!(summary.fees, 10); // 100 in − 90 out
        assert_eq!(utxo.balance(&bob.address()), 90);
        assert_eq!(utxo.balance(&alice.address()), 0);
        assert!(!utxo.contains(&op), "spent input is gone");
    }

    #[test]
    fn bad_signature_is_rejected_and_atomic() {
        let alice = KeyPair::from_u64(1);
        let mallory = KeyPair::from_u64(9);
        let bob = KeyPair::from_u64(2);
        let mut utxo = UtxoSet::new();
        let op = funded(&mut utxo, &alice, 100, 1);
        let before = utxo.total_value();

        // Mallory signs a spend of Alice's output.
        let tx = Transaction::signed(
            &[(op, &mallory)],
            vec![TxOutput::new(50, bob.address())],
            vec![],
        );
        let err = apply_block(&mut utxo, &[tx], 0).unwrap_err();

        assert!(matches!(err, LedgerError::BadSignature { input: 0, .. }));
        assert_eq!(
            utxo.total_value(),
            before,
            "rejected block left state untouched"
        );
        assert!(utxo.contains(&op));
    }

    #[test]
    fn overspend_is_rejected() {
        let alice = KeyPair::from_u64(1);
        let bob = KeyPair::from_u64(2);
        let mut utxo = UtxoSet::new();
        let op = funded(&mut utxo, &alice, 100, 1);

        let tx = Transaction::signed(
            &[(op, &alice)],
            vec![TxOutput::new(101, bob.address())],
            vec![],
        );
        let err = apply_block(&mut utxo, &[tx], 0).unwrap_err();
        assert!(matches!(
            err,
            LedgerError::ValueNotConserved {
                inputs: 100,
                outputs: 101,
                ..
            }
        ));
    }

    #[test]
    fn double_spend_within_block_is_rejected() {
        let alice = KeyPair::from_u64(1);
        let bob = KeyPair::from_u64(2);
        let mut utxo = UtxoSet::new();
        let op = funded(&mut utxo, &alice, 100, 1);

        let first = Transaction::signed(
            &[(op, &alice)],
            vec![TxOutput::new(90, bob.address())],
            b"1".to_vec(),
        );
        // Second tx spends the same outpoint; by application time it's gone.
        let second = Transaction::signed(
            &[(op, &alice)],
            vec![TxOutput::new(80, bob.address())],
            b"2".to_vec(),
        );
        let err = apply_block(&mut utxo, &[first, second], 0).unwrap_err();
        assert_eq!(err, LedgerError::MissingInput(op));
        // Atomic: neither spend took effect.
        assert!(utxo.contains(&op));
    }

    #[test]
    fn coinbase_may_claim_subsidy_plus_fees_but_no_more() {
        let alice = KeyPair::from_u64(1);
        let bob = KeyPair::from_u64(2);
        let miner = KeyPair::from_u64(3);
        let mut utxo = UtxoSet::new();
        let op = funded(&mut utxo, &alice, 100, 1);

        // Transfer leaves a fee of 10; subsidy 50 ⇒ coinbase may claim 60.
        let transfer = Transaction::signed(
            &[(op, &alice)],
            vec![TxOutput::new(90, bob.address())],
            vec![],
        );
        let good_cb =
            Transaction::coinbase(vec![TxOutput::new(60, miner.address())], b"h1".to_vec());
        let summary = apply_block(&mut utxo, &[good_cb, transfer.clone()], 50).unwrap();
        assert_eq!(
            summary,
            BlockSummary {
                fees: 10,
                minted: 60
            }
        );

        // Claiming 61 overspends.
        let mut utxo2 = UtxoSet::new();
        let op2 = funded(&mut utxo2, &alice, 100, 1);
        let transfer2 = Transaction::signed(
            &[(op2, &alice)],
            vec![TxOutput::new(90, bob.address())],
            vec![],
        );
        let greedy_cb =
            Transaction::coinbase(vec![TxOutput::new(61, miner.address())], b"h1".to_vec());
        let err = apply_block(&mut utxo2, &[greedy_cb, transfer2], 50).unwrap_err();
        assert_eq!(
            err,
            LedgerError::CoinbaseOverspend {
                claimed: 61,
                allowed: 60
            }
        );
    }

    // ---- stake registry integration ----

    use crate::stake::{bond_tag, StakeState, UNBOND_MATURITY};

    fn vrf_pk(seed: u8) -> [u8; 32] {
        kovanica_dag::vrf::vrf_keypair_from_seed(&[seed; 32])
            .1
            .to_bytes()
    }

    /// A bond transaction: `amount` from `kp`, single self-output, `KVB1||pk` tag.
    fn bond_tx(kp: &KeyPair, op: OutPoint, amount: u64, pk: [u8; 32]) -> Transaction {
        Transaction::signed(
            &[(op, kp)],
            vec![TxOutput::new(amount, kp.address())],
            bond_tag(&pk),
        )
    }

    /// An unbond transaction spending frozen outpoints back to their owner
    /// (a transaction must have at least one output, so the freed value returns
    /// to the spender as an ordinary UTXO).
    fn unbond_tx(kp: &KeyPair, ops: &[OutPoint], total: u64) -> Transaction {
        let inputs: Vec<(OutPoint, &KeyPair)> = ops.iter().map(|op| (*op, kp)).collect();
        Transaction::signed(
            &inputs,
            vec![TxOutput::new(total, kp.address())],
            b"KVU1".to_vec(),
        )
    }

    #[test]
    fn bond_freezes_and_unbond_releases() {
        let alice = KeyPair::from_u64(1);
        let pk = vrf_pk(5);
        let mut utxo = UtxoSet::new();
        let op = funded(&mut utxo, &alice, 100, 1);
        let mut stake = StakeState::new();

        // Bond 60 of the 100.
        apply_block_with_stake(&mut utxo, &mut stake, &[bond_tx(&alice, op, 60, pk)], 0, 10)
            .unwrap();
        assert_eq!(stake.stake_of(&pk), 60);
        // The bond output is the only output (the 40 remainder is fee); it is
        // still a normal UTXO — just frozen in the registry.
        assert_eq!(utxo.balance(&alice.address()), 60);

        // The frozen outpoint cannot be spent by a regular transaction.
        let frozen_op = OutPoint::new(bond_tx(&alice, op, 60, pk).id(), 0);
        let steal = Transaction::signed(
            &[(frozen_op, &alice)],
            vec![TxOutput::new(60, KeyPair::from_u64(9).address())],
            vec![],
        );
        let err =
            apply_block_with_stake(&mut utxo, &mut stake, std::slice::from_ref(&steal), 0, 11)
                .unwrap_err();
        assert!(matches!(
            err,
            LedgerError::Stake {
                reason: StakeError::FrozenInput { .. },
                ..
            }
        ));
        // Atomic: the rejected steal changed nothing.
        assert!(utxo.contains(&frozen_op));
        assert_eq!(stake.stake_of(&pk), 60);

        // Immature unbond is rejected.
        let unbond = unbond_tx(&alice, &[frozen_op], 60);
        let err =
            apply_block_with_stake(&mut utxo, &mut stake, std::slice::from_ref(&unbond), 0, 50)
                .unwrap_err();
        assert!(matches!(
            err,
            LedgerError::Stake {
                reason: StakeError::UnbondImmature { .. },
                ..
            }
        ));

        // After maturity the unbond applies and frees the value.
        apply_block_with_stake(&mut utxo, &mut stake, &[unbond], 0, 10 + UNBOND_MATURITY).unwrap();
        assert_eq!(stake.stake_of(&pk), 0);
        assert_eq!(stake.total_stake(), 0);

        // The released output is an ordinary UTXO again.
        let freed = OutPoint::new(unbond_tx(&alice, &[frozen_op], 60).id(), 0);
        let spend = Transaction::signed(
            &[(freed, &alice)],
            vec![TxOutput::new(59, KeyPair::from_u64(9).address())],
            vec![],
        );
        apply_block_with_stake(&mut utxo, &mut stake, &[spend], 0, 200).unwrap();
    }

    #[test]
    fn ledger_tracks_stake_per_block_across_heights() {
        let validator = KeyPair::from_u64(7);
        let pk = vrf_pk(7);
        let genesis_cb = Transaction::coinbase(
            vec![TxOutput::new(1_000, validator.address())],
            b"g".to_vec(),
        );
        let genesis_cb_id = genesis_cb.id();
        let mut ledger =
            Ledger::new(3, HalvingSchedule::new(1_000, 1_000), &[genesis_cb]).expect("genesis");

        // Height 1: bond 400.
        let coin = OutPoint::new(genesis_cb_id, 0);
        let bond = bond_tx(&validator, coin, 400, pk);
        let bond_out = OutPoint::new(bond.id(), 0);
        let b1 = ledger
            .insert(vec![ledger.genesis()], 1, 1, 0, &[bond])
            .unwrap();
        assert_eq!(ledger.stake_state(&b1).unwrap().stake_of(&pk), 400);
        // Genesis's view still shows zero (per-block states are independent).
        assert_eq!(
            ledger.stake_state(&ledger.genesis()).unwrap().total_stake(),
            0
        );

        // Height 2..maturity: regular spends of the frozen output never apply.
        for h in 2..UNBOND_MATURITY {
            let steal = Transaction::signed(
                &[(bond_out, &validator)],
                vec![TxOutput::new(399, validator.address())],
                b"steal attempt".to_vec(),
            );
            assert!(
                ledger.insert(vec![b1], 1, h, 0, &[steal]).is_err(),
                "frozen spend must not apply at height {h}"
            );
        }

        // Age to maturity with empty blocks, then unbond.
        let mut tip = b1;
        for h in UNBOND_MATURITY..UNBOND_MATURITY + 101 {
            tip = ledger.insert(vec![tip], 1, h, 0, &[]).unwrap();
        }
        let unbond = unbond_tx(&validator, &[bond_out], 400);
        let unbond_id = unbond.id();
        let b_unbond = ledger
            .insert(vec![tip], 1, 300, 0, &[unbond])
            .expect("matured unbond applies");
        assert_eq!(ledger.stake_state(&b_unbond).unwrap().stake_of(&pk), 0);
        // The unbonded output is freely spendable in a later block.
        let freed = OutPoint::new(unbond_id, 0);
        let spend = Transaction::signed(
            &[(freed, &validator)],
            vec![TxOutput::new(399, validator.address())],
            b"after unbond".to_vec(),
        );
        ledger
            .insert(vec![b_unbond], 1, 301, 0, &[spend])
            .expect("unbonded value is ordinary");
    }
}
