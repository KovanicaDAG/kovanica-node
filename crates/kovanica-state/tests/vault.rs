//! RFC-005 consensus test suite: time-lock vault / escrow (0x05) + real CSV.
//!
//! 25 tests.
//!
//! RFC-005 ships two things in one consensus change:
//!  1. **Real relative locktime (BIP-68/BIP-112 CSV)**: a transaction whose
//!     `sequence` is non-final delays each spend until the input's UTXO has aged
//!     `sequence` linearized blocks since its *creation height* (now stored per
//!     UTXO entry; checkpoint v6). `sequence == 0`, `sequence == 0xFFFF_FFFF`,
//!     and the BIP-68 disable-flag bit (`0x80000000`) all mean final.
//!  2. **The vault template**: outputs locked to a v0x05 address (BLAKE3 of a
//!     40-byte template `unlock_height(4) || csv(4) || owner_pk(32)`). Both locks
//!     are required; the spend also needs an Ed25519 signature by `owner_pk` over
//!     the tx sighash.
//!
//! Reference protocols: BIP-68 (relative lock-time), BIP-112 (CSV), BIP-65
//! (CLTV), BIP-113 (height semantics), RFC-004 (real CLTV + HTLC template
//! pattern), RFC-001/003 (versioned-hash templates, activation gating).
//!
//! Activation gating: `blue_score <= VAULT_ACTIVATION_SCORE` is pre-activation
//! (0x05 outputs and spends rejected). The CSV *ledger rule* is deliberately NOT
//! gated (RFC-005 §4.3): from height zero every tx with `sequence = 0` is final
//! and unaffected; a tx declaring `sequence != 0` is a deliberate opt-in.

use kovanica_dag::{Block, Dag};
use kovanica_state::{
    apply_dag, encode_block_payload, Address, HalvingSchedule, KeyPair, Ledger, LedgerError,
    LedgerInsertError, OutPoint, Transaction, TxInput, TxOutput, UtxoSet, VaultScript,
    VaultScriptError, DEFAULT_HALVING_ERA, VAULT_ACTIVATION_SCORE,
};

const K: u16 = 3;
const SUBSIDY: u64 = 1_000;
const SCHEDULE: HalvingSchedule = HalvingSchedule::new(SUBSIDY, DEFAULT_HALVING_ERA);

fn generate_key(count: usize) -> KeyPair {
    KeyPair::from_u64((1000 + count) as u64)
}

/// A validated vault template owned by `gen(seed)` with the given locks.
fn make_vault(seed: usize, unlock_height: u32, csv: u32) -> VaultScript {
    let owner_pk = *generate_key(seed).address().payload();
    VaultScript::new(unlock_height, csv, owner_pk).expect("valid vault template")
}

/// A ledger whose genesis coinbase funds a P2PK address (coin created at height 0).
fn funded_ledger(owner: Address, funding: u64) -> (Ledger, OutPoint) {
    let coinbase =
        Transaction::coinbase(vec![TxOutput::native(funding, owner)], b"genesis".to_vec());
    let coin = OutPoint::new(coinbase.id(), 0);
    let ledger = Ledger::new(K, SCHEDULE, &[coinbase]).expect("valid genesis");
    (ledger, coin)
}

/// A ledger whose genesis coinbase funds a vault address directly (coinbase
/// output is exempt from the vault output gate, mirroring RFC-004's HTLC).
fn vault_funded_ledger(script: &VaultScript, funding: u64) -> (Ledger, OutPoint) {
    let coinbase = Transaction::coinbase(
        vec![TxOutput::native(funding, script.address())],
        b"genesis".to_vec(),
    );
    let coin = OutPoint::new(coinbase.id(), 0);
    let ledger = Ledger::new(K, SCHEDULE, &[coinbase]).expect("valid genesis");
    (ledger, coin)
}

/// A vault spend: witness = [template, owner_signature].
fn build_vault_spend(
    outpoint: OutPoint,
    script: &VaultScript,
    owner_kp: &KeyPair,
    outputs: Vec<TxOutput>,
    tag: Vec<u8>,
    n_lock_time: u32,
    sequence: u32,
) -> Transaction {
    let dummy_input = TxInput {
        outpoint,
        witness: Vec::new(),
    };
    let mut tx = Transaction::new_with_lock(vec![dummy_input], outputs, tag, n_lock_time, sequence);
    let sighash = tx.sighash();
    let sig = owner_kp.sign(&sighash);
    tx.inputs_mut()[0].witness = script.spend_witness(sig);
    tx
}

/// A multi-input P2PK-spend transaction with a chosen `sequence`.
fn build_multi_input_spend(
    spends: &[(OutPoint, &KeyPair)],
    outputs: Vec<TxOutput>,
    tag: Vec<u8>,
    n_lock_time: u32,
    sequence: u32,
) -> Transaction {
    let inputs = spends
        .iter()
        .map(|(outpoint, _)| TxInput {
            outpoint: *outpoint,
            witness: Vec::new(),
        })
        .collect::<Vec<_>>();
    let mut tx = Transaction::new_with_lock(inputs, outputs, tag, n_lock_time, sequence);
    let sighash = tx.sighash();
    for (i, (_, kp)) in spends.iter().enumerate() {
        tx.inputs_mut()[i].witness = vec![kp.sign(&sighash).to_vec()];
    }
    tx
}

/// Extend a ledger by `n` empty blocks (each block height = parent height + 1).
fn extend_chain(ledger: &mut Ledger, n: u64) {
    for _ in 0..n {
        ledger
            .insert(vec![ledger.dag().selected_tip()], 1, 0, 0, &[])
            .unwrap();
    }
}

// =========================================================================
// CSV ledger rule (RFC-005 §3) — 8 tests
// =========================================================================

#[test]
fn csv_zero_final() {
    // `sequence = 0` is immediately final: spending a genesis coin (created at
    // height 0) in the very next block succeeds — the pre-RFC behaviour.
    let owner = generate_key(0);
    let bob = generate_key(1).address();
    let (mut ledger, coin) = funded_ledger(owner.address(), 1_000);

    let spend = Transaction::signed(
        &[(coin, &owner)],
        vec![TxOutput::native(900, bob)],
        b"csv0".to_vec(),
    );
    ledger
        .insert(vec![ledger.dag().selected_tip()], 1, 0, 0, &[spend])
        .expect("sequence 0 is final");
}

#[test]
fn csv_disable_flag_final() {
    // BIP-68 disable-flag bit (0x80000000): the field is ignored → final even
    // with low bits set.
    let owner = generate_key(0);
    let bob = generate_key(1).address();
    let (mut ledger, coin) = funded_ledger(owner.address(), 1_000);

    let spend = build_multi_input_spend(
        &[(coin, &owner)],
        vec![TxOutput::native(900, bob)],
        b"csv-flag".to_vec(),
        0,
        0x8000_0001,
    );
    ledger
        .insert(vec![ledger.dag().selected_tip()], 1, 0, 0, &[spend])
        .expect("disable flag means final");
}

#[test]
fn csv_max_sequence_final() {
    // 0xFFFFFFFF (BIP-68 "no relative lock") behaves like 0.
    let owner = generate_key(0);
    let bob = generate_key(1).address();
    let (mut ledger, coin) = funded_ledger(owner.address(), 1_000);

    let spend = build_multi_input_spend(
        &[(coin, &owner)],
        vec![TxOutput::native(900, bob)],
        b"csv-max".to_vec(),
        0,
        0xFFFF_FFFF,
    );
    ledger
        .insert(vec![ledger.dag().selected_tip()], 1, 0, 0, &[spend])
        .expect("max sequence is final");
}

#[test]
fn csv_aged_unlocks() {
    // Output created at height 0; spend with sequence 3 rejected until the
    // chain reaches creation_height + 3 = 3.
    let owner = generate_key(0);
    let bob = generate_key(1).address();
    let (mut ledger, coin) = funded_ledger(owner.address(), 1_000);

    let spend = build_multi_input_spend(
        &[(coin, &owner)],
        vec![TxOutput::native(900, bob)],
        b"csv-age".to_vec(),
        0,
        3,
    );

    // Spend block height 1: 1 < 0+3 → non-final.
    let err = ledger
        .insert(
            vec![ledger.dag().selected_tip()],
            1,
            0,
            0,
            std::slice::from_ref(&spend),
        )
        .unwrap_err();
    assert!(matches!(
        err,
        LedgerInsertError::State(LedgerError::NonFinalRelativeSequence {
            creation_height: 0,
            sequence: 3,
            block_height: 1,
            ..
        })
    ));

    // Tip at height 2: spend block height 3 → 3 >= 0+3 → accepted.
    extend_chain(&mut ledger, 2); // tip height 2 (the rejected block was not inserted)
    ledger
        .insert(vec![ledger.dag().selected_tip()], 1, 0, 0, &[spend])
        .expect("output has aged 3 blocks");
    let utxo = ledger.state(&ledger.dag().selected_tip()).unwrap();
    assert_eq!(utxo.balance(&bob), 900);
}

#[test]
fn csv_creation_height_from_later_block() {
    // The creation height is the *storing block's* height, not 0: a coin minted
    // at height 6 must age `sequence` blocks from 6.
    let miner = generate_key(2);
    let owner = generate_key(0);
    let bob = generate_key(1).address();

    let (mut ledger, _) = funded_ledger(miner.address(), 1_000);
    extend_chain(&mut ledger, 5); // tip height 5

    // Block at height 6 carries a coinbase paying the owner.
    let cb = Transaction::coinbase(
        vec![TxOutput::native(SUBSIDY, owner.address())],
        b"h6".to_vec(),
    );
    let coin = OutPoint::new(cb.id(), 0);
    ledger
        .insert(vec![ledger.dag().selected_tip()], 1, 0, 0, &[cb])
        .unwrap();

    let spend = build_multi_input_spend(
        &[(coin, &owner)],
        vec![TxOutput::native(900, bob)],
        b"csv-h6".to_vec(),
        0,
        3,
    );

    // Spend at height 8: 8 < 6+3 → non-final.
    extend_chain(&mut ledger, 1); // tip height 7
    let err = ledger
        .insert(
            vec![ledger.dag().selected_tip()],
            1,
            0,
            0,
            std::slice::from_ref(&spend),
        )
        .unwrap_err();
    assert!(matches!(
        err,
        LedgerInsertError::State(LedgerError::NonFinalRelativeSequence {
            creation_height: 6,
            sequence: 3,
            block_height: 8,
            ..
        })
    ));

    // Spend at height 9: 9 >= 6+3 → accepted.
    extend_chain(&mut ledger, 1); // tip height 8
    ledger
        .insert(vec![ledger.dag().selected_tip()], 1, 0, 0, &[spend])
        .expect("output has aged 3 blocks from height 6");
}

#[test]
fn csv_parallel_utxo_lookup() {
    // Two inputs created at different heights, each relative clock checked
    // independently: coin_a (height 0), coin_b (height 10), sequence 5.
    let owner_a = generate_key(0);
    let owner_b = generate_key(3);
    let funder = generate_key(4);

    let (mut ledger, coin_a) = funded_ledger(owner_a.address(), 1_000);
    extend_chain(&mut ledger, 9); // tip height 9
    let cb = Transaction::coinbase(
        vec![TxOutput::native(SUBSIDY, owner_b.address())],
        b"hb".to_vec(),
    );
    let coin_b = OutPoint::new(cb.id(), 0);
    ledger
        .insert(vec![ledger.dag().selected_tip()], 1, 0, 0, &[cb])
        .unwrap(); // block height 10

    let bob = funder.address();
    let spend = build_multi_input_spend(
        &[(coin_a, &owner_a), (coin_b, &owner_b)],
        vec![TxOutput::native(1_900, bob)],
        b"csv-2in".to_vec(),
        0,
        5,
    );

    // Tip height 10 (spend height 11): coin_b is final (11 >= 10+5? NO — 11 < 15).
    // …so the tx is rejected because coin_b has not aged 5 blocks since height 10.
    let err = ledger
        .insert(
            vec![ledger.dag().selected_tip()],
            1,
            0,
            0,
            std::slice::from_ref(&spend),
        )
        .unwrap_err();
    assert!(matches!(
        err,
        LedgerInsertError::State(LedgerError::NonFinalRelativeSequence {
            creation_height: 10,
            sequence: 5,
            ..
        })
    ));

    // Tip height 14 (spend height 15): both clocks satisfied → accepted.
    for _ in 0..4 {
        extend_chain(&mut ledger, 1);
    }
    ledger
        .insert(vec![ledger.dag().selected_tip()], 1, 0, 0, &[spend])
        .expect("both relative clocks elapsed");
}

#[test]
fn csv_cltv_compose() {
    // A tx with BOTH n_lock_time and sequence: either clock not met → reject.
    // coin at height 0; n_lock_time = 1 (satisfied at any height >= 1);
    // sequence = 5 (needs height >= 5). At spend height 2 CLTV passes but CSV
    // does not → NonFinalRelativeSequence.
    let owner = generate_key(0);
    let bob = generate_key(1).address();
    let (mut ledger, coin) = funded_ledger(owner.address(), 1_000);

    let spend = build_multi_input_spend(
        &[(coin, &owner)],
        vec![TxOutput::native(900, bob)],
        b"csv+cltv".to_vec(),
        1,
        5,
    );

    extend_chain(&mut ledger, 2); // tip height 2
    let err = ledger
        .insert(
            vec![ledger.dag().selected_tip()],
            1,
            0,
            0,
            std::slice::from_ref(&spend),
        )
        .unwrap_err();
    assert!(matches!(
        err,
        LedgerInsertError::State(LedgerError::NonFinalRelativeSequence { sequence: 5, .. })
    ));

    // And the absolute clock alone rejects when it is the unmet one:
    // n_lock_time = 10, sequence = 0. At height 5 → NonFinalTransaction.
    let (mut ledger2, coin2) = funded_ledger(owner.address(), 1_000);
    extend_chain(&mut ledger2, 4); // tip height 4
    let spend2 = build_multi_input_spend(
        &[(coin2, &owner)],
        vec![TxOutput::native(900, bob)],
        b"cltv-only".to_vec(),
        10,
        0,
    );
    let err = ledger2
        .insert(vec![ledger2.dag().selected_tip()], 1, 0, 0, &[spend2])
        .unwrap_err();
    assert!(matches!(
        err,
        LedgerInsertError::State(LedgerError::NonFinalTransaction {
            n_lock_time: 10,
            ..
        })
    ));
}

#[test]
fn utxo_entry_roundtrip() {
    // Unit-level: entries carry creation height through insert/encode/decode,
    // and the legacy v5 decode yields height 0.
    let owner = generate_key(0).address();
    let output = TxOutput::native(50, owner);
    let op = OutPoint::new(Transaction::coinbase(vec![output], b"x".to_vec()).id(), 0);

    let mut set = UtxoSet::new();
    set.insert_with_height(op, output, 7);
    assert_eq!(set.creation_height(&op), Some(7));
    assert_eq!(set.get_entry(&op).unwrap().output, output);
    assert_eq!(set.get(&op), Some(&output));

    let enc = set.encode();
    assert_eq!(enc.len(), set.encoded_len());
    let mut slice = &enc[..];
    let restored = UtxoSet::decode(&mut slice).unwrap();
    assert_eq!(restored.creation_height(&op), Some(7));
    assert!(slice.is_empty());

    // Strip the per-entry creation-height field → a v5-format payload; decoding
    // it (as legacy checkpoints are) must default creation_height to 0.
    let v5 = &enc[..enc.len() - 8];
    let mut slice5 = v5;
    let legacy = UtxoSet::decode_v5(&mut slice5).unwrap();
    assert_eq!(legacy.creation_height(&op), Some(0));
    assert_eq!(legacy.get(&op), Some(&output));
}

#[test]
fn csv_roundtrip_checkpoint_v6() {
    // Checkpoint v6 persists creation heights; a restored ledger sees them.
    let owner_a = generate_key(0);
    let owner_b = generate_key(1);
    let genesis_cb = Transaction::coinbase(
        vec![TxOutput::native(1_000, owner_a.address())],
        b"genesis".to_vec(),
    );
    let coin_a = OutPoint::new(genesis_cb.id(), 0);
    let mut ledger = Ledger::with_finality(K, SCHEDULE, &[genesis_cb], 3).expect("valid genesis");

    // Mint a second output at height 4 (block heights 1..=4).
    extend_chain(&mut ledger, 3); // tip height 3
    let cb = Transaction::coinbase(
        vec![TxOutput::native(SUBSIDY, owner_b.address())],
        b"h4".to_vec(),
    );
    let coin_b = OutPoint::new(cb.id(), 0);
    ledger
        .insert(vec![ledger.dag().selected_tip()], 1, 0, 0, &[cb])
        .unwrap(); // block height 4
    extend_chain(&mut ledger, 6); // tip height 10; finality 3 → checkpoint at height 7

    let bytes = ledger.write_checkpoint().expect("checkpoint writable");
    let restored = Ledger::read_checkpoint(&bytes).expect("checkpoint readable");

    let cp_state = restored.state(&restored.genesis()).unwrap();
    assert_eq!(cp_state.creation_height(&coin_a), Some(0));
    assert_eq!(cp_state.creation_height(&coin_b), Some(4));
}
// =========================================================================
// Vault template (RFC-005 §4) — 13 tests
// =========================================================================

#[test]
fn vault_locked_rejected() {
    // unlock 50 / csv 20; spend at height 10 → absolute lock not reached.
    let script = make_vault(0, 50, 20);
    let owner = generate_key(0);
    let bob = generate_key(1).address();
    let (mut ledger, coin) = vault_funded_ledger(&script, 1_000);

    extend_chain(&mut ledger, 9); // tip height 9
    let spend = build_vault_spend(
        coin,
        &script,
        &owner,
        vec![TxOutput::native(900, bob)],
        b"locked".to_vec(),
        0,
        0,
    );
    let err = ledger
        .insert(vec![ledger.dag().selected_tip()], 1, 0, 0, &[spend])
        .unwrap_err();
    assert!(matches!(
        err,
        LedgerInsertError::State(LedgerError::VaultAbsoluteNotReached {
            required: 50,
            block_height: 10,
            ..
        })
    ));
}

#[test]
fn vault_absolute_unlock() {
    // unlock = 5, csv = 0: spent exactly at height 5, rejected one early.
    let script = make_vault(0, 5, 0);
    let owner = generate_key(0);
    let bob = generate_key(1).address();
    let (mut ledger, coin) = vault_funded_ledger(&script, 1_000);

    let spend = build_vault_spend(
        coin,
        &script,
        &owner,
        vec![TxOutput::native(900, bob)],
        b"abs".to_vec(),
        0,
        0,
    );

    extend_chain(&mut ledger, 3); // tip height 3
    let err = ledger
        .insert(
            vec![ledger.dag().selected_tip()],
            1,
            0,
            0,
            std::slice::from_ref(&spend),
        )
        .unwrap_err();
    assert!(matches!(
        err,
        LedgerInsertError::State(LedgerError::VaultAbsoluteNotReached {
            required: 5,
            block_height: 4,
            ..
        })
    ));

    extend_chain(&mut ledger, 1); // tip height 4
    ledger
        .insert(vec![ledger.dag().selected_tip()], 1, 0, 0, &[spend])
        .expect("unlock height reached");
    let utxo = ledger.state(&ledger.dag().selected_tip()).unwrap();
    assert_eq!(utxo.balance(&bob), 900);
}

#[test]
fn vault_relative_unlock() {
    // csv = 5, unlock = 0: output created at height 0 must age 5 blocks.
    let script = make_vault(0, 0, 5);
    let owner = generate_key(0);
    let bob = generate_key(1).address();
    let (mut ledger, coin) = vault_funded_ledger(&script, 1_000);

    let spend = build_vault_spend(
        coin,
        &script,
        &owner,
        vec![TxOutput::native(900, bob)],
        b"rel".to_vec(),
        0,
        0,
    );

    extend_chain(&mut ledger, 3); // tip height 3
    let err = ledger
        .insert(
            vec![ledger.dag().selected_tip()],
            1,
            0,
            0,
            std::slice::from_ref(&spend),
        )
        .unwrap_err();
    assert!(matches!(
        err,
        LedgerInsertError::State(LedgerError::VaultRelativeNotReached {
            required: 5,
            creation_height: 0,
            block_height: 4,
            ..
        })
    ));

    extend_chain(&mut ledger, 1); // tip height 4
    ledger
        .insert(vec![ledger.dag().selected_tip()], 1, 0, 0, &[spend])
        .expect("relative age reached");
    let utxo = ledger.state(&ledger.dag().selected_tip()).unwrap();
    assert_eq!(utxo.balance(&bob), 900);
}

#[test]
fn vault_both_locks_required() {
    // unlock = 5 / csv = 10: at height 8 the absolute clock has passed but the
    // relative clock has not → VaultRelativeNotReached (not just the absolute).
    let script = make_vault(0, 5, 10);
    let owner = generate_key(0);
    let bob = generate_key(1).address();
    let (mut ledger, coin) = vault_funded_ledger(&script, 1_000);

    let spend = build_vault_spend(
        coin,
        &script,
        &owner,
        vec![TxOutput::native(900, bob)],
        b"both".to_vec(),
        0,
        0,
    );

    // Tip height 7 → spend height 8: absolute 8>=5 ✓, relative 8 < 0+10 ✗.
    extend_chain(&mut ledger, 7);
    let err = ledger
        .insert(
            vec![ledger.dag().selected_tip()],
            1,
            0,
            0,
            std::slice::from_ref(&spend),
        )
        .unwrap_err();
    assert!(matches!(
        err,
        LedgerInsertError::State(LedgerError::VaultRelativeNotReached { required: 10, .. })
    ));

    // Tip height 9 → spend height 10: both clocks pass.
    extend_chain(&mut ledger, 2);
    ledger
        .insert(vec![ledger.dag().selected_tip()], 1, 0, 0, &[spend])
        .expect("both locks elapsed");
}

#[test]
fn vault_no_lock_invalid() {
    // A vault with no locks at all is rejected at parse/construct.
    let owner_pk = *generate_key(0).address().payload();
    assert_eq!(
        VaultScript::new(0, 0, owner_pk),
        Err(VaultScriptError::NoLock)
    );
    assert_eq!(
        VaultScript::parse(&[0u8; 40]),
        Err(VaultScriptError::NoLock)
    );
}

#[test]
fn vault_witness_count() {
    // A spend must carry exactly [template, owner_sig]: 2 elements.
    let script = make_vault(0, 1, 0);
    let owner = generate_key(0);
    let bob = generate_key(1).address();
    let (mut ledger, coin) = vault_funded_ledger(&script, 1_000);

    let mut spend = build_vault_spend(
        coin,
        &script,
        &owner,
        vec![TxOutput::native(900, bob)],
        b"wcount".to_vec(),
        0,
        0,
    );
    spend.inputs_mut()[0].witness = vec![script.bytes().to_vec()]; // only template
    let err = ledger
        .insert(vec![ledger.dag().selected_tip()], 1, 0, 0, &[spend])
        .unwrap_err();
    assert!(matches!(
        err,
        LedgerInsertError::State(LedgerError::InvalidWitnessCount {
            expected: 2,
            actual: 1,
            ..
        })
    ));
}

#[test]
fn vault_bad_script_hash() {
    // A tampered template (same length, valid parse, different bytes) does not
    // hash to the owner address → ScriptHashMismatch, before any lock logic.
    let script = make_vault(0, 5, 0);
    let owner = generate_key(0);
    let bob = generate_key(1).address();
    let (mut ledger, coin) = vault_funded_ledger(&script, 1_000);

    // Same shape, different key → different hash → different address.
    let forged = make_vault(7, 5, 0);
    assert_ne!(script.address(), forged.address());

    let mut spend = build_vault_spend(
        coin,
        &script,
        &owner,
        vec![TxOutput::native(900, bob)],
        b"forged".to_vec(),
        0,
        0,
    );
    spend.inputs_mut()[0].witness = forged.spend_witness([0x11u8; 64]);
    let err = ledger
        .insert(vec![ledger.dag().selected_tip()], 1, 0, 0, &[spend])
        .unwrap_err();
    assert!(matches!(
        err,
        LedgerInsertError::State(LedgerError::ScriptHashMismatch { .. })
    ));
}

#[test]
fn vault_tampered_template() {
    // Flipping one byte of the template fields keeps the length and parse intact
    // but changes the hash → ScriptHashMismatch. This is the relay-replay /
    // witness-confusion adversarial vector beyond bad_script_hash: every byte of
    // the template is committed to by BLAKE3.
    let script = make_vault(0, 100, 0);
    let owner = generate_key(0);
    let bob = generate_key(1).address();
    let (mut ledger, coin) = vault_funded_ledger(&script, 1_000);

    let mut tpl = script.bytes();
    tpl[0] ^= 0x01; // unlock_height 100 -> 101
    assert_ne!(
        VaultScript::parse(&tpl).unwrap().address(),
        script.address()
    );

    let mut spend = build_vault_spend(
        coin,
        &script,
        &owner,
        vec![TxOutput::native(900, bob)],
        b"tamper".to_vec(),
        0,
        0,
    );
    spend.inputs_mut()[0].witness[0] = tpl.to_vec();
    let err = ledger
        .insert(vec![ledger.dag().selected_tip()], 1, 0, 0, &[spend])
        .unwrap_err();
    assert!(matches!(
        err,
        LedgerInsertError::State(LedgerError::ScriptHashMismatch { .. })
    ));
}

#[test]
fn vault_bad_signature() {
    // Correct template, wrong owner signature → BadSignature (only checked
    // after both locks have elapsed).
    let script = make_vault(0, 1, 0);
    let thief = generate_key(9);
    let bob = generate_key(1).address();
    let (mut ledger, coin) = vault_funded_ledger(&script, 1_000);

    let spend = build_vault_spend(
        coin,
        &script,
        &thief,
        vec![TxOutput::native(900, bob)],
        b"forgery".to_vec(),
        0,
        0,
    );
    let err = ledger
        .insert(vec![ledger.dag().selected_tip()], 1, 0, 0, &[spend])
        .unwrap_err();
    assert!(matches!(
        err,
        LedgerInsertError::State(LedgerError::BadSignature { .. })
    ));
}

#[test]
fn vault_pre_activation_rejected() {
    // With VAULT_ACTIVATION_SCORE raised, both the 0x05 output *gate* and the
    // 0x05 spend *gate* fail pre-activation; post-activation spending works.
    let script = make_vault(0, 1, 0); // unlock at 1, no csv
    let owner = generate_key(0); // template owner (seed 0)
    let funder = generate_key(2);
    let bob = generate_key(1).address();

    // Genesis coinbase: P2PK to funder (index 0) AND a vault output (index 1).
    // Coinbase outputs are exempt from the output gate (like HTLC), so the
    // vault coin exists from height 0 and pre-activation *spends* are directly
    // exercised too. Total = subsidy (1_000).
    let coinbase = Transaction::coinbase(
        vec![
            TxOutput::native(500, funder.address()),
            TxOutput::native(500, script.address()),
        ],
        b"genesis".to_vec(),
    );
    let funder_coin = OutPoint::new(coinbase.id(), 0);
    let vault_coin = OutPoint::new(coinbase.id(), 1);
    let mut ledger = Ledger::new(K, SCHEDULE, &[coinbase]).expect("valid genesis");
    ledger.set_vault_activation_score(2); // pre-activation: blue score <= 2

    // Pre-activation vault SPEND → PreActivationVault (blue 1 <= 2).
    let spend = build_vault_spend(
        vault_coin,
        &script,
        &owner,
        vec![TxOutput::native(400, bob)],
        b"pre-spend".to_vec(),
        0,
        0,
    );
    let err = ledger
        .insert(vec![ledger.dag().selected_tip()], 1, 0, 0, &[spend])
        .unwrap_err();
    assert!(matches!(
        err,
        LedgerInsertError::State(LedgerError::PreActivationVault {
            blue_score: 1,
            activation_score: 2,
            ..
        })
    ));

    // Pre-activation vault OUTPUT (a regular tx to the vault address) →
    // PreActivationVault as well.
    let to_vault = Transaction::signed(
        &[(funder_coin, &funder)],
        vec![TxOutput::native(400, script.address())],
        b"pre-out".to_vec(),
    );
    let err = ledger
        .insert(vec![ledger.dag().selected_tip()], 1, 0, 0, &[to_vault])
        .unwrap_err();
    assert!(matches!(
        err,
        LedgerInsertError::State(LedgerError::PreActivationVault {
            blue_score: 1,
            activation_score: 2,
            ..
        })
    ));

    // Tip is still at genesis after the two rejections. Advance to blue 2
    // (blocks at heights 1..=2, no vault txs).
    extend_chain(&mut ledger, 2);

    // Post-activation (blue 3 > 2): the genesis vault coin spends fine.
    let spend = build_vault_spend(
        vault_coin,
        &script,
        &owner,
        vec![TxOutput::native(400, bob)],
        b"post-spend".to_vec(),
        0,
        0,
    );
    ledger
        .insert(vec![ledger.dag().selected_tip()], 1, 0, 0, &[spend])
        .expect("post-activation vault spend");
    let utxo = ledger.state(&ledger.dag().selected_tip()).unwrap();
    assert_eq!(utxo.balance(&bob), 400);
}

#[test]
fn vault_parallel_dag_conflict() {
    // Two parallel blocks spend the SAME vault coin; each is valid in its own
    // view (the coin is unspent in both) → both admitted; the selected tip
    // resolves the double spend deterministically.
    let script = make_vault(0, 1, 0);
    let owner = generate_key(0);
    let (mut ledger, coin) = vault_funded_ledger(&script, 1_000);
    let genesis_id = ledger.dag().selected_tip();

    let alice = generate_key(1).address();
    let bob = generate_key(2).address();

    let a = build_vault_spend(
        coin,
        &script,
        &owner,
        vec![TxOutput::native(900, alice)],
        b"a".to_vec(),
        0,
        0,
    );
    let id_a = ledger.insert(vec![genesis_id], 1, 0, 0, &[a]).unwrap();

    let b = build_vault_spend(
        coin,
        &script,
        &owner,
        vec![TxOutput::native(900, bob)],
        b"b".to_vec(),
        0,
        0,
    );
    let id_b = ledger.insert(vec![genesis_id], 1, 0, 0, &[b]).unwrap();

    assert!(ledger.dag().contains(&id_a));
    assert!(ledger.dag().contains(&id_b));

    let utxo = ledger.state(&ledger.dag().selected_tip()).unwrap();
    assert_eq!(utxo.balance(&alice) + utxo.balance(&bob), 900);
}

#[test]
fn vault_snapshot_roundtrip() {
    // A snapshot replays blocks, so creation heights are recomputed, not
    // stored: a restored ledger still spends the vault after the relative age.
    let script = make_vault(0, 0, 5);
    let owner = generate_key(0);
    let bob = generate_key(1).address();
    let (mut ledger, coin) = vault_funded_ledger(&script, 1_000);
    extend_chain(&mut ledger, 5); // tip height 5

    let snap = ledger.write_snapshot();
    let mut restored = Ledger::read_snapshot(&snap).expect("snapshot readable");
    let utxo = restored.state(&restored.dag().selected_tip()).unwrap();
    assert_eq!(utxo.balance(&script.address()), 1_000);

    // The restored ledger knows the vault output was created at height 0 and
    // has now aged 5 blocks → spend works.
    let spend = build_vault_spend(
        coin,
        &script,
        &owner,
        vec![TxOutput::native(900, bob)],
        b"restored".to_vec(),
        0,
        0,
    );
    restored
        .insert(vec![restored.dag().selected_tip()], 1, 0, 0, &[spend])
        .expect("restored creation heights intact");
    let utxo = restored.state(&restored.dag().selected_tip()).unwrap();
    assert_eq!(utxo.balance(&bob), 900);
}

// =========================================================================
// Adversarial (RFC-005 §6) — 4 tests
// =========================================================================

#[test]
fn csv_understate_sequence() {
    // Vault demands csv = 2; spender declares only sequence = 1. The ledger's
    // tx-level CSV lets the tx through from height 1, but the *vault* branch
    // still requires creation + 2 → VaultRelativeNotReached. Declaring a
    // smaller tx sequence cannot outrun the vault's own lock.
    let script = make_vault(0, 0, 2);
    let owner = generate_key(0);
    let bob = generate_key(1).address();
    let (mut ledger, coin) = vault_funded_ledger(&script, 1_000);

    let spend = build_vault_spend(
        coin,
        &script,
        &owner,
        vec![TxOutput::native(900, bob)],
        b"understate".to_vec(),
        0,
        1,
    );
    let err = ledger
        .insert(vec![ledger.dag().selected_tip()], 1, 0, 0, &[spend])
        .unwrap_err();
    assert!(matches!(
        err,
        LedgerInsertError::State(LedgerError::VaultRelativeNotReached {
            required: 2,
            creation_height: 0,
            block_height: 1,
            ..
        })
    ));
}

#[test]
fn csv_grind_creation() {
    // Creation heights are a pure function of the DAG: the incremental Ledger
    // and the batch apply_dag path must agree on every entry's creation height,
    // so an adversary cannot grind a UTXO to "look" created earlier than its
    // linearization position by reordering parallel blocks.
    let miner = generate_key(1);
    let owner = generate_key(2);
    let miner_addr = miner.address();
    let owner_addr = owner.address();

    let genesis_cb = Transaction::coinbase(
        vec![TxOutput::native(SUBSIDY, miner_addr)],
        b"genesis".to_vec(),
    );
    let genesis_id = genesis_cb.id();
    // fund owner from genesis via block 1
    let fund = Transaction::signed(
        &[(OutPoint::new(genesis_id, 0), &miner)],
        vec![TxOutput::native(500, owner_addr)],
        b"fund".to_vec(),
    );
    let merger_tx = Transaction::signed(
        &[(OutPoint::new(fund.id(), 0), &owner)],
        vec![TxOutput::native(400, miner_addr)],
        b"m".to_vec(),
    );

    // Build the raw DAG: genesis -> b1 (funds owner); two parallel blocks b2/b3
    // (no txs) both reference b1; merger m references both.
    let genesis = Block::genesis(
        1,
        0,
        0,
        encode_block_payload(std::slice::from_ref(&genesis_cb)),
    );
    let gid = genesis.id();
    let b1 = Block::new(
        vec![gid],
        1,
        1,
        0,
        encode_block_payload(std::slice::from_ref(&fund)),
    );
    let b1_id = b1.id();
    let b2 = Block::new(vec![b1_id], 1, 2, 0, encode_block_payload(&[]));
    let b2_id = b2.id();
    let b3 = Block::new(vec![b1_id], 1, 2, 1, encode_block_payload(&[]));
    let b3_id = b3.id();
    let merger = Block::new(
        vec![b2_id, b3_id],
        1,
        3,
        0,
        encode_block_payload(std::slice::from_ref(&merger_tx)),
    );
    let mut dag = Dag::new(3, genesis);
    dag.insert(b1).unwrap();
    dag.insert(b2).unwrap();
    dag.insert(b3).unwrap();
    dag.insert(merger).unwrap();

    // Batch path.
    let run = apply_dag(&dag, SUBSIDY);

    // Incremental path: identical structure through Ledger.
    let mut ledger =
        Ledger::new(K, SCHEDULE, std::slice::from_ref(&genesis_cb)).expect("valid genesis");
    let _ = ledger
        .insert(vec![gid], 1, 1, 0, std::slice::from_ref(&fund))
        .unwrap();
    let b2_id_inc = ledger.insert(vec![b1_id], 1, 2, 0, &[]).unwrap();
    let b3_id_inc = ledger.insert(vec![b1_id], 1, 2, 1, &[]).unwrap();
    let _ = ledger
        .insert(
            vec![b2_id_inc, b3_id_inc],
            1,
            3,
            0,
            std::slice::from_ref(&merger_tx),
        )
        .unwrap();

    // The merged-block's own creations and the merger's outputs must carry the
    // same creation heights under both paths: outpoints reference *transaction*
    // ids (not block ids), so the height of the block that carried them is the
    // only thing compared.
    let owner_out = OutPoint::new(fund.id(), 0);
    let merger_out = OutPoint::new(merger_tx.id(), 0);
    let inc = ledger.ledger_state();
    assert_eq!(
        run.utxo.creation_height(&owner_out),
        inc.creation_height(&owner_out),
        "creation height of b1's output must agree"
    );
    assert_eq!(
        run.utxo.creation_height(&merger_out),
        inc.creation_height(&merger_out),
        "creation height of the merger's output must agree"
    );
}

#[test]
fn vault_relay_replay() {
    // A redeemed vault output is removed from the UTXO set — re-spending it
    // (replaying the same witness from an old relay capture) is MissingInput.
    let script = make_vault(0, 1, 0);
    let owner = generate_key(0);
    let bob = generate_key(1).address();
    let (mut ledger, coin) = vault_funded_ledger(&script, 1_000);

    let spend = build_vault_spend(
        coin,
        &script,
        &owner,
        vec![TxOutput::native(900, bob)],
        b"relay".to_vec(),
        0,
        0,
    );
    ledger
        .insert(
            vec![ledger.dag().selected_tip()],
            1,
            0,
            0,
            std::slice::from_ref(&spend),
        )
        .expect("first spend");

    // Same exact transaction bytes (and thus same id) replayed:
    let err = ledger
        .insert(vec![ledger.dag().selected_tip()], 1, 0, 0, &[spend])
        .unwrap_err();
    assert!(matches!(
        err,
        LedgerInsertError::State(LedgerError::MissingInput(_))
    ));
}

#[test]
fn pipeline_csv_after_relay_replay() {
    // Sanity: a relayed/replayed *vault tx* that declares a non-final sequence
    // still has to wait for the tx-level CSV even when the vault's own locks
    // have elapsed.
    let script = make_vault(0, 0, 1);
    let owner = generate_key(0);
    let bob = generate_key(1).address();
    let (mut ledger, coin) = vault_funded_ledger(&script, 1_000);

    let spend = build_vault_spend(
        coin,
        &script,
        &owner,
        vec![TxOutput::native(900, bob)],
        b"csv-relay".to_vec(),
        0,
        2,
    );
    let err = ledger
        .insert(
            vec![ledger.dag().selected_tip()],
            1,
            0,
            0,
            std::slice::from_ref(&spend),
        )
        .unwrap_err();
    assert!(matches!(
        err,
        LedgerInsertError::State(LedgerError::NonFinalRelativeSequence {
            creation_height: 0,
            sequence: 2,
            block_height: 1,
            ..
        })
    ));

    // After it has aged 2 blocks, the vault's own lock (csv 1) is already
    // satisfied and the same tx succeeds.
    extend_chain(&mut ledger, 1); // tip height 1
    ledger
        .insert(vec![ledger.dag().selected_tip()], 1, 0, 0, &[spend])
        .expect("both the tx-level CSV and vault lock reached");
}

/// Keep `VAULT_ACTIVATION_SCORE` import meaningful (it is the default exposed
/// through the crate API).
#[test]
fn activation_default_is_zero() {
    assert_eq!(VAULT_ACTIVATION_SCORE, 0);
}
