//! RFC-003 consensus test suite: stealth addresses + script v2 opcodes.
//!
//! 25 tests: 12 stealth + 13 script v2.
//!
//! Stealth (RFC-003): outputs locked to a v0x03 address carry a `StealthExt`
//! (`R`, `view_tag`, `P`); spends are authorised by exactly one 64-byte
//! signature over the sighash, verified against the derived one-time pubkey `P`.
//!
//! Script v2 (RFC-003): outputs locked to a v0x02 address (BLAKE3 of the
//! program); spends carry `witness[0] = script bytes` and the ledger executes
//! the program against the remaining witness elements with lock-time/sequence
//! context (BIP-65 CLTV / BIP-112 CSV semantics).
//!
//! Activation gating: `blue_score <= activation_score` is pre-activation for
//! both features (outputs and spends rejected). Genesis is blue score 0; the
//! first inserted block is blue score 1. Coinbase outputs are exempt from the
//! stealth/script-v2 output gates (mirroring the native-token coinbase
//! exemption), so genesis can fund a stealth or script-v2 address directly.

use ed25519_dalek::Signer as _;
use kovanica_state::ledger::STEALTH_ACTIVATION_SCORE;
use kovanica_state::script_v2::ScriptV2;
use kovanica_state::{
    apply_block, Address, HalvingSchedule, KeyPair, Ledger, LedgerError, LedgerInsertError,
    OutPoint, StealthAddress, StealthExt, Transaction, TxInput, TxOutput, UtxoSet,
    DEFAULT_HALVING_ERA,
};

const K: u16 = 3;
const SUBSIDY: u64 = 1_000;
const SCHEDULE: HalvingSchedule = HalvingSchedule::new(SUBSIDY, DEFAULT_HALVING_ERA);

/// Fixed ephemeral secret for deterministic stealth derivations.
const R_SECRET: [u8; 32] = [0x42u8; 32];

fn generate_key(count: usize) -> KeyPair {
    KeyPair::from_u64((1000 + count) as u64)
}

/// A deterministic stealth recipient from two keypairs.
fn make_recipient(scan_idx: usize, spend_idx: usize) -> StealthAddress {
    let scan_kp = generate_key(scan_idx);
    let spend_kp = generate_key(spend_idx);
    StealthAddress::new(*scan_kp.address().payload(), *spend_kp.address().payload())
}

/// Build a stealth output for `recipient` using the fixed ephemeral secret.
fn make_stealth_output(value: u64, recipient: &StealthAddress) -> TxOutput {
    let ext = recipient
        .derive_output(&R_SECRET)
        .expect("valid derivation");
    TxOutput::stealth(value, recipient.address(), ext)
}

/// Build a stealth spend: witness = exactly one 64-byte signature over the
/// sighash, signed by the one-time key derived from `spend_kp` and `ext.r`.
fn build_stealth_spend(
    outpoint: OutPoint,
    spend_kp: &KeyPair,
    ext: &StealthExt,
    outputs: Vec<TxOutput>,
    tag: Vec<u8>,
) -> Transaction {
    let dummy_input = TxInput {
        outpoint,
        witness: Vec::new(),
    };
    let mut tx = Transaction::new(vec![dummy_input], outputs, tag);
    let sighash = tx.sighash();
    let one_time_sk =
        StealthAddress::derive_one_time_key(&spend_kp.seed(), &ext.r).expect("valid one-time key");
    let sig = one_time_sk.sign(&sighash).to_bytes();
    tx.inputs_mut()[0].witness = vec![sig.to_vec()];
    tx
}

/// Build a script v2 spend: witness = [script_bytes, elem_1, ...].
fn build_script_v2_spend(
    outpoint: OutPoint,
    script: Vec<u8>,
    witness_elems: Vec<Vec<u8>>,
    outputs: Vec<TxOutput>,
    tag: Vec<u8>,
) -> Transaction {
    let dummy_input = TxInput {
        outpoint,
        witness: Vec::new(),
    };
    let mut tx = Transaction::new(vec![dummy_input], outputs, tag);
    let mut witness = Vec::with_capacity(1 + witness_elems.len());
    witness.push(script);
    witness.extend(witness_elems);
    tx.inputs_mut()[0].witness = witness;
    tx
}

/// Build a script v2 spend with explicit lock time and sequence.
fn build_script_v2_spend_with_lock(
    outpoint: OutPoint,
    script: Vec<u8>,
    witness_elems: Vec<Vec<u8>>,
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
    let mut witness = Vec::with_capacity(1 + witness_elems.len());
    witness.push(script);
    witness.extend(witness_elems);
    tx.inputs_mut()[0].witness = witness;
    tx
}

/// A ledger whose genesis coinbase funds `owner` with a native P2PK output.
fn funded_ledger(owner: Address, funding: u64) -> (Ledger, OutPoint) {
    let coinbase =
        Transaction::coinbase(vec![TxOutput::native(funding, owner)], b"genesis".to_vec());
    let coin = OutPoint::new(coinbase.id(), 0);
    let ledger = Ledger::new(K, SCHEDULE, &[coinbase]).expect("valid genesis");
    (ledger, coin)
}

/// A ledger whose genesis coinbase funds `recipient` with a stealth output.
fn stealth_funded_ledger(
    recipient: &StealthAddress,
    funding: u64,
) -> (Ledger, OutPoint, StealthExt) {
    let ext = recipient
        .derive_output(&R_SECRET)
        .expect("valid derivation");
    let output = TxOutput::stealth(funding, recipient.address(), ext);
    let coinbase = Transaction::coinbase(vec![output], b"genesis".to_vec());
    let coin = OutPoint::new(coinbase.id(), 0);
    let ledger = Ledger::new(K, SCHEDULE, &[coinbase]).expect("valid genesis");
    (ledger, coin, ext)
}

// =========================================================================
// Stealth (RFC-003) — 12 tests
// =========================================================================

#[test]
fn test_stealth_coinbase_output_created() {
    let recipient = make_recipient(0, 1);

    let mut utxo = UtxoSet::new();
    let output = make_stealth_output(1_000, &recipient);
    let coinbase = Transaction::coinbase(vec![output], b"cb".to_vec());
    let coin = OutPoint::new(coinbase.id(), 0);
    apply_block(&mut utxo, &[coinbase], 1_000).unwrap();

    assert_eq!(utxo.balance(&recipient.address()), 1_000);
    let stored = utxo.get(&coin).expect("stealth output present");
    assert!(stored.is_stealth());
    assert_eq!(stored.stealth.unwrap(), output.stealth.unwrap());
}

#[test]
fn test_stealth_spend_success() {
    let recipient = make_recipient(0, 1);
    let spend_kp = generate_key(1);

    let (mut ledger, coin, ext) = stealth_funded_ledger(&recipient, 1_000);

    let bob = generate_key(2).address();
    let spend = build_stealth_spend(
        coin,
        &spend_kp,
        &ext,
        vec![TxOutput::native(900, bob)],
        b"stealth-spend".to_vec(),
    );
    ledger
        .insert(vec![ledger.dag().selected_tip()], 1, 0, 0, &[spend])
        .unwrap();

    let utxo = ledger.state(&ledger.dag().selected_tip()).unwrap();
    assert_eq!(utxo.balance(&bob), 900);
    assert_eq!(utxo.balance(&recipient.address()), 0);
}

#[test]
fn test_stealth_spend_wrong_key_rejected() {
    let recipient = make_recipient(0, 1);

    let (mut ledger, coin, ext) = stealth_funded_ledger(&recipient, 1_000);

    // A different spend key derives a different one-time key → signature fails
    // against the output's `P`.
    let wrong_kp = generate_key(99);
    let bob = generate_key(2).address();
    let spend = build_stealth_spend(
        coin,
        &wrong_kp,
        &ext,
        vec![TxOutput::native(900, bob)],
        b"wrong-key".to_vec(),
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
fn test_stealth_spend_wrong_witness_count() {
    let recipient = make_recipient(0, 1);

    let (mut ledger, coin, _ext) = stealth_funded_ledger(&recipient, 1_000);

    // Witness with 2 elements instead of exactly 1.
    let bob = generate_key(2).address();
    let dummy_input = TxInput {
        outpoint: coin,
        witness: vec![vec![0u8; 64], vec![0u8; 64]],
    };
    let tx = Transaction::new(
        vec![dummy_input],
        vec![TxOutput::native(900, bob)],
        b"bad-witness".to_vec(),
    );
    let err = ledger
        .insert(vec![ledger.dag().selected_tip()], 1, 0, 0, &[tx])
        .unwrap_err();
    assert!(matches!(
        err,
        LedgerInsertError::State(LedgerError::InvalidWitnessCount {
            expected: 1,
            actual: 2,
            ..
        })
    ));
}

#[test]
fn test_stealth_spend_bad_signature_size() {
    let recipient = make_recipient(0, 1);

    let (mut ledger, coin, _ext) = stealth_funded_ledger(&recipient, 1_000);

    // Witness has 1 element but it is not 64 bytes.
    let bob = generate_key(2).address();
    let dummy_input = TxInput {
        outpoint: coin,
        witness: vec![vec![0u8; 32]],
    };
    let tx = Transaction::new(
        vec![dummy_input],
        vec![TxOutput::native(900, bob)],
        b"bad-sig-size".to_vec(),
    );
    let err = ledger
        .insert(vec![ledger.dag().selected_tip()], 1, 0, 0, &[tx])
        .unwrap_err();
    assert!(matches!(
        err,
        LedgerInsertError::State(LedgerError::BadSignatureSize { len: 32, .. })
    ));
}

#[test]
fn test_stealth_spend_tampered_r() {
    let recipient = make_recipient(0, 1);
    let spend_kp = generate_key(1);

    let (mut ledger, coin, ext) = stealth_funded_ledger(&recipient, 1_000);

    // Tamper with `R` by flipping the X sign bit (byte 31): the result is the
    // valid point `-R`, so derivation succeeds but yields a different one-time
    // key — the ledger verifies against the output's original `P` → fail.
    let mut tampered = ext;
    tampered.r[31] ^= 0x80;
    let bob = generate_key(2).address();
    let spend = build_stealth_spend(
        coin,
        &spend_kp,
        &tampered,
        vec![TxOutput::native(900, bob)],
        b"tampered-r".to_vec(),
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
fn test_stealth_view_tag_matches() {
    let scan_kp = generate_key(0);
    let spend_kp = generate_key(1);
    let recipient =
        StealthAddress::new(*scan_kp.address().payload(), *spend_kp.address().payload());

    let ext = recipient
        .derive_output(&R_SECRET)
        .expect("valid derivation");
    let expected =
        StealthAddress::view_tag_for(&scan_kp.seed(), &ext.r).expect("valid view tag derivation");
    assert_eq!(ext.view_tag, expected);
}

#[test]
fn test_stealth_pre_activation_output_rejected() {
    let recipient = make_recipient(0, 1);
    let funder = generate_key(10);

    let (mut ledger, coin) = funded_ledger(funder.address(), 1_000);
    ledger.set_stealth_activation_score(100);

    // Regular tx creating a stealth output at blue score 1 (<= 100) → rejected.
    let output = make_stealth_output(900, &recipient);
    let tx = Transaction::signed(&[(coin, &funder)], vec![output], b"pre".to_vec());
    let err = ledger
        .insert(vec![ledger.dag().selected_tip()], 1, 0, 0, &[tx])
        .unwrap_err();
    assert!(matches!(
        err,
        LedgerInsertError::State(LedgerError::PreActivationStealth {
            blue_score: 1,
            activation_score: 100,
            ..
        })
    ));
}

#[test]
fn test_stealth_pre_activation_spend_rejected() {
    let recipient = make_recipient(0, 1);
    let spend_kp = generate_key(1);

    // Genesis funds the stealth address (coinbase exempt from the output gate).
    let (mut ledger, coin, ext) = stealth_funded_ledger(&recipient, 1_000);
    ledger.set_stealth_activation_score(100);

    // Spend at blue score 1 (<= 100) → rejected.
    let bob = generate_key(2).address();
    let spend = build_stealth_spend(
        coin,
        &spend_kp,
        &ext,
        vec![TxOutput::native(900, bob)],
        b"pre-spend".to_vec(),
    );
    let err = ledger
        .insert(vec![ledger.dag().selected_tip()], 1, 0, 0, &[spend])
        .unwrap_err();
    assert!(matches!(
        err,
        LedgerInsertError::State(LedgerError::PreActivationStealth {
            blue_score: 1,
            activation_score: 100,
            ..
        })
    ));
}

#[test]
fn test_stealth_activation_boundary() {
    let recipient = make_recipient(0, 1);
    let funder = generate_key(10);

    let (mut ledger, mut coin) = funded_ledger(funder.address(), 1_000);
    ledger.set_stealth_activation_score(2); // activates at blue score > 2

    let mut parent = ledger.dag().selected_tip();

    // Block 1 (blue 1): still pre-activation → stealth output rejected.
    let output = make_stealth_output(900, &recipient);
    let tx_fail = Transaction::signed(&[(coin, &funder)], vec![output], b"b1-fail".to_vec());
    let err = ledger
        .insert(vec![parent], 1, 0, 0, &[tx_fail])
        .unwrap_err();
    assert!(matches!(
        err,
        LedgerInsertError::State(LedgerError::PreActivationStealth {
            blue_score: 1,
            activation_score: 2,
            ..
        })
    ));

    // Valid P2PK tx for Block 1.
    let tx1 = Transaction::signed(
        &[(coin, &funder)],
        vec![TxOutput::native(900, funder.address())],
        b"b1".to_vec(),
    );
    coin = OutPoint::new(tx1.id(), 0);
    parent = ledger.insert(vec![parent], 1, 0, 0, &[tx1]).unwrap();

    // Block 2 (blue 2): still pre-activation (2 <= 2) → rejected.
    let output2 = make_stealth_output(800, &recipient);
    let tx_fail2 = Transaction::signed(&[(coin, &funder)], vec![output2], b"b2-fail".to_vec());
    let err2 = ledger
        .insert(vec![parent], 1, 0, 0, &[tx_fail2])
        .unwrap_err();
    assert!(matches!(
        err2,
        LedgerInsertError::State(LedgerError::PreActivationStealth {
            blue_score: 2,
            activation_score: 2,
            ..
        })
    ));

    // Valid P2PK tx for Block 2.
    let tx2 = Transaction::signed(
        &[(coin, &funder)],
        vec![TxOutput::native(800, funder.address())],
        b"b2".to_vec(),
    );
    coin = OutPoint::new(tx2.id(), 0);
    parent = ledger.insert(vec![parent], 1, 0, 0, &[tx2]).unwrap();

    // Block 3 (blue 3): post-activation (3 > 2) → stealth output accepted.
    let output3 = make_stealth_output(700, &recipient);
    let tx3 = Transaction::signed(&[(coin, &funder)], vec![output3], b"b3".to_vec());
    ledger.insert(vec![parent], 1, 0, 0, &[tx3]).unwrap();

    let utxo = ledger.state(&ledger.dag().selected_tip()).unwrap();
    assert_eq!(utxo.balance(&recipient.address()), 700);
}

#[test]
fn test_stealth_parallel_dag_double_spend() {
    let recipient = make_recipient(0, 1);
    let spend_kp = generate_key(1);

    let (mut ledger, coin, ext) = stealth_funded_ledger(&recipient, 1_000);
    let genesis_id = ledger.dag().selected_tip();

    let alice = generate_key(2).address();
    let bob = generate_key(3).address();

    // Two parallel blocks spending the SAME stealth coin to different recipients.
    let spend_a = build_stealth_spend(
        coin,
        &spend_kp,
        &ext,
        vec![TxOutput::native(900, alice)],
        b"a".to_vec(),
    );
    let id_a = ledger
        .insert(vec![genesis_id], 1, 0, 0, &[spend_a])
        .unwrap();

    let spend_b = build_stealth_spend(
        coin,
        &spend_kp,
        &ext,
        vec![TxOutput::native(900, bob)],
        b"b".to_vec(),
    );
    let id_b = ledger
        .insert(vec![genesis_id], 1, 0, 0, &[spend_b])
        .unwrap();

    // Both are valid in their own view (each sees the coin unspent) → both admitted.
    assert!(ledger.dag().contains(&id_a));
    assert!(ledger.dag().contains(&id_b));

    // The selected tip's state applies only one of the two spends.
    let utxo = ledger.state(&ledger.dag().selected_tip()).unwrap();
    assert_eq!(utxo.balance(&alice) + utxo.balance(&bob), 900);
}

#[test]
fn test_stealth_checkpoint_roundtrip() {
    let recipient = make_recipient(0, 1);
    let spend_kp = generate_key(1);

    // Genesis funds the stealth address (coinbase exempt from the output gate).
    // Finality must be enabled for write_checkpoint.
    let ext = recipient
        .derive_output(&R_SECRET)
        .expect("valid derivation");
    let output = TxOutput::stealth(1_000, recipient.address(), ext);
    let coinbase = Transaction::coinbase(vec![output], b"genesis".to_vec());
    let coin = OutPoint::new(coinbase.id(), 0);
    let mut ledger = Ledger::with_finality(K, SCHEDULE, &[coinbase], 2).expect("valid genesis");
    ledger.set_stealth_activation_score(0);

    // Push the tip past finality depth so finality activates (checkpoint requires it).
    let mut tip = ledger.dag().selected_tip();
    for i in 0..5 {
        let cb = Transaction::coinbase(
            vec![TxOutput::native(1_000, generate_key(10).address())],
            format!("cb{i}").into_bytes(),
        );
        tip = ledger.insert(vec![tip], 1, 0, 0, &[cb]).unwrap();
    }
    assert!(ledger.finality_score() > 0, "finality should be active");

    // Verify the stealth output is still present with its extension.
    let utxo = ledger.state(&ledger.dag().selected_tip()).unwrap();
    assert_eq!(utxo.balance(&recipient.address()), 1_000);
    let stored = utxo.get(&coin).expect("stealth output present");
    assert!(stored.is_stealth());
    assert_eq!(stored.stealth.unwrap(), ext);

    // Write checkpoint (v5: stealth extension in UTXO encoding).
    let buf = ledger.write_checkpoint().unwrap();

    // Read checkpoint into a new ledger.
    let mut restored = Ledger::read_checkpoint(&buf).unwrap();

    // The stealth output survives the round-trip with its extension intact.
    let restored_utxo = restored.state(&restored.dag().selected_tip()).unwrap();
    assert_eq!(restored_utxo.balance(&recipient.address()), 1_000);
    let restored_out = restored_utxo.get(&coin).expect("stealth output present");
    assert!(restored_out.is_stealth());
    assert_eq!(restored_out.stealth.unwrap(), ext);
    assert_eq!(
        restored.stealth_activation_score(),
        STEALTH_ACTIVATION_SCORE
    );

    // And the restored ledger can still spend it.
    let bob = generate_key(2).address();
    let spend = build_stealth_spend(
        coin,
        &spend_kp,
        &ext,
        vec![TxOutput::native(900, bob)],
        b"post-restore".to_vec(),
    );
    restored
        .insert(vec![restored.dag().selected_tip()], 1, 0, 0, &[spend])
        .unwrap();
    let final_utxo = restored.state(&restored.dag().selected_tip()).unwrap();
    assert_eq!(final_utxo.balance(&bob), 900);
}

// =========================================================================
// Script v2 (RFC-003) — 13 tests
// =========================================================================

#[test]
fn test_script_v2_single_sig_spend() {
    let alice = generate_key(0);
    let bob = generate_key(1);

    // Script: ED25519_VERIFY (0x01). Witness: [script, pk, sig] (pk pushed
    // first, sig on top — the opcode pops sig, then pk).
    let script = vec![0x01];
    let script_addr = Address::from_script_v2(&script);

    let (mut ledger, coin) = funded_ledger(script_addr, 1_000);

    let dummy_input = TxInput {
        outpoint: coin,
        witness: Vec::new(),
    };
    let mut tx = Transaction::new(
        vec![dummy_input],
        vec![TxOutput::native(900, bob.address())],
        b"sv2".to_vec(),
    );
    let sighash = tx.sighash();
    tx.inputs_mut()[0].witness = vec![
        script,
        alice.address().payload().to_vec(),
        alice.sign(&sighash).to_vec(),
    ];

    ledger
        .insert(vec![ledger.dag().selected_tip()], 1, 0, 0, &[tx])
        .unwrap();

    let utxo = ledger.state(&ledger.dag().selected_tip()).unwrap();
    assert_eq!(utxo.balance(&bob.address()), 900);
    assert_eq!(utxo.balance(&script_addr), 0);
}

#[test]
fn test_script_v2_cltv_spend() {
    let bob = generate_key(1);

    // Script: CHECKLOCKTIMEVERIFY (0x02). Witness: [script, v, truthy].
    let script = vec![0x02];
    let script_addr = Address::from_script_v2(&script);

    let (mut ledger, coin) = funded_ledger(script_addr, 1_000);

    // Real CLTV semantics (BIP-65/BIP-113): the block's height (1) must be
    // >= n_lock_time (1) >= v (1). n_lock_time = 1, v = 1 → passes.
    let spend = build_script_v2_spend_with_lock(
        coin,
        script,
        vec![vec![1u8], 1u32.to_le_bytes().to_vec()],
        vec![TxOutput::native(900, bob.address())],
        b"cltv".to_vec(),
        1,
        0,
    );

    ledger
        .insert(vec![ledger.dag().selected_tip()], 1, 0, 0, &[spend])
        .unwrap();

    let utxo = ledger.state(&ledger.dag().selected_tip()).unwrap();
    assert_eq!(utxo.balance(&bob.address()), 900);
}

#[test]
fn test_script_v2_cltv_rejected() {
    let bob = generate_key(1);

    let script = vec![0x02];
    let script_addr = Address::from_script_v2(&script);

    let (mut ledger, coin) = funded_ledger(script_addr, 1_000);

    // Real CLTV semantics (BIP-65/BIP-113): at block height 1, n_lock_time = 1
    // is final (1 <= 1), but the script check n_lock_time >= v fails for v = 2
    // → LockTimeViolation → BadSignature.
    let spend = build_script_v2_spend_with_lock(
        coin,
        script,
        vec![vec![1u8], 2u32.to_le_bytes().to_vec()],
        vec![TxOutput::native(900, bob.address())],
        b"cltv-fail".to_vec(),
        1,
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
fn test_script_v2_csv_spend() {
    let bob = generate_key(1);

    // Script: CHECKSEQUENCEVERIFY (0x03). Witness: [script, v, truthy].
    let script = vec![0x03];
    let script_addr = Address::from_script_v2(&script);

    let (mut ledger, coin) = funded_ledger(script_addr, 1_000);

    // RFC-005 made CSV *real*: `sequence` now also requires the output to have
    // aged that many blocks since its creation (genesis height 0 here). Advance
    // the chain 100 blocks so both the script (seq >= v) and the relative age
    // (block_height >= creation_height + seq) are satisfied.
    for _ in 0..100 {
        ledger
            .insert(vec![ledger.dag().selected_tip()], 1, 0, 0, &[])
            .unwrap();
    }

    // sequence = 100 >= v = 50 → script passes, and CSV is satisfied at height 101.
    let spend = build_script_v2_spend_with_lock(
        coin,
        script,
        vec![vec![1u8], 50u32.to_le_bytes().to_vec()],
        vec![TxOutput::native(900, bob.address())],
        b"csv".to_vec(),
        0,
        100,
    );

    ledger
        .insert(vec![ledger.dag().selected_tip()], 1, 0, 0, &[spend])
        .unwrap();

    let utxo = ledger.state(&ledger.dag().selected_tip()).unwrap();
    assert_eq!(utxo.balance(&bob.address()), 900);
}

#[test]
fn test_script_v2_csv_rejected() {
    let bob = generate_key(1);

    let script = vec![0x03];
    let script_addr = Address::from_script_v2(&script);

    let (mut ledger, coin) = funded_ledger(script_addr, 1_000);

    // sequence = 50 < v = 100 → the *script* would reject (SequenceViolation →
    // BadSignature), but with RFC-005 real CSV the ledger's relative-age rule
    // fires first: the coin (created at height 0) has not yet aged 50 blocks, so
    // the spend is non-final and the script never runs.
    let spend = build_script_v2_spend_with_lock(
        coin,
        script.clone(),
        vec![vec![1u8], 100u32.to_le_bytes().to_vec()],
        vec![TxOutput::native(900, bob.address())],
        b"csv-fail".to_vec(),
        0,
        50,
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
        LedgerInsertError::State(LedgerError::NonFinalRelativeSequence { .. })
    ));

    // Once the relative age is reached (block height >= 50), CSV passes and the
    // spend is handed to the script, which still rejects: declared sequence
    // 50 < v 100 → SequenceViolation → BadSignature.
    for _ in 0..50 {
        ledger
            .insert(vec![ledger.dag().selected_tip()], 1, 0, 0, &[])
            .unwrap();
    }
    let err = ledger
        .insert(vec![ledger.dag().selected_tip()], 1, 0, 0, &[spend])
        .unwrap_err();
    assert!(matches!(
        err,
        LedgerInsertError::State(LedgerError::BadSignature { .. })
    ));
}

#[test]
fn test_script_v2_hash_equal() {
    let bob = generate_key(1);

    // Script: HASH_BLAKE3 (0x04) + EQUAL (0x05).
    let script = vec![0x04, 0x05];
    let script_addr = Address::from_script_v2(&script);

    let (mut ledger, coin) = funded_ledger(script_addr, 1_000);

    let preimage = b"kovanica".to_vec();
    let expected = blake3::hash(&preimage).as_bytes().to_vec();

    // Witness: [script, expected, preimage] — HASH_BLAKE3 pops the preimage
    // (top), EQUAL then compares the pushed hash against `expected`.
    let spend = build_script_v2_spend(
        coin,
        script,
        vec![expected, preimage],
        vec![TxOutput::native(900, bob.address())],
        b"hash-eq".to_vec(),
    );

    ledger
        .insert(vec![ledger.dag().selected_tip()], 1, 0, 0, &[spend])
        .unwrap();

    let utxo = ledger.state(&ledger.dag().selected_tip()).unwrap();
    assert_eq!(utxo.balance(&bob.address()), 900);
}

#[test]
fn test_script_v2_and_or() {
    let bob = generate_key(1);

    // Script: AND (0x06) then OR (0x07).
    let script = vec![0x06, 0x07];
    let script_addr = Address::from_script_v2(&script);

    let (mut ledger, coin) = funded_ledger(script_addr, 1_000);

    // Witness: [script, a=1, b=1, c=0] → (1 AND 1) OR 0 = 1 → truthy.
    let spend = build_script_v2_spend(
        coin,
        script,
        vec![vec![1u8], vec![1u8], vec![0u8]],
        vec![TxOutput::native(900, bob.address())],
        b"and-or".to_vec(),
    );

    ledger
        .insert(vec![ledger.dag().selected_tip()], 1, 0, 0, &[spend])
        .unwrap();

    let utxo = ledger.state(&ledger.dag().selected_tip()).unwrap();
    assert_eq!(utxo.balance(&bob.address()), 900);
}

/// THRESHOLD (0x08) carries its signatures inline in the script, so the script
/// bytes depend on the sighash, which depends on the funding outpoint, which
/// depends on the script hash — a fixed-point cycle that cannot be resolved
/// through the ledger. These tests exercise the exact `ScriptV2::execute` path
/// the ledger calls (with the real sighash as the message).
#[test]
fn test_script_v2_threshold_2of3() {
    let kp1 = generate_key(0);
    let kp2 = generate_key(1);
    let kp3 = generate_key(2);

    let msg = b"threshold sighash";
    let sig1 = kp1.sign(msg);
    let sig2 = kp2.sign(msg);

    // 2-of-3 threshold: M=2, N=3, 2 valid sigs + 3 pubkeys.
    let mut script_bytes = vec![0x08, 0x02, 0x03];
    script_bytes.extend_from_slice(&sig1);
    script_bytes.extend_from_slice(&sig2);
    script_bytes.extend_from_slice(&[0u8; 64]); // third sig invalid
    for kp in [&kp1, &kp2, &kp3] {
        script_bytes.extend_from_slice(kp.address().payload());
    }

    let script = ScriptV2::new(&script_bytes).expect("valid threshold script");
    let result = script.execute(msg, &[], 0, 0).expect("executes");
    assert!(result);
}

#[test]
fn test_script_v2_threshold_not_met() {
    let kp1 = generate_key(0);
    let kp2 = generate_key(1);
    let kp3 = generate_key(2);

    let msg = b"threshold sighash";
    let sig1 = kp1.sign(msg);

    // 2-of-3 threshold with only 1 valid signature → ThresholdNotMet.
    let mut script_bytes = vec![0x08, 0x02, 0x03];
    script_bytes.extend_from_slice(&sig1);
    script_bytes.extend_from_slice(&[0u8; 64]);
    script_bytes.extend_from_slice(&[0u8; 64]);
    for kp in [&kp1, &kp2, &kp3] {
        script_bytes.extend_from_slice(kp.address().payload());
    }

    let script = ScriptV2::new(&script_bytes).expect("valid threshold script");
    let result = script.execute(msg, &[], 0, 0);
    assert!(result.is_err(), "threshold not met must fail");
}

#[test]
fn test_script_v2_script_hash_mismatch() {
    let bob = generate_key(1);

    let script = vec![0x01];
    let script_addr = Address::from_script_v2(&script);

    let (mut ledger, coin) = funded_ledger(script_addr, 1_000);

    // A different (but valid) script in the witness → hash mismatch.
    let wrong_script = vec![0x01, 0x01];
    let spend = build_script_v2_spend(
        coin,
        wrong_script,
        vec![vec![0u8; 64], generate_key(2).address().payload().to_vec()],
        vec![TxOutput::native(900, bob.address())],
        b"mismatch".to_vec(),
    );

    let err = ledger
        .insert(vec![ledger.dag().selected_tip()], 1, 0, 0, &[spend])
        .unwrap_err();
    assert!(matches!(
        err,
        LedgerInsertError::State(LedgerError::ScriptHashMismatch { .. })
    ));
}

#[test]
fn test_script_v2_invalid_script() {
    let bob = generate_key(1);

    // An address locked to an invalid program (unknown opcode 0x09). The
    // coinbase output gate is exempt, so the address can be funded in genesis.
    let invalid_script = vec![0x09];
    let script_addr = Address::from_script_v2(&invalid_script);

    let (mut ledger, coin) = funded_ledger(script_addr, 1_000);

    let spend = build_script_v2_spend(
        coin,
        invalid_script,
        vec![],
        vec![TxOutput::native(900, bob.address())],
        b"invalid".to_vec(),
    );

    let err = ledger
        .insert(vec![ledger.dag().selected_tip()], 1, 0, 0, &[spend])
        .unwrap_err();
    assert!(matches!(
        err,
        LedgerInsertError::State(LedgerError::InvalidRedeemScript { .. })
    ));
}

#[test]
fn test_script_v2_pre_activation_output_rejected() {
    let funder = generate_key(10);
    let script = vec![0x01];
    let script_addr = Address::from_script_v2(&script);

    let (mut ledger, coin) = funded_ledger(funder.address(), 1_000);
    ledger.set_script_v2_activation_score(100);

    // Regular tx creating a script v2 output at blue score 1 (<= 100) → rejected.
    let tx = Transaction::signed(
        &[(coin, &funder)],
        vec![TxOutput::native(900, script_addr)],
        b"pre".to_vec(),
    );
    let err = ledger
        .insert(vec![ledger.dag().selected_tip()], 1, 0, 0, &[tx])
        .unwrap_err();
    assert!(matches!(
        err,
        LedgerInsertError::State(LedgerError::PreActivationScriptV2 {
            blue_score: 1,
            activation_score: 100,
            ..
        })
    ));
}

#[test]
fn test_script_v2_activation_boundary() {
    let funder = generate_key(10);
    let script = vec![0x01];
    let script_addr = Address::from_script_v2(&script);

    let (mut ledger, mut coin) = funded_ledger(funder.address(), 1_000);
    ledger.set_script_v2_activation_score(2); // activates at blue score > 2

    let mut parent = ledger.dag().selected_tip();

    // Block 1 (blue 1): still pre-activation → script v2 output rejected.
    let tx_fail = Transaction::signed(
        &[(coin, &funder)],
        vec![TxOutput::native(900, script_addr)],
        b"b1-fail".to_vec(),
    );
    let err = ledger
        .insert(vec![parent], 1, 0, 0, &[tx_fail])
        .unwrap_err();
    assert!(matches!(
        err,
        LedgerInsertError::State(LedgerError::PreActivationScriptV2 {
            blue_score: 1,
            activation_score: 2,
            ..
        })
    ));

    // Valid P2PK tx for Block 1.
    let tx1 = Transaction::signed(
        &[(coin, &funder)],
        vec![TxOutput::native(900, funder.address())],
        b"b1".to_vec(),
    );
    coin = OutPoint::new(tx1.id(), 0);
    parent = ledger.insert(vec![parent], 1, 0, 0, &[tx1]).unwrap();

    // Block 2 (blue 2): still pre-activation (2 <= 2) → rejected.
    let tx_fail2 = Transaction::signed(
        &[(coin, &funder)],
        vec![TxOutput::native(800, script_addr)],
        b"b2-fail".to_vec(),
    );
    let err2 = ledger
        .insert(vec![parent], 1, 0, 0, &[tx_fail2])
        .unwrap_err();
    assert!(matches!(
        err2,
        LedgerInsertError::State(LedgerError::PreActivationScriptV2 {
            blue_score: 2,
            activation_score: 2,
            ..
        })
    ));

    // Valid P2PK tx for Block 2.
    let tx2 = Transaction::signed(
        &[(coin, &funder)],
        vec![TxOutput::native(800, funder.address())],
        b"b2".to_vec(),
    );
    coin = OutPoint::new(tx2.id(), 0);
    parent = ledger.insert(vec![parent], 1, 0, 0, &[tx2]).unwrap();

    // Block 3 (blue 3): post-activation (3 > 2) → script v2 output accepted.
    let tx3 = Transaction::signed(
        &[(coin, &funder)],
        vec![TxOutput::native(700, script_addr)],
        b"b3".to_vec(),
    );
    ledger.insert(vec![parent], 1, 0, 0, &[tx3]).unwrap();

    let utxo = ledger.state(&ledger.dag().selected_tip()).unwrap();
    assert_eq!(utxo.balance(&script_addr), 700);
    assert_eq!(ledger.script_v2_activation_score(), 2);
}
