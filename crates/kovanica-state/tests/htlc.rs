//! RFC-004 consensus test suite: HTLC (hashed time-locked contracts).
//!
//! 23 tests.
//!
//! HTLC (RFC-004): outputs locked to a v0x04 address (BLAKE3 of a 100-byte
//! template: `preimage_hash || recipient_pk || sender_pk || timeout`). Spends
//! are discriminated by witness length — 3 elements = REDEEM (preimage +
//! recipient signature, no time constraint), 2 elements = REFUND (sender
//! signature, only once the chain height reaches the timeout).
//!
//! Reference protocols: BIP-199 (hashed time-locked contracts), Tier Nolan
//! atomic swap (preimage revelation), Lightning (preimage-based settlement),
//! BIP-65/BIP-113 (absolute locktime semantics for the companion CLTV fix).
//! The template/address shape mirrors RFC-001 P2SH and RFC-003 script v2;
//! activation gating mirrors RFC-001/002/003.
//!
//! Activation gating: `blue_score <= activation_score` is pre-activation
//! (outputs and spends rejected). Genesis is blue score 0; the first inserted
//! block is blue score 1. Coinbase outputs are exempt from the HTLC output
//! gate (mirroring the stealth/script-v2/native-token coinbase exemption), so
//! genesis can fund an HTLC address directly.

use ed25519_dalek::Signer as _;
use kovanica_state::htlc::HtlcScript;
use kovanica_state::ledger::HTLC_ACTIVATION_SCORE;
use kovanica_state::multisig::MultisigScript;
use kovanica_state::{
    Address, AssetId, HalvingSchedule, KeyPair, Ledger, LedgerError, LedgerInsertError, OutPoint,
    StealthAddress, Transaction, TxInput, TxOutput, DEFAULT_HALVING_ERA,
};

const K: u16 = 3;
const SUBSIDY: u64 = 1_000;
const SCHEDULE: HalvingSchedule = HalvingSchedule::new(SUBSIDY, DEFAULT_HALVING_ERA);

/// Fixed ephemeral secret for deterministic stealth derivations.
const R_SECRET: [u8; 32] = [0x42u8; 32];

fn generate_key(count: usize) -> KeyPair {
    KeyPair::from_u64((1000 + count) as u64)
}

/// Build a validated HTLC template from a preimage and two parties.
fn make_htlc(preimage: &[u8], recipient: &KeyPair, sender: &KeyPair, timeout: u32) -> HtlcScript {
    let preimage_hash = *blake3::hash(preimage).as_bytes();
    HtlcScript::new(
        preimage_hash,
        *recipient.address().payload(),
        *sender.address().payload(),
        timeout,
    )
    .expect("valid htlc template")
}

/// A ledger whose genesis coinbase funds an HTLC address (coinbase exempt from
/// the output gate).
fn htlc_funded_ledger(script: &HtlcScript, funding: u64) -> (Ledger, OutPoint) {
    let coinbase = Transaction::coinbase(
        vec![TxOutput::native(funding, script.address())],
        b"genesis".to_vec(),
    );
    let coin = OutPoint::new(coinbase.id(), 0);
    let ledger = Ledger::new(K, SCHEDULE, &[coinbase]).expect("valid genesis");
    (ledger, coin)
}

/// A ledger whose genesis coinbase funds a P2PK address.
fn funded_ledger(owner: Address, funding: u64) -> (Ledger, OutPoint) {
    let coinbase =
        Transaction::coinbase(vec![TxOutput::native(funding, owner)], b"genesis".to_vec());
    let coin = OutPoint::new(coinbase.id(), 0);
    let ledger = Ledger::new(K, SCHEDULE, &[coinbase]).expect("valid genesis");
    (ledger, coin)
}

/// Build an HTLC redeem: witness = [template, preimage, recipient_sig].
fn build_htlc_redeem(
    outpoint: OutPoint,
    script: &HtlcScript,
    preimage: &[u8],
    recipient_kp: &KeyPair,
    outputs: Vec<TxOutput>,
    tag: Vec<u8>,
) -> Transaction {
    let dummy_input = TxInput {
        outpoint,
        witness: Vec::new(),
    };
    let mut tx = Transaction::new(vec![dummy_input], outputs, tag);
    let sighash = tx.sighash();
    let sig = recipient_kp.sign(&sighash);
    tx.inputs_mut()[0].witness = script.redeem_witness(preimage, sig);
    tx
}

/// Build an HTLC refund: witness = [template, sender_sig].
fn build_htlc_refund(
    outpoint: OutPoint,
    script: &HtlcScript,
    sender_kp: &KeyPair,
    outputs: Vec<TxOutput>,
    tag: Vec<u8>,
) -> Transaction {
    let dummy_input = TxInput {
        outpoint,
        witness: Vec::new(),
    };
    let mut tx = Transaction::new(vec![dummy_input], outputs, tag);
    let sighash = tx.sighash();
    let sig = sender_kp.sign(&sighash);
    tx.inputs_mut()[0].witness = script.refund_witness(sig);
    tx
}

// =========================================================================
// HTLC (RFC-004) — 23 tests
// =========================================================================

#[test]
fn htlc_redeem_happy_path() {
    let recipient = generate_key(0);
    let sender = generate_key(1);
    let script = make_htlc(b"correct horse battery staple", &recipient, &sender, 100);

    let (mut ledger, coin) = htlc_funded_ledger(&script, 1_000);
    let bob = generate_key(2).address();

    let redeem = build_htlc_redeem(
        coin,
        &script,
        b"correct horse battery staple",
        &recipient,
        vec![TxOutput::native(900, bob)],
        b"redeem".to_vec(),
    );
    ledger
        .insert(vec![ledger.dag().selected_tip()], 1, 0, 0, &[redeem])
        .unwrap();

    let utxo = ledger.state(&ledger.dag().selected_tip()).unwrap();
    assert_eq!(utxo.balance(&bob), 900);
    assert_eq!(utxo.balance(&script.address()), 0);
}

#[test]
fn htlc_refund_happy_path() {
    let recipient = generate_key(0);
    let sender = generate_key(1);
    let script = make_htlc(b"secret", &recipient, &sender, 1); // timeout at height 1

    let (mut ledger, coin) = htlc_funded_ledger(&script, 1_000);
    let sender_addr = sender.address();

    let refund = build_htlc_refund(
        coin,
        &script,
        &sender,
        vec![TxOutput::native(900, sender_addr)],
        b"refund".to_vec(),
    );
    ledger
        .insert(vec![ledger.dag().selected_tip()], 1, 0, 0, &[refund])
        .unwrap();

    let utxo = ledger.state(&ledger.dag().selected_tip()).unwrap();
    assert_eq!(utxo.balance(&sender_addr), 900);
}

#[test]
fn htlc_refund_before_timeout_rejected() {
    let recipient = generate_key(0);
    let sender = generate_key(1);
    let script = make_htlc(b"secret", &recipient, &sender, 100);

    let (mut ledger, coin) = htlc_funded_ledger(&script, 1_000);

    let refund = build_htlc_refund(
        coin,
        &script,
        &sender,
        vec![TxOutput::native(900, sender.address())],
        b"early-refund".to_vec(),
    );
    let err = ledger
        .insert(vec![ledger.dag().selected_tip()], 1, 0, 0, &[refund])
        .unwrap_err();
    assert!(matches!(
        err,
        LedgerInsertError::State(LedgerError::HtlcTimeoutNotReached {
            height: 1,
            timeout: 100,
            ..
        })
    ));
}

#[test]
fn htlc_refund_at_timeout_boundary() {
    // timeout = 1, block height = 1 → height >= timeout, refund allowed.
    let recipient = generate_key(0);
    let sender = generate_key(1);
    let script = make_htlc(b"secret", &recipient, &sender, 1);

    let (mut ledger, coin) = htlc_funded_ledger(&script, 1_000);

    let refund = build_htlc_refund(
        coin,
        &script,
        &sender,
        vec![TxOutput::native(900, sender.address())],
        b"boundary-refund".to_vec(),
    );
    ledger
        .insert(vec![ledger.dag().selected_tip()], 1, 0, 0, &[refund])
        .unwrap();
    let utxo = ledger.state(&ledger.dag().selected_tip()).unwrap();
    assert_eq!(utxo.balance(&sender.address()), 900);
}

#[test]
fn htlc_wrong_preimage_rejected() {
    let recipient = generate_key(0);
    let sender = generate_key(1);
    let script = make_htlc(b"correct preimage", &recipient, &sender, 100);

    let (mut ledger, coin) = htlc_funded_ledger(&script, 1_000);

    let redeem = build_htlc_redeem(
        coin,
        &script,
        b"wrong preimage",
        &recipient,
        vec![TxOutput::native(900, generate_key(2).address())],
        b"wrong-preimage".to_vec(),
    );
    let err = ledger
        .insert(vec![ledger.dag().selected_tip()], 1, 0, 0, &[redeem])
        .unwrap_err();
    assert!(matches!(
        err,
        LedgerInsertError::State(LedgerError::HtlcPreimageMismatch { input: 0, .. })
    ));
}

#[test]
fn htlc_wrong_recipient_key_rejected() {
    let recipient = generate_key(0);
    let sender = generate_key(1);
    let script = make_htlc(b"secret", &recipient, &sender, 100);

    let (mut ledger, coin) = htlc_funded_ledger(&script, 1_000);

    // A different key signs the redeem → BadSignature.
    let wrong_kp = generate_key(99);
    let redeem = build_htlc_redeem(
        coin,
        &script,
        b"secret",
        &wrong_kp,
        vec![TxOutput::native(900, generate_key(2).address())],
        b"wrong-recipient".to_vec(),
    );
    let err = ledger
        .insert(vec![ledger.dag().selected_tip()], 1, 0, 0, &[redeem])
        .unwrap_err();
    assert!(matches!(
        err,
        LedgerInsertError::State(LedgerError::BadSignature { input: 0, .. })
    ));
}

#[test]
fn htlc_refund_wrong_key_rejected() {
    let recipient = generate_key(0);
    let sender = generate_key(1);
    let script = make_htlc(b"secret", &recipient, &sender, 1);

    let (mut ledger, coin) = htlc_funded_ledger(&script, 1_000);

    // The recipient (not the sender) tries the refund path → BadSignature.
    let refund = build_htlc_refund(
        coin,
        &script,
        &recipient,
        vec![TxOutput::native(900, recipient.address())],
        b"wrong-refunder".to_vec(),
    );
    let err = ledger
        .insert(vec![ledger.dag().selected_tip()], 1, 0, 0, &[refund])
        .unwrap_err();
    assert!(matches!(
        err,
        LedgerInsertError::State(LedgerError::BadSignature { input: 0, .. })
    ));
}

#[test]
fn htlc_redeem_after_timeout_allowed() {
    // BIP-199: the redeem path has no time constraint — the recipient may
    // redeem even after the refund timeout has passed.
    let recipient = generate_key(0);
    let sender = generate_key(1);
    let script = make_htlc(b"secret", &recipient, &sender, 1);

    let (mut ledger, coin) = htlc_funded_ledger(&script, 1_000);
    let bob = generate_key(2).address();

    let redeem = build_htlc_redeem(
        coin,
        &script,
        b"secret",
        &recipient,
        vec![TxOutput::native(900, bob)],
        b"late-redeem".to_vec(),
    );
    ledger
        .insert(vec![ledger.dag().selected_tip()], 1, 0, 0, &[redeem])
        .unwrap();
    let utxo = ledger.state(&ledger.dag().selected_tip()).unwrap();
    assert_eq!(utxo.balance(&bob), 900);
}

#[test]
fn htlc_script_hash_mismatch() {
    let recipient = generate_key(0);
    let sender = generate_key(1);
    let script = make_htlc(b"secret", &recipient, &sender, 100);

    let (mut ledger, coin) = htlc_funded_ledger(&script, 1_000);

    // witness[0] is a *different* valid template → BLAKE3 mismatch.
    let other = make_htlc(b"other", &generate_key(10), &generate_key(11), 100);
    let dummy_input = TxInput {
        outpoint: coin,
        witness: other.redeem_witness(b"secret", recipient.sign(&[0u8; 32])),
    };
    let tx = Transaction::new(
        vec![dummy_input],
        vec![TxOutput::native(900, generate_key(2).address())],
        b"hash-mismatch".to_vec(),
    );
    let err = ledger
        .insert(vec![ledger.dag().selected_tip()], 1, 0, 0, &[tx])
        .unwrap_err();
    assert!(matches!(
        err,
        LedgerInsertError::State(LedgerError::ScriptHashMismatch { input: 0, .. })
    ));
}

#[test]
fn htlc_malformed_script_rejected() {
    // An HTLC address whose template hash commits to a *structurally invalid*
    // template (recipient/sender keys not on the curve) → parse fails at spend
    // time with InvalidRedeemScript.
    let mut malformed = [0u8; 100];
    malformed[32..64].copy_from_slice(&[0x02u8; 32]); // invalid Ed25519 point
    malformed[64..96].copy_from_slice(&[0x03u8; 32]); // invalid Ed25519 point
    let owner = Address::htlc(*blake3::hash(&malformed).as_bytes());

    let coinbase = Transaction::coinbase(vec![TxOutput::native(1_000, owner)], b"genesis".to_vec());
    let coin = OutPoint::new(coinbase.id(), 0);
    let mut ledger = Ledger::new(K, SCHEDULE, &[coinbase]).expect("valid genesis");

    let dummy_input = TxInput {
        outpoint: coin,
        witness: vec![malformed.to_vec(), b"secret".to_vec(), vec![0u8; 64]],
    };
    let tx = Transaction::new(
        vec![dummy_input],
        vec![TxOutput::native(900, generate_key(2).address())],
        b"malformed".to_vec(),
    );
    let err = ledger
        .insert(vec![ledger.dag().selected_tip()], 1, 0, 0, &[tx])
        .unwrap_err();
    assert!(matches!(
        err,
        LedgerInsertError::State(LedgerError::InvalidRedeemScript { input: 0, .. })
    ));
}

#[test]
fn htlc_witness_count_rejected() {
    let recipient = generate_key(0);
    let sender = generate_key(1);
    let script = make_htlc(b"secret", &recipient, &sender, 100);

    let (mut ledger, coin) = htlc_funded_ledger(&script, 1_000);

    // 4 witness elements → neither redeem (3) nor refund (2).
    let dummy_input = TxInput {
        outpoint: coin,
        witness: vec![
            script.bytes().to_vec(),
            b"secret".to_vec(),
            vec![0u8; 64],
            vec![0u8; 64],
        ],
    };
    let tx = Transaction::new(
        vec![dummy_input],
        vec![TxOutput::native(900, generate_key(2).address())],
        b"bad-count".to_vec(),
    );
    let err = ledger
        .insert(vec![ledger.dag().selected_tip()], 1, 0, 0, &[tx])
        .unwrap_err();
    assert!(matches!(
        err,
        LedgerInsertError::State(LedgerError::InvalidWitnessCount {
            expected: 2,
            actual: 4,
            ..
        })
    ));
}

#[test]
fn htlc_parallel_double_spend() {
    // Two parallel blocks spend the SAME HTLC coin: one redeems (recipient),
    // one refunds (sender). Each is valid in its own view (the coin is unspent
    // in both) → both admitted; the selected tip's state resolves the conflict
    // deterministically by linearization order.
    let recipient = generate_key(0);
    let sender = generate_key(1);
    let script = make_htlc(b"secret", &recipient, &sender, 1);

    let (mut ledger, coin) = htlc_funded_ledger(&script, 1_000);
    let genesis_id = ledger.dag().selected_tip();

    let alice = generate_key(2).address();
    let bob = generate_key(3).address();

    let redeem = build_htlc_redeem(
        coin,
        &script,
        b"secret",
        &recipient,
        vec![TxOutput::native(900, alice)],
        b"a".to_vec(),
    );
    let id_a = ledger.insert(vec![genesis_id], 1, 0, 0, &[redeem]).unwrap();

    let refund = build_htlc_refund(
        coin,
        &script,
        &sender,
        vec![TxOutput::native(900, bob)],
        b"b".to_vec(),
    );
    let id_b = ledger.insert(vec![genesis_id], 1, 0, 0, &[refund]).unwrap();

    // Both are valid in their own view → both admitted.
    assert!(ledger.dag().contains(&id_a));
    assert!(ledger.dag().contains(&id_b));

    // The selected tip's state applies only one of the two spends.
    let utxo = ledger.state(&ledger.dag().selected_tip()).unwrap();
    assert_eq!(utxo.balance(&alice) + utxo.balance(&bob), 900);
}

#[test]
fn htlc_activation_boundary() {
    let recipient = generate_key(0);
    let sender = generate_key(1);
    let script = make_htlc(b"secret", &recipient, &sender, 100);
    let funder = generate_key(10);

    // Genesis coinbase funds both the funder (P2PK) and the HTLC address
    // (coinbase exempt from the output gate) so the *spend* gate can be
    // exercised pre-activation too.
    let coinbase = Transaction::coinbase(
        vec![
            TxOutput::native(1_000, funder.address()),
            TxOutput::native(1_000, script.address()),
        ],
        b"genesis".to_vec(),
    );
    let funder_coin = OutPoint::new(coinbase.id(), 0);
    let htlc_coin = OutPoint::new(coinbase.id(), 1);
    let schedule = HalvingSchedule::new(2_000, DEFAULT_HALVING_ERA);
    let mut ledger = Ledger::new(K, schedule, &[coinbase]).expect("valid genesis");
    ledger.set_htlc_activation_score(2); // activates at blue score > 2

    let mut parent = ledger.dag().selected_tip();

    // Block 1 (blue 1): pre-activation → HTLC output rejected.
    let tx_out = Transaction::signed(
        &[(funder_coin, &funder)],
        vec![TxOutput::native(900, script.address())],
        b"b1-out".to_vec(),
    );
    let err = ledger.insert(vec![parent], 1, 0, 0, &[tx_out]).unwrap_err();
    assert!(matches!(
        err,
        LedgerInsertError::State(LedgerError::PreActivationHtlc {
            blue_score: 1,
            activation_score: 2,
            ..
        })
    ));

    // Block 1 (blue 1): pre-activation → HTLC spend rejected.
    let redeem = build_htlc_redeem(
        htlc_coin,
        &script,
        b"secret",
        &recipient,
        vec![TxOutput::native(900, funder.address())],
        b"b1-spend".to_vec(),
    );
    let err = ledger.insert(vec![parent], 1, 0, 0, &[redeem]).unwrap_err();
    assert!(matches!(
        err,
        LedgerInsertError::State(LedgerError::PreActivationHtlc {
            blue_score: 1,
            activation_score: 2,
            ..
        })
    ));

    // Valid P2PK tx for Block 1.
    let tx1 = Transaction::signed(
        &[(funder_coin, &funder)],
        vec![TxOutput::native(900, funder.address())],
        b"b1".to_vec(),
    );
    let funder_coin2 = OutPoint::new(tx1.id(), 0);
    parent = ledger.insert(vec![parent], 1, 0, 0, &[tx1]).unwrap();

    // Block 2 (blue 2): still pre-activation (2 <= 2) → output rejected.
    let tx_out2 = Transaction::signed(
        &[(funder_coin2, &funder)],
        vec![TxOutput::native(800, script.address())],
        b"b2-out".to_vec(),
    );
    let err2 = ledger
        .insert(vec![parent], 1, 0, 0, &[tx_out2])
        .unwrap_err();
    assert!(matches!(
        err2,
        LedgerInsertError::State(LedgerError::PreActivationHtlc {
            blue_score: 2,
            activation_score: 2,
            ..
        })
    ));

    // Valid P2PK tx for Block 2.
    let tx2 = Transaction::signed(
        &[(funder_coin2, &funder)],
        vec![TxOutput::native(800, funder.address())],
        b"b2".to_vec(),
    );
    parent = ledger.insert(vec![parent], 1, 0, 0, &[tx2]).unwrap();

    // Block 3 (blue 3): post-activation (3 > 2) → HTLC spend accepted.
    let redeem3 = build_htlc_redeem(
        htlc_coin,
        &script,
        b"secret",
        &recipient,
        vec![TxOutput::native(900, funder.address())],
        b"b3-spend".to_vec(),
    );
    ledger.insert(vec![parent], 1, 0, 0, &[redeem3]).unwrap();

    let utxo = ledger.state(&ledger.dag().selected_tip()).unwrap();
    // funder_coin3 (800) + redeem3 output (900).
    assert_eq!(utxo.balance(&funder.address()), 1_700);
}

#[test]
fn htlc_checkpoint_roundtrip() {
    let recipient = generate_key(0);
    let sender = generate_key(1);
    let script = make_htlc(b"secret", &recipient, &sender, 100);

    let coinbase = Transaction::coinbase(
        vec![TxOutput::native(1_000, script.address())],
        b"genesis".to_vec(),
    );
    let coin = OutPoint::new(coinbase.id(), 0);
    let mut ledger = Ledger::with_finality(K, SCHEDULE, &[coinbase], 2).expect("valid genesis");
    ledger.set_htlc_activation_score(0);

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

    // The HTLC output survives the push.
    let utxo = ledger.state(&ledger.dag().selected_tip()).unwrap();
    assert_eq!(utxo.balance(&script.address()), 1_000);

    // Write checkpoint (v5: HTLC is an address version, no format change).
    let buf = ledger.write_checkpoint().unwrap();

    // Read checkpoint into a new ledger.
    let mut restored = Ledger::read_checkpoint(&buf).unwrap();

    let restored_utxo = restored.state(&restored.dag().selected_tip()).unwrap();
    assert_eq!(restored_utxo.balance(&script.address()), 1_000);
    assert_eq!(restored.htlc_activation_score(), HTLC_ACTIVATION_SCORE);

    // And the restored ledger can still redeem it.
    let bob = generate_key(2).address();
    let redeem = build_htlc_redeem(
        coin,
        &script,
        b"secret",
        &recipient,
        vec![TxOutput::native(900, bob)],
        b"post-restore".to_vec(),
    );
    restored
        .insert(vec![restored.dag().selected_tip()], 1, 0, 0, &[redeem])
        .unwrap();
    let final_utxo = restored.state(&restored.dag().selected_tip()).unwrap();
    assert_eq!(final_utxo.balance(&bob), 900);
}

#[test]
fn htlc_snapshot_roundtrip() {
    let recipient = generate_key(0);
    let sender = generate_key(1);
    let script = make_htlc(b"secret", &recipient, &sender, 100);

    let (mut ledger, coin) = htlc_funded_ledger(&script, 1_000);

    // Redeem before snapshot.
    let bob = generate_key(2).address();
    let redeem = build_htlc_redeem(
        coin,
        &script,
        b"secret",
        &recipient,
        vec![TxOutput::native(900, bob)],
        b"pre-snapshot".to_vec(),
    );
    ledger
        .insert(vec![ledger.dag().selected_tip()], 1, 0, 0, &[redeem])
        .unwrap();

    let buf = ledger.write_snapshot();
    let restored = Ledger::read_snapshot(&buf).unwrap();

    let restored_utxo = restored.state(&restored.dag().selected_tip()).unwrap();
    assert_eq!(restored_utxo.balance(&bob), 900);
    assert_eq!(restored_utxo.balance(&script.address()), 0);
    assert_eq!(restored.htlc_activation_score(), HTLC_ACTIVATION_SCORE);
}

#[test]
fn htlc_mixed_block() {
    // One block creating all six output types (P2PK, P2SH, script v2, stealth,
    // HTLC native, HTLC asset), then one block spending all of them.
    let funder = generate_key(0);
    let alice = generate_key(1);
    let carol = generate_key(3);
    let asset = AssetId::from_bytes([0x11u8; 32]);

    // HTLC parties.
    let recipient = generate_key(4);
    let sender = generate_key(5);
    let script = make_htlc(b"mixed-preimage", &recipient, &sender, 100);

    // P2SH 2-of-3.
    let m_keys = [generate_key(6), generate_key(7), generate_key(8)];
    let ms = MultisigScript::new(2, m_keys.iter().map(|k| *k.address().payload()).collect())
        .expect("valid multisig");

    // Script v2 single-sig.
    let sv2_script = vec![0x01];
    let sv2_addr = Address::from_script_v2(&sv2_script);

    // Stealth recipient.
    let scan_kp = generate_key(9);
    let spend_kp = generate_key(10);
    let stealth = StealthAddress::new(*scan_kp.address().payload(), *spend_kp.address().payload());
    let ext = stealth.derive_output(&R_SECRET).expect("valid derivation");

    // Genesis: native + asset to funder.
    let coinbase = Transaction::coinbase(
        vec![
            TxOutput::native(10_000, funder.address()),
            TxOutput::new(1_000, Some(asset), funder.address()),
        ],
        b"genesis".to_vec(),
    );
    let native_coin = OutPoint::new(coinbase.id(), 0);
    let asset_coin = OutPoint::new(coinbase.id(), 1);
    let schedule = HalvingSchedule::new(11_000, DEFAULT_HALVING_ERA);
    let mut ledger = Ledger::new(K, schedule, &[coinbase]).expect("valid genesis");

    // Block 1: create all six output types in one transaction.
    let tx1 = Transaction::signed(
        &[(native_coin, &funder), (asset_coin, &funder)],
        vec![
            TxOutput::native(1_000, alice.address()),            // P2PK
            TxOutput::native(1_000, ms.address()),               // P2SH
            TxOutput::native(1_000, sv2_addr),                   // script v2
            TxOutput::stealth(1_000, stealth.address(), ext),    // stealth
            TxOutput::native(1_000, script.address()),           // HTLC native
            TxOutput::new(1_000, Some(asset), script.address()), // HTLC asset
            TxOutput::native(4_000, funder.address()),           // change
        ],
        b"mixed-create".to_vec(),
    );
    let p2pk_coin = OutPoint::new(tx1.id(), 0);
    let p2sh_coin = OutPoint::new(tx1.id(), 1);
    let sv2_coin = OutPoint::new(tx1.id(), 2);
    let stealth_coin = OutPoint::new(tx1.id(), 3);
    let htlc_coin = OutPoint::new(tx1.id(), 4);
    let htlc_asset_coin = OutPoint::new(tx1.id(), 5);

    ledger
        .insert(vec![ledger.dag().selected_tip()], 1, 0, 0, &[tx1])
        .unwrap();

    // Block 2: spend all six.
    let tx_p2pk = Transaction::signed(
        &[(p2pk_coin, &alice)],
        vec![TxOutput::native(900, carol.address())],
        b"spend-p2pk".to_vec(),
    );

    let tx_p2sh = Transaction::signed_multisig(
        p2sh_coin,
        ms.encode(),
        &[&m_keys[0], &m_keys[1]],
        vec![TxOutput::native(900, carol.address())],
        b"spend-p2sh".to_vec(),
    );

    let dummy_input = TxInput {
        outpoint: sv2_coin,
        witness: Vec::new(),
    };
    let mut tx_sv2 = Transaction::new(
        vec![dummy_input],
        vec![TxOutput::native(900, carol.address())],
        b"spend-sv2".to_vec(),
    );
    let sighash = tx_sv2.sighash();
    tx_sv2.inputs_mut()[0].witness = vec![
        sv2_script,
        alice.address().payload().to_vec(),
        alice.sign(&sighash).to_vec(),
    ];

    let dummy_input = TxInput {
        outpoint: stealth_coin,
        witness: Vec::new(),
    };
    let mut tx_stealth = Transaction::new(
        vec![dummy_input],
        vec![TxOutput::native(900, carol.address())],
        b"spend-stealth".to_vec(),
    );
    let sighash = tx_stealth.sighash();
    let one_time_sk =
        StealthAddress::derive_one_time_key(&spend_kp.seed(), &ext.r).expect("valid one-time key");
    tx_stealth.inputs_mut()[0].witness = vec![one_time_sk.sign(&sighash).to_bytes().to_vec()];

    let tx_htlc = build_htlc_redeem(
        htlc_coin,
        &script,
        b"mixed-preimage",
        &recipient,
        vec![TxOutput::native(900, carol.address())],
        b"spend-htlc".to_vec(),
    );

    let tx_htlc_asset = build_htlc_redeem(
        htlc_asset_coin,
        &script,
        b"mixed-preimage",
        &recipient,
        vec![TxOutput::new(900, Some(asset), carol.address())],
        b"spend-htlc-asset".to_vec(),
    );

    ledger
        .insert(
            vec![ledger.dag().selected_tip()],
            1,
            0,
            0,
            &[tx_p2pk, tx_p2sh, tx_sv2, tx_stealth, tx_htlc, tx_htlc_asset],
        )
        .unwrap();

    let utxo = ledger.state(&ledger.dag().selected_tip()).unwrap();
    // 5 native spends of 900 each (P2PK, P2SH, script v2, stealth, HTLC).
    assert_eq!(utxo.balance(&carol.address()), 900 * 5);
    assert_eq!(utxo.balance_of_asset(&carol.address(), Some(asset)), 900);
    assert_eq!(utxo.balance(&script.address()), 0);
    assert_eq!(utxo.balance_of_asset(&script.address(), Some(asset)), 0);
}

#[test]
fn htlc_asset_swap() {
    // An atomic swap of native KVNC for an asset, both legs locked behind the
    // same HTLC template. Asset conservation is per-asset; the fee is paid in
    // native KVNC only.
    let recipient = generate_key(0);
    let sender = generate_key(1);
    let script = make_htlc(b"swap-preimage", &recipient, &sender, 100);
    let asset = AssetId::from_bytes([0x22u8; 32]);

    // Genesis: native + asset to sender.
    let coinbase = Transaction::coinbase(
        vec![
            TxOutput::native(1_000, sender.address()),
            TxOutput::new(1_000, Some(asset), sender.address()),
        ],
        b"genesis".to_vec(),
    );
    let native_coin = OutPoint::new(coinbase.id(), 0);
    let asset_coin = OutPoint::new(coinbase.id(), 1);
    let mut ledger = Ledger::new(K, SCHEDULE, &[coinbase]).expect("valid genesis");

    // Block 1: lock both legs behind the HTLC (native + asset), fee in native.
    let lock = Transaction::signed(
        &[(native_coin, &sender), (asset_coin, &sender)],
        vec![
            TxOutput::native(900, script.address()),
            TxOutput::new(1_000, Some(asset), script.address()),
        ],
        b"lock".to_vec(),
    );
    let native_htlc = OutPoint::new(lock.id(), 0);
    let asset_htlc = OutPoint::new(lock.id(), 1);

    ledger
        .insert(vec![ledger.dag().selected_tip()], 1, 0, 0, &[lock])
        .unwrap();

    // Block 2: recipient redeems both legs in one transaction.
    let dummy_inputs = vec![
        TxInput {
            outpoint: native_htlc,
            witness: Vec::new(),
        },
        TxInput {
            outpoint: asset_htlc,
            witness: Vec::new(),
        },
    ];
    let mut redeem = Transaction::new(
        dummy_inputs,
        vec![
            TxOutput::native(890, recipient.address()),
            TxOutput::new(1_000, Some(asset), recipient.address()),
        ],
        b"redeem".to_vec(),
    );
    let sighash = redeem.sighash();
    let sig = recipient.sign(&sighash);
    redeem.inputs_mut()[0].witness = script.redeem_witness(b"swap-preimage", sig);
    redeem.inputs_mut()[1].witness = script.redeem_witness(b"swap-preimage", sig);
    ledger
        .insert(vec![ledger.dag().selected_tip()], 1, 0, 0, &[redeem])
        .unwrap();

    let utxo = ledger.state(&ledger.dag().selected_tip()).unwrap();
    assert_eq!(utxo.balance(&recipient.address()), 890);
    assert_eq!(
        utxo.balance_of_asset(&recipient.address(), Some(asset)),
        1_000
    );
    assert_eq!(utxo.balance(&script.address()), 0);
    assert_eq!(utxo.balance_of_asset(&script.address(), Some(asset)), 0);
}

#[test]
fn htlc_duplicate_scripts() {
    // Two outputs locked to the *same* HTLC template (same address) — both
    // spendable in one transaction.
    let recipient = generate_key(0);
    let sender = generate_key(1);
    let script = make_htlc(b"dup-preimage", &recipient, &sender, 100);

    let coinbase = Transaction::coinbase(
        vec![
            TxOutput::native(1_000, script.address()),
            TxOutput::native(1_000, script.address()),
        ],
        b"genesis".to_vec(),
    );
    let coin_a = OutPoint::new(coinbase.id(), 0);
    let coin_b = OutPoint::new(coinbase.id(), 1);
    let schedule = HalvingSchedule::new(2_000, DEFAULT_HALVING_ERA);
    let mut ledger = Ledger::new(K, schedule, &[coinbase]).expect("valid genesis");

    let bob = generate_key(2).address();
    let dummy_inputs = vec![
        TxInput {
            outpoint: coin_a,
            witness: Vec::new(),
        },
        TxInput {
            outpoint: coin_b,
            witness: Vec::new(),
        },
    ];
    let mut tx = Transaction::new(
        dummy_inputs,
        vec![TxOutput::native(1_800, bob)],
        b"dup-spend".to_vec(),
    );
    let sighash = tx.sighash();
    let sig = recipient.sign(&sighash);
    tx.inputs_mut()[0].witness = script.redeem_witness(b"dup-preimage", sig);
    tx.inputs_mut()[1].witness = script.redeem_witness(b"dup-preimage", sig);
    ledger
        .insert(vec![ledger.dag().selected_tip()], 1, 0, 0, &[tx])
        .unwrap();

    let utxo = ledger.state(&ledger.dag().selected_tip()).unwrap();
    assert_eq!(utxo.balance(&bob), 1_800);
}

#[test]
fn htlc_cross_version_confusion() {
    // The address version discriminates: an HTLC template must NOT be accepted
    // as a script-v2 program or a P2SH redeem script, and a P2SH redeem script
    // must NOT be accepted as an HTLC template.
    let recipient = generate_key(0);
    let sender = generate_key(1);

    // A template whose first byte is an invalid script-v2 opcode (0x00), so
    // the script-v2 branch deterministically rejects it at parse time.
    let mut template = [0u8; 100];
    template[32..64].copy_from_slice(recipient.address().payload());
    template[64..96].copy_from_slice(sender.address().payload());
    template[96..100].copy_from_slice(&100u32.to_le_bytes());

    // 1. HTLC template bytes as a script-v2 program → InvalidRedeemScript.
    let sv2_addr = Address::from_script_v2(&template);
    let coinbase =
        Transaction::coinbase(vec![TxOutput::native(1_000, sv2_addr)], b"genesis".to_vec());
    let coin = OutPoint::new(coinbase.id(), 0);
    let mut ledger = Ledger::new(K, SCHEDULE, &[coinbase]).expect("valid genesis");

    let dummy_input = TxInput {
        outpoint: coin,
        witness: vec![
            template.to_vec(),
            recipient.address().payload().to_vec(),
            vec![0u8; 64],
        ],
    };
    let tx = Transaction::new(
        vec![dummy_input],
        vec![TxOutput::native(900, generate_key(2).address())],
        b"sv2-confusion".to_vec(),
    );
    let err = ledger
        .insert(vec![ledger.dag().selected_tip()], 1, 0, 0, &[tx])
        .unwrap_err();
    assert!(matches!(
        err,
        LedgerInsertError::State(LedgerError::InvalidRedeemScript { input: 0, .. })
    ));

    // 2. HTLC template bytes as a P2SH redeem script → InvalidRedeemScript
    //    (multisig parse rejects the 100-byte input).
    let p2sh_addr = Address::from_script(&template);
    let coinbase = Transaction::coinbase(
        vec![TxOutput::native(1_000, p2sh_addr)],
        b"genesis".to_vec(),
    );
    let coin = OutPoint::new(coinbase.id(), 0);
    let mut ledger = Ledger::new(K, SCHEDULE, &[coinbase]).expect("valid genesis");

    let dummy_input = TxInput {
        outpoint: coin,
        witness: vec![template.to_vec(), vec![0u8; 64], vec![0u8; 64]],
    };
    let tx = Transaction::new(
        vec![dummy_input],
        vec![TxOutput::native(900, generate_key(2).address())],
        b"p2sh-confusion".to_vec(),
    );
    let err = ledger
        .insert(vec![ledger.dag().selected_tip()], 1, 0, 0, &[tx])
        .unwrap_err();
    assert!(matches!(
        err,
        LedgerInsertError::State(LedgerError::InvalidRedeemScript { input: 0, .. })
    ));

    // 3. A P2SH redeem script (multisig) as an HTLC template → InvalidRedeemScript
    //    (HTLC parse rejects the wrong length).
    let ms = MultisigScript::new(
        2,
        vec![
            *generate_key(6).address().payload(),
            *generate_key(7).address().payload(),
            *generate_key(8).address().payload(),
        ],
    )
    .expect("valid multisig");
    let htlc_addr = Address::htlc(*blake3::hash(&ms.encode()).as_bytes());
    let coinbase = Transaction::coinbase(
        vec![TxOutput::native(1_000, htlc_addr)],
        b"genesis".to_vec(),
    );
    let coin = OutPoint::new(coinbase.id(), 0);
    let mut ledger = Ledger::new(K, SCHEDULE, &[coinbase]).expect("valid genesis");

    let dummy_input = TxInput {
        outpoint: coin,
        witness: vec![ms.encode(), vec![0u8; 64]],
    };
    let tx = Transaction::new(
        vec![dummy_input],
        vec![TxOutput::native(900, generate_key(2).address())],
        b"htlc-confusion".to_vec(),
    );
    let err = ledger
        .insert(vec![ledger.dag().selected_tip()], 1, 0, 0, &[tx])
        .unwrap_err();
    assert!(matches!(
        err,
        LedgerInsertError::State(LedgerError::InvalidRedeemScript { input: 0, .. })
    ));
}

#[test]
fn htlc_timeout_overflow() {
    // timeout = u32::MAX: the refund path never unlocks within any reachable
    // height; the redeem path is unaffected.
    let recipient = generate_key(0);
    let sender = generate_key(1);
    let script = make_htlc(b"overflow", &recipient, &sender, u32::MAX);

    let (mut ledger, coin) = htlc_funded_ledger(&script, 1_000);

    // Refund at height 1 → HtlcTimeoutNotReached.
    let refund = build_htlc_refund(
        coin,
        &script,
        &sender,
        vec![TxOutput::native(900, sender.address())],
        b"overflow-refund".to_vec(),
    );
    let err = ledger
        .insert(vec![ledger.dag().selected_tip()], 1, 0, 0, &[refund])
        .unwrap_err();
    assert!(matches!(
        err,
        LedgerInsertError::State(LedgerError::HtlcTimeoutNotReached {
            height: 1,
            timeout: u32::MAX,
            ..
        })
    ));

    // Redeem still works.
    let bob = generate_key(2).address();
    let redeem = build_htlc_redeem(
        coin,
        &script,
        b"overflow",
        &recipient,
        vec![TxOutput::native(900, bob)],
        b"overflow-redeem".to_vec(),
    );
    ledger
        .insert(vec![ledger.dag().selected_tip()], 1, 0, 0, &[redeem])
        .unwrap();
    let utxo = ledger.state(&ledger.dag().selected_tip()).unwrap();
    assert_eq!(utxo.balance(&bob), 900);
}

#[test]
fn htlc_determinism() {
    // Building the same DAG twice yields identical block ids and identical
    // per-block UTXO state — consensus output is a pure function of the DAG.
    let recipient = generate_key(0);
    let sender = generate_key(1);
    let script = make_htlc(b"determinism", &recipient, &sender, 100);

    let mut ledgers = Vec::new();
    for _ in 0..2 {
        let (mut ledger, coin) = htlc_funded_ledger(&script, 1_000);
        let redeem = build_htlc_redeem(
            coin,
            &script,
            b"determinism",
            &recipient,
            vec![TxOutput::native(900, generate_key(2).address())],
            b"det".to_vec(),
        );
        ledger
            .insert(vec![ledger.dag().selected_tip()], 1, 0, 0, &[redeem])
            .unwrap();
        ledgers.push(ledger);
    }

    let a = &ledgers[0];
    let b = &ledgers[1];
    assert_eq!(a.dag().selected_tip(), b.dag().selected_tip());
    assert_eq!(
        a.state(&a.dag().selected_tip()).unwrap(),
        b.state(&b.dag().selected_tip()).unwrap()
    );
}

#[test]
fn cltv_non_final_rejected() {
    // Companion CLTV fix (BIP-65/BIP-113): a transaction whose n_lock_time
    // exceeds the block's height is non-final and cannot be mined.
    let alice = generate_key(0);
    let bob = generate_key(1);

    let (mut ledger, coin) = funded_ledger(alice.address(), 1_000);

    let dummy_input = TxInput {
        outpoint: coin,
        witness: Vec::new(),
    };
    let tx = Transaction::new_with_lock(
        vec![dummy_input],
        vec![TxOutput::native(900, bob.address())],
        b"non-final".to_vec(),
        100, // n_lock_time > block height 1
        0,
    );
    let err = ledger
        .insert(vec![ledger.dag().selected_tip()], 1, 0, 0, &[tx])
        .unwrap_err();
    assert!(matches!(
        err,
        LedgerInsertError::State(LedgerError::NonFinalTransaction {
            n_lock_time: 100,
            height: 1,
            ..
        })
    ));
}

#[test]
fn cltv_final_at_height() {
    // n_lock_time == block height → final; the tx proceeds to normal
    // validation (here, a valid P2PK signature).
    let alice = generate_key(0);
    let bob = generate_key(1);

    let (mut ledger, coin) = funded_ledger(alice.address(), 1_000);

    let dummy_input = TxInput {
        outpoint: coin,
        witness: Vec::new(),
    };
    let mut tx = Transaction::new_with_lock(
        vec![dummy_input],
        vec![TxOutput::native(900, bob.address())],
        b"final".to_vec(),
        1, // n_lock_time == block height 1 → final
        0,
    );
    let sighash = tx.sighash();
    tx.inputs_mut()[0].witness = vec![alice.sign(&sighash).to_vec()];
    ledger
        .insert(vec![ledger.dag().selected_tip()], 1, 0, 0, &[tx])
        .unwrap();

    let utxo = ledger.state(&ledger.dag().selected_tip()).unwrap();
    assert_eq!(utxo.balance(&bob.address()), 900);
}
