//! Dedicated Adversarial Consensus Test Suite for RFC-001 Multisig (Witness Payloads & P2SH).
//!
//! Tests include:
//! 1. Valid 1-of-1, 2-of-2, 2-of-3, 3-of-5, 16-of-16, 1-of-16 threshold spends.
//! 2. Invalid M/N combinations (M=0, N=0, M>N, N>16, 255/255).
//! 3. Malformed scripts (too short, truncated, trailing garbage, duplicate pubkeys, invalid Ed25519 points).
//! 4. Script hash and address mismatches (wrong script, bit flips).
//! 5. Witness count anomalies (missing signatures, excess signatures, empty witness).
//! 6. Cryptographic integrity (corrupted signatures, unauthorized signers, wrong sighash, wrong sig size).
//! 7. Duplicate signature attacks.
//! 8. Consensus blue score activation gating (pre vs post activation, exact boundary).
//! 9. Mixed transaction blocks (P2PK/P2SH coexisting) and mixed-input transactions.
//! 10. Cross-type witness mismatch, parallel DAG resolution, and snapshot roundtrip.

use kovanica_dag::{Block, Dag};
use kovanica_state::{
    apply_block, apply_dag, encode_block_payload, Address, HalvingSchedule, KeyPair, Ledger,
    LedgerError, LedgerInsertError, MultisigScript, OutPoint, Transaction, TxInput, TxOutput,
    UtxoSet, DEFAULT_HALVING_ERA, MAX_MULTISIG_KEYS,
};

const K: u16 = 3;
const SUBSIDY: u64 = 1_000;
const SCHEDULE: HalvingSchedule = HalvingSchedule::new(SUBSIDY, DEFAULT_HALVING_ERA);

fn generate_keys(count: usize) -> Vec<KeyPair> {
    (0..count)
        .map(|i| KeyPair::from_u64((1000 + i) as u64))
        .collect()
}

fn make_redeem_script_bytes(m: u8, keys: &[&KeyPair]) -> Vec<u8> {
    let mut script = Vec::with_capacity(2 + 32 * keys.len());
    script.push(m);
    script.push(keys.len() as u8);
    for kp in keys {
        script.extend_from_slice(kp.address().payload());
    }
    script
}

fn build_multisig_spend(
    outpoint: OutPoint,
    redeem_script: Vec<u8>,
    signers: &[&KeyPair],
    outputs: Vec<TxOutput>,
    tag: Vec<u8>,
) -> Transaction {
    let dummy_input = TxInput {
        outpoint,
        witness: Vec::new(),
    };
    let mut tx = Transaction::new(vec![dummy_input], outputs, tag);
    let sighash = tx.sighash();

    let mut witness = Vec::with_capacity(1 + signers.len());
    witness.push(redeem_script);
    for signer in signers {
        witness.push(signer.sign(&sighash).to_vec());
    }
    tx.inputs_mut()[0].witness = witness;
    tx
}

fn funded_ledger(owner: Address, funding: u64) -> (Ledger, OutPoint) {
    let coinbase = Transaction::coinbase(vec![TxOutput::new(funding, owner)], b"genesis".to_vec());
    let coin = OutPoint::new(coinbase.id(), 0);
    let ledger = Ledger::new(K, SCHEDULE, &[coinbase]).expect("valid genesis");
    (ledger, coin)
}

// =========================================================================
// Category 1: Positive M-of-N Threshold Spends
// =========================================================================

#[test]
fn test_multisig_1_of_1_spend_success() {
    let keys = generate_keys(1);
    let script = MultisigScript::new(1, vec![*keys[0].address().payload()]).unwrap();
    let p2sh_addr = script.address();

    let mut utxo = UtxoSet::new();
    let coinbase = Transaction::coinbase(vec![TxOutput::new(1_000, p2sh_addr)], b"cb".to_vec());
    let coin = OutPoint::new(coinbase.id(), 0);
    apply_block(&mut utxo, &[coinbase], 1_000).unwrap();

    let alice = KeyPair::from_u64(1).address();
    let spend = build_multisig_spend(
        coin,
        script.encode(),
        &[&keys[0]],
        vec![TxOutput::new(950, alice)],
        b"1of1".to_vec(),
    );

    let res = apply_block(&mut utxo, &[spend], 0);
    assert!(res.is_ok());
    assert_eq!(utxo.balance(&alice), 950);
    assert_eq!(utxo.balance(&p2sh_addr), 0);
}

#[test]
fn test_multisig_2_of_2_spend_success() {
    let keys = generate_keys(2);
    let script = MultisigScript::new(
        2,
        vec![*keys[0].address().payload(), *keys[1].address().payload()],
    )
    .unwrap();
    let p2sh_addr = script.address();

    let mut utxo = UtxoSet::new();
    let coinbase = Transaction::coinbase(vec![TxOutput::new(2_000, p2sh_addr)], b"cb".to_vec());
    let coin = OutPoint::new(coinbase.id(), 0);
    apply_block(&mut utxo, &[coinbase], 2_000).unwrap();

    let recipient = KeyPair::from_u64(2).address();
    let spend = build_multisig_spend(
        coin,
        script.encode(),
        &[&keys[0], &keys[1]],
        vec![TxOutput::new(1_900, recipient)],
        b"2of2".to_vec(),
    );

    let res = apply_block(&mut utxo, &[spend], 0);
    assert!(res.is_ok());
    assert_eq!(utxo.balance(&recipient), 1_900);
}

#[test]
fn test_multisig_2_of_3_all_subsets_success() {
    let keys = generate_keys(3);
    let pks = vec![
        *keys[0].address().payload(),
        *keys[1].address().payload(),
        *keys[2].address().payload(),
    ];
    let script = MultisigScript::new(2, pks).unwrap();
    let p2sh_addr = script.address();

    let subsets: [(&KeyPair, &KeyPair); 3] = [
        (&keys[0], &keys[1]), // {K1, K2}
        (&keys[0], &keys[2]), // {K1, K3}
        (&keys[1], &keys[2]), // {K2, K3}
    ];

    for (k_a, k_b) in subsets {
        let mut utxo = UtxoSet::new();
        let coinbase = Transaction::coinbase(vec![TxOutput::new(1_000, p2sh_addr)], b"cb".to_vec());
        let coin = OutPoint::new(coinbase.id(), 0);
        apply_block(&mut utxo, &[coinbase], 1_000).unwrap();

        let recipient = KeyPair::from_u64(99).address();
        let spend = build_multisig_spend(
            coin,
            script.encode(),
            &[k_a, k_b],
            vec![TxOutput::new(900, recipient)],
            b"sub".to_vec(),
        );

        let res = apply_block(&mut utxo, &[spend], 0);
        assert!(res.is_ok(), "failed subset spend");
        assert_eq!(utxo.balance(&recipient), 900);
    }
}

#[test]
fn test_multisig_3_of_5_spend_success() {
    let keys = generate_keys(5);
    let pks: Vec<[u8; 32]> = keys.iter().map(|k| *k.address().payload()).collect();
    let script = MultisigScript::new(3, pks).unwrap();
    let p2sh_addr = script.address();

    let mut utxo = UtxoSet::new();
    let coinbase = Transaction::coinbase(vec![TxOutput::new(5_000, p2sh_addr)], b"cb".to_vec());
    let coin = OutPoint::new(coinbase.id(), 0);
    apply_block(&mut utxo, &[coinbase], 5_000).unwrap();

    let recipient = KeyPair::from_u64(50).address();
    // Signers: K1, K3, K5
    let spend = build_multisig_spend(
        coin,
        script.encode(),
        &[&keys[0], &keys[2], &keys[4]],
        vec![TxOutput::new(4_800, recipient)],
        b"3of5".to_vec(),
    );

    let res = apply_block(&mut utxo, &[spend], 0);
    assert!(res.is_ok());
    assert_eq!(utxo.balance(&recipient), 4_800);
}

#[test]
fn test_multisig_16_of_16_max_keys_success() {
    let keys = generate_keys(MAX_MULTISIG_KEYS);
    let pks: Vec<[u8; 32]> = keys.iter().map(|k| *k.address().payload()).collect();
    let script = MultisigScript::new(16, pks).unwrap();
    let p2sh_addr = script.address();

    let mut utxo = UtxoSet::new();
    let coinbase = Transaction::coinbase(vec![TxOutput::new(16_000, p2sh_addr)], b"cb".to_vec());
    let coin = OutPoint::new(coinbase.id(), 0);
    apply_block(&mut utxo, &[coinbase], 16_000).unwrap();

    let signers: Vec<&KeyPair> = keys.iter().collect();
    let recipient = KeyPair::from_u64(100).address();
    let spend = build_multisig_spend(
        coin,
        script.encode(),
        &signers,
        vec![TxOutput::new(15_500, recipient)],
        b"16of16".to_vec(),
    );

    let res = apply_block(&mut utxo, &[spend], 0);
    assert!(res.is_ok());
    assert_eq!(utxo.balance(&recipient), 15_500);
}

#[test]
fn test_multisig_1_of_16_min_threshold_max_keys_success() {
    let keys = generate_keys(MAX_MULTISIG_KEYS);
    let pks: Vec<[u8; 32]> = keys.iter().map(|k| *k.address().payload()).collect();
    let script = MultisigScript::new(1, pks).unwrap();
    let p2sh_addr = script.address();

    let mut utxo = UtxoSet::new();
    let coinbase = Transaction::coinbase(vec![TxOutput::new(1_000, p2sh_addr)], b"cb".to_vec());
    let coin = OutPoint::new(coinbase.id(), 0);
    apply_block(&mut utxo, &[coinbase], 1_000).unwrap();

    // Sign with 15th key
    let recipient = KeyPair::from_u64(100).address();
    let spend = build_multisig_spend(
        coin,
        script.encode(),
        &[&keys[14]],
        vec![TxOutput::new(900, recipient)],
        b"1of16".to_vec(),
    );

    let res = apply_block(&mut utxo, &[spend], 0);
    assert!(res.is_ok());
    assert_eq!(utxo.balance(&recipient), 900);
}

// =========================================================================
// Category 2: Invalid M/N Combinations in Redeem Script
// =========================================================================

#[test]
fn test_redeem_script_zero_threshold_rejected() {
    let keys = generate_keys(2);
    let raw_script = make_redeem_script_bytes(0, &[&keys[0], &keys[1]]);
    let p2sh_addr = Address::from_script(&raw_script);

    let mut utxo = UtxoSet::new();
    let coinbase = Transaction::coinbase(vec![TxOutput::new(1_000, p2sh_addr)], b"cb".to_vec());
    let coin = OutPoint::new(coinbase.id(), 0);
    apply_block(&mut utxo, &[coinbase], 1_000).unwrap();

    let dummy_spend = TxInput {
        outpoint: coin,
        witness: vec![raw_script],
    };
    let tx = Transaction::new(
        vec![dummy_spend],
        vec![TxOutput::new(900, keys[0].address())],
        b"m".to_vec(),
    );

    let err = apply_block(&mut utxo, &[tx], 0).unwrap_err();
    assert!(matches!(err, LedgerError::InvalidRedeemScript { .. }));
}

#[test]
fn test_redeem_script_zero_key_count_rejected() {
    let raw_script = vec![0x01, 0x00]; // M=1, N=0
    let p2sh_addr = Address::from_script(&raw_script);

    let mut utxo = UtxoSet::new();
    let coinbase = Transaction::coinbase(vec![TxOutput::new(1_000, p2sh_addr)], b"cb".to_vec());
    let coin = OutPoint::new(coinbase.id(), 0);
    apply_block(&mut utxo, &[coinbase], 1_000).unwrap();

    let dummy_spend = TxInput {
        outpoint: coin,
        witness: vec![raw_script],
    };
    let tx = Transaction::new(
        vec![dummy_spend],
        vec![TxOutput::new(900, Address::p2pk([0u8; 32]))],
        b"m".to_vec(),
    );

    let err = apply_block(&mut utxo, &[tx], 0).unwrap_err();
    assert!(matches!(err, LedgerError::InvalidRedeemScript { .. }));
}

#[test]
fn test_redeem_script_threshold_exceeds_key_count_rejected() {
    let keys = generate_keys(2);
    let raw_script = make_redeem_script_bytes(3, &[&keys[0], &keys[1]]); // M=3, N=2
    let p2sh_addr = Address::from_script(&raw_script);

    let mut utxo = UtxoSet::new();
    let coinbase = Transaction::coinbase(vec![TxOutput::new(1_000, p2sh_addr)], b"cb".to_vec());
    let coin = OutPoint::new(coinbase.id(), 0);
    apply_block(&mut utxo, &[coinbase], 1_000).unwrap();

    let dummy_spend = TxInput {
        outpoint: coin,
        witness: vec![raw_script],
    };
    let tx = Transaction::new(
        vec![dummy_spend],
        vec![TxOutput::new(900, keys[0].address())],
        b"m".to_vec(),
    );

    let err = apply_block(&mut utxo, &[tx], 0).unwrap_err();
    assert!(matches!(err, LedgerError::InvalidRedeemScript { .. }));
}

#[test]
fn test_redeem_script_key_count_exceeds_max_16_rejected() {
    let keys = generate_keys(17);
    let key_refs: Vec<&KeyPair> = keys.iter().collect();
    let raw_script = make_redeem_script_bytes(1, &key_refs); // N=17
    let p2sh_addr = Address::from_script(&raw_script);

    let mut utxo = UtxoSet::new();
    let coinbase = Transaction::coinbase(vec![TxOutput::new(1_000, p2sh_addr)], b"cb".to_vec());
    let coin = OutPoint::new(coinbase.id(), 0);
    apply_block(&mut utxo, &[coinbase], 1_000).unwrap();

    let dummy_spend = TxInput {
        outpoint: coin,
        witness: vec![raw_script],
    };
    let tx = Transaction::new(
        vec![dummy_spend],
        vec![TxOutput::new(900, keys[0].address())],
        b"m".to_vec(),
    );

    let err = apply_block(&mut utxo, &[tx], 0).unwrap_err();
    assert!(matches!(err, LedgerError::InvalidRedeemScript { .. }));
}

#[test]
fn test_redeem_script_max_byte_values_rejected() {
    let mut raw_script = vec![0xFF, 0xFF]; // M=255, N=255
    raw_script.resize(2 + 32 * 255, 0x01);
    let p2sh_addr = Address::from_script(&raw_script);

    let mut utxo = UtxoSet::new();
    let coinbase = Transaction::coinbase(vec![TxOutput::new(1_000, p2sh_addr)], b"cb".to_vec());
    let coin = OutPoint::new(coinbase.id(), 0);
    apply_block(&mut utxo, &[coinbase], 1_000).unwrap();

    let dummy_spend = TxInput {
        outpoint: coin,
        witness: vec![raw_script],
    };
    let tx = Transaction::new(
        vec![dummy_spend],
        vec![TxOutput::new(900, Address::p2pk([0u8; 32]))],
        b"m".to_vec(),
    );

    let err = apply_block(&mut utxo, &[tx], 0).unwrap_err();
    assert!(matches!(err, LedgerError::InvalidRedeemScript { .. }));
}

// =========================================================================
// Category 3: Script Malformation & Non-Canonical Encodings
// =========================================================================

#[test]
fn test_redeem_script_empty_or_too_short_rejected() {
    let raw_script = vec![0x01]; // 1 byte
    let p2sh_addr = Address::from_script(&raw_script);

    let mut utxo = UtxoSet::new();
    let coinbase = Transaction::coinbase(vec![TxOutput::new(1_000, p2sh_addr)], b"cb".to_vec());
    let coin = OutPoint::new(coinbase.id(), 0);
    apply_block(&mut utxo, &[coinbase], 1_000).unwrap();

    let dummy_spend = TxInput {
        outpoint: coin,
        witness: vec![raw_script],
    };
    let tx = Transaction::new(
        vec![dummy_spend],
        vec![TxOutput::new(900, Address::p2pk([0u8; 32]))],
        b"m".to_vec(),
    );

    let err = apply_block(&mut utxo, &[tx], 0).unwrap_err();
    assert!(matches!(err, LedgerError::InvalidRedeemScript { .. }));
}

#[test]
fn test_redeem_script_truncated_rejected() {
    let keys = generate_keys(2);
    let mut raw_script = make_redeem_script_bytes(1, &[&keys[0], &keys[1]]); // Declares N=2 (66 bytes)
    raw_script.truncate(50); // Truncate to 50 bytes

    let p2sh_addr = Address::from_script(&raw_script);
    let mut utxo = UtxoSet::new();
    let coinbase = Transaction::coinbase(vec![TxOutput::new(1_000, p2sh_addr)], b"cb".to_vec());
    let coin = OutPoint::new(coinbase.id(), 0);
    apply_block(&mut utxo, &[coinbase], 1_000).unwrap();

    let dummy_spend = TxInput {
        outpoint: coin,
        witness: vec![raw_script],
    };
    let tx = Transaction::new(
        vec![dummy_spend],
        vec![TxOutput::new(900, keys[0].address())],
        b"m".to_vec(),
    );

    let err = apply_block(&mut utxo, &[tx], 0).unwrap_err();
    assert!(matches!(err, LedgerError::InvalidRedeemScript { .. }));
}

#[test]
fn test_redeem_script_trailing_garbage_bytes_rejected() {
    let keys = generate_keys(1);
    let mut raw_script = make_redeem_script_bytes(1, &[&keys[0]]); // Declares N=1 (34 bytes)
    raw_script.push(0x99); // 35 bytes

    let p2sh_addr = Address::from_script(&raw_script);
    let mut utxo = UtxoSet::new();
    let coinbase = Transaction::coinbase(vec![TxOutput::new(1_000, p2sh_addr)], b"cb".to_vec());
    let coin = OutPoint::new(coinbase.id(), 0);
    apply_block(&mut utxo, &[coinbase], 1_000).unwrap();

    let dummy_spend = TxInput {
        outpoint: coin,
        witness: vec![raw_script],
    };
    let tx = Transaction::new(
        vec![dummy_spend],
        vec![TxOutput::new(900, keys[0].address())],
        b"m".to_vec(),
    );

    let err = apply_block(&mut utxo, &[tx], 0).unwrap_err();
    assert!(matches!(err, LedgerError::InvalidRedeemScript { .. }));
}

#[test]
fn test_redeem_script_duplicate_public_keys_rejected() {
    let keys = generate_keys(1);
    let raw_script = make_redeem_script_bytes(2, &[&keys[0], &keys[0]]); // Duplicate K1
    let p2sh_addr = Address::from_script(&raw_script);

    let mut utxo = UtxoSet::new();
    let coinbase = Transaction::coinbase(vec![TxOutput::new(1_000, p2sh_addr)], b"cb".to_vec());
    let coin = OutPoint::new(coinbase.id(), 0);
    apply_block(&mut utxo, &[coinbase], 1_000).unwrap();

    let dummy_spend = TxInput {
        outpoint: coin,
        witness: vec![raw_script],
    };
    let tx = Transaction::new(
        vec![dummy_spend],
        vec![TxOutput::new(900, keys[0].address())],
        b"m".to_vec(),
    );

    let err = apply_block(&mut utxo, &[tx], 0).unwrap_err();
    assert!(matches!(err, LedgerError::InvalidRedeemScript { .. }));
}

// =========================================================================
// Category 4: Script Hash & Address Mismatch
// =========================================================================

#[test]
fn test_valid_script_wrong_address_hash_rejected() {
    let keys = generate_keys(2);
    let script_a = MultisigScript::new(1, vec![*keys[0].address().payload()]).unwrap();
    let script_b = MultisigScript::new(1, vec![*keys[1].address().payload()]).unwrap();

    let mut utxo = UtxoSet::new();
    // Locked to Script B
    let coinbase = Transaction::coinbase(
        vec![TxOutput::new(1_000, script_b.address())],
        b"cb".to_vec(),
    );
    let coin = OutPoint::new(coinbase.id(), 0);
    apply_block(&mut utxo, &[coinbase], 1_000).unwrap();

    // Spending with Script A
    let spend = build_multisig_spend(
        coin,
        script_a.encode(),
        &[&keys[0]],
        vec![TxOutput::new(900, keys[0].address())],
        b"m".to_vec(),
    );

    let err = apply_block(&mut utxo, &[spend], 0).unwrap_err();
    assert!(matches!(err, LedgerError::ScriptHashMismatch { .. }));
}

#[test]
fn test_single_bit_flip_in_script_hash_rejected() {
    let keys = generate_keys(1);
    let script = MultisigScript::new(1, vec![*keys[0].address().payload()]).unwrap();

    let mut utxo = UtxoSet::new();
    let coinbase =
        Transaction::coinbase(vec![TxOutput::new(1_000, script.address())], b"cb".to_vec());
    let coin = OutPoint::new(coinbase.id(), 0);
    apply_block(&mut utxo, &[coinbase], 1_000).unwrap();

    let mut tampered_script = script.encode();
    tampered_script[0] ^= 0x01; // flip 1 bit

    let spend = build_multisig_spend(
        coin,
        tampered_script,
        &[&keys[0]],
        vec![TxOutput::new(900, keys[0].address())],
        b"m".to_vec(),
    );

    let err = apply_block(&mut utxo, &[spend], 0).unwrap_err();
    assert!(matches!(err, LedgerError::ScriptHashMismatch { .. }));
}

// =========================================================================
// Category 5: Signature Count Anomalies (Threshold Violations)
// =========================================================================

#[test]
fn test_missing_signatures_insufficient_threshold_rejected() {
    let keys = generate_keys(3);
    let pks = vec![
        *keys[0].address().payload(),
        *keys[1].address().payload(),
        *keys[2].address().payload(),
    ];
    let script = MultisigScript::new(2, pks).unwrap(); // 2-of-3
    let p2sh_addr = script.address();

    let mut utxo = UtxoSet::new();
    let coinbase = Transaction::coinbase(vec![TxOutput::new(1_000, p2sh_addr)], b"cb".to_vec());
    let coin = OutPoint::new(coinbase.id(), 0);
    apply_block(&mut utxo, &[coinbase], 1_000).unwrap();

    // Provide only 1 signature for 2-of-3
    let spend = build_multisig_spend(
        coin,
        script.encode(),
        &[&keys[0]], // only 1
        vec![TxOutput::new(900, keys[0].address())],
        b"m".to_vec(),
    );

    let err = apply_block(&mut utxo, &[spend], 0).unwrap_err();
    assert!(matches!(
        err,
        LedgerError::InvalidWitnessCount {
            expected: 3,
            actual: 2,
            ..
        }
    ));
}

#[test]
fn test_zero_signatures_witness_only_script_rejected() {
    let keys = generate_keys(2);
    let script = MultisigScript::new(
        2,
        vec![*keys[0].address().payload(), *keys[1].address().payload()],
    )
    .unwrap();
    let p2sh_addr = script.address();

    let mut utxo = UtxoSet::new();
    let coinbase = Transaction::coinbase(vec![TxOutput::new(1_000, p2sh_addr)], b"cb".to_vec());
    let coin = OutPoint::new(coinbase.id(), 0);
    apply_block(&mut utxo, &[coinbase], 1_000).unwrap();

    // Witness contains only the redeem script (0 signatures)
    let spend = build_multisig_spend(
        coin,
        script.encode(),
        &[], // 0 signatures
        vec![TxOutput::new(900, keys[0].address())],
        b"m".to_vec(),
    );

    let err = apply_block(&mut utxo, &[spend], 0).unwrap_err();
    assert!(matches!(
        err,
        LedgerError::InvalidWitnessCount {
            expected: 3,
            actual: 1,
            ..
        }
    ));
}

#[test]
fn test_excess_signatures_rejected() {
    let keys = generate_keys(3);
    let pks = vec![
        *keys[0].address().payload(),
        *keys[1].address().payload(),
        *keys[2].address().payload(),
    ];
    let script = MultisigScript::new(2, pks).unwrap(); // 2-of-3
    let p2sh_addr = script.address();

    let mut utxo = UtxoSet::new();
    let coinbase = Transaction::coinbase(vec![TxOutput::new(1_000, p2sh_addr)], b"cb".to_vec());
    let coin = OutPoint::new(coinbase.id(), 0);
    apply_block(&mut utxo, &[coinbase], 1_000).unwrap();

    // Provide 3 signatures for 2-of-3
    let spend = build_multisig_spend(
        coin,
        script.encode(),
        &[&keys[0], &keys[1], &keys[2]], // 3 signatures
        vec![TxOutput::new(900, keys[0].address())],
        b"m".to_vec(),
    );

    let err = apply_block(&mut utxo, &[spend], 0).unwrap_err();
    assert!(matches!(
        err,
        LedgerError::InvalidWitnessCount {
            expected: 3,
            actual: 4,
            ..
        }
    ));
}

#[test]
fn test_empty_witness_stack_on_p2sh_spend_rejected() {
    let keys = generate_keys(1);
    let script = MultisigScript::new(1, vec![*keys[0].address().payload()]).unwrap();
    let p2sh_addr = script.address();

    let mut utxo = UtxoSet::new();
    let coinbase = Transaction::coinbase(vec![TxOutput::new(1_000, p2sh_addr)], b"cb".to_vec());
    let coin = OutPoint::new(coinbase.id(), 0);
    apply_block(&mut utxo, &[coinbase], 1_000).unwrap();

    let tx = Transaction::new(
        vec![TxInput {
            outpoint: coin,
            witness: Vec::new(), // completely empty
        }],
        vec![TxOutput::new(900, keys[0].address())],
        b"m".to_vec(),
    );

    let err = apply_block(&mut utxo, &[tx], 0).unwrap_err();
    assert!(matches!(
        err,
        LedgerError::InvalidWitnessCount {
            expected: 1,
            actual: 0,
            ..
        }
    ));
}

// =========================================================================
// Category 6: Cryptographic Signature Integrity & Key Authorization
// =========================================================================

#[test]
fn test_corrupted_signature_bytes_rejected() {
    let keys = generate_keys(2);
    let script = MultisigScript::new(
        2,
        vec![*keys[0].address().payload(), *keys[1].address().payload()],
    )
    .unwrap();
    let p2sh_addr = script.address();

    let mut utxo = UtxoSet::new();
    let coinbase = Transaction::coinbase(vec![TxOutput::new(1_000, p2sh_addr)], b"cb".to_vec());
    let coin = OutPoint::new(coinbase.id(), 0);
    apply_block(&mut utxo, &[coinbase], 1_000).unwrap();

    let mut tx = build_multisig_spend(
        coin,
        script.encode(),
        &[&keys[0], &keys[1]],
        vec![TxOutput::new(900, keys[0].address())],
        b"m".to_vec(),
    );
    // Corrupt signature byte
    tx.inputs_mut()[0].witness[1][0] ^= 0xFF;

    let err = apply_block(&mut utxo, &[tx], 0).unwrap_err();
    assert!(matches!(err, LedgerError::BadSignature { .. }));
}

#[test]
fn test_signature_from_unauthorized_key_rejected() {
    let keys = generate_keys(2);
    let outsider = KeyPair::from_u64(999);
    let script = MultisigScript::new(
        2,
        vec![*keys[0].address().payload(), *keys[1].address().payload()],
    )
    .unwrap();
    let p2sh_addr = script.address();

    let mut utxo = UtxoSet::new();
    let coinbase = Transaction::coinbase(vec![TxOutput::new(1_000, p2sh_addr)], b"cb".to_vec());
    let coin = OutPoint::new(coinbase.id(), 0);
    apply_block(&mut utxo, &[coinbase], 1_000).unwrap();

    // Signers: K1 + Outsider
    let tx = build_multisig_spend(
        coin,
        script.encode(),
        &[&keys[0], &outsider],
        vec![TxOutput::new(900, keys[0].address())],
        b"m".to_vec(),
    );

    let err = apply_block(&mut utxo, &[tx], 0).unwrap_err();
    assert!(matches!(err, LedgerError::BadSignature { .. }));
}

#[test]
fn test_signature_wrong_sighash_replay_rejected() {
    let keys = generate_keys(1);
    let script = MultisigScript::new(1, vec![*keys[0].address().payload()]).unwrap();
    let p2sh_addr = script.address();

    let mut utxo = UtxoSet::new();
    let coinbase = Transaction::coinbase(vec![TxOutput::new(1_000, p2sh_addr)], b"cb".to_vec());
    let coin = OutPoint::new(coinbase.id(), 0);
    apply_block(&mut utxo, &[coinbase], 1_000).unwrap();

    // Sign a dummy message instead of the transaction's sighash
    let wrong_sig = keys[0].sign(b"wrong_message").to_vec();
    let dummy_spend = TxInput {
        outpoint: coin,
        witness: vec![script.encode(), wrong_sig],
    };
    let tx = Transaction::new(
        vec![dummy_spend],
        vec![TxOutput::new(900, keys[0].address())],
        b"m".to_vec(),
    );

    let err = apply_block(&mut utxo, &[tx], 0).unwrap_err();
    assert!(matches!(err, LedgerError::BadSignature { .. }));
}

#[test]
fn test_malformed_signature_length_rejected() {
    let keys = generate_keys(1);
    let script = MultisigScript::new(1, vec![*keys[0].address().payload()]).unwrap();
    let p2sh_addr = script.address();

    let mut utxo = UtxoSet::new();
    let coinbase = Transaction::coinbase(vec![TxOutput::new(1_000, p2sh_addr)], b"cb".to_vec());
    let coin = OutPoint::new(coinbase.id(), 0);
    apply_block(&mut utxo, &[coinbase], 1_000).unwrap();

    // 63-byte signature
    let short_sig = vec![0x42u8; 63];
    let dummy_spend = TxInput {
        outpoint: coin,
        witness: vec![script.encode(), short_sig],
    };
    let tx = Transaction::new(
        vec![dummy_spend],
        vec![TxOutput::new(900, keys[0].address())],
        b"m".to_vec(),
    );

    let err = apply_block(&mut utxo, &[tx], 0).unwrap_err();
    assert!(matches!(err, LedgerError::BadSignatureSize { len: 63, .. }));
}

// =========================================================================
// Category 7: Duplicate Signature Attacks
// =========================================================================

#[test]
fn test_duplicate_signature_reuse_rejected() {
    let keys = generate_keys(2);
    let script = MultisigScript::new(
        2,
        vec![*keys[0].address().payload(), *keys[1].address().payload()],
    )
    .unwrap();
    let p2sh_addr = script.address();

    let mut utxo = UtxoSet::new();
    let coinbase = Transaction::coinbase(vec![TxOutput::new(1_000, p2sh_addr)], b"cb".to_vec());
    let coin = OutPoint::new(coinbase.id(), 0);
    apply_block(&mut utxo, &[coinbase], 1_000).unwrap();

    let mut tx = Transaction::new(
        vec![TxInput {
            outpoint: coin,
            witness: Vec::new(),
        }],
        vec![TxOutput::new(900, keys[0].address())],
        b"m".to_vec(),
    );
    let sighash = tx.sighash();
    let sig1 = keys[0].sign(&sighash).to_vec();

    // Attach sig1 TWICE to satisfy 2-of-2
    tx.inputs_mut()[0].witness = vec![script.encode(), sig1.clone(), sig1];

    let err = apply_block(&mut utxo, &[tx], 0).unwrap_err();
    assert!(matches!(err, LedgerError::DuplicateSignature { .. }));
}

// =========================================================================
// Category 8: Consensus Activation & Pre-Activation Gating
// =========================================================================

#[test]
fn test_pre_activation_p2sh_output_rejected() {
    let keys = generate_keys(1);
    let script = MultisigScript::new(1, vec![*keys[0].address().payload()]).unwrap();
    let p2sh_addr = script.address();

    let (mut ledger, coin) = funded_ledger(keys[0].address(), 1_000);
    ledger.set_multisig_activation_score(100); // Activated at blue score > 100

    // Attempt to create P2SH output at blue score 1
    let tx = Transaction::signed(
        &[(coin, &keys[0])],
        vec![TxOutput::new(900, p2sh_addr)],
        b"pre".to_vec(),
    );

    let err = ledger
        .insert(vec![ledger.genesis()], 1, 1, 0, &[tx])
        .unwrap_err();
    assert!(matches!(
        err,
        LedgerInsertError::State(LedgerError::PreActivationMultisig {
            blue_score: 1,
            activation_score: 100,
            ..
        })
    ));
}

#[test]
fn test_exact_activation_boundary_transition() {
    let keys = generate_keys(1);
    let script = MultisigScript::new(1, vec![*keys[0].address().payload()]).unwrap();
    let p2sh_addr = script.address();

    let (mut ledger, mut current_coin) = funded_ledger(keys[0].address(), 1_000);
    ledger.set_multisig_activation_score(2); // Activates at blue score > 2

    let mut parent = ledger.genesis();

    // Advance chain: Block 1 (blue score 1)
    let tx1 = Transaction::signed(
        &[(current_coin, &keys[0])],
        vec![TxOutput::new(950, keys[0].address())],
        b"b1".to_vec(),
    );
    current_coin = OutPoint::new(tx1.id(), 0);
    parent = ledger
        .insert(vec![parent], 1, 1, 0, &[tx1])
        .expect("b1 valid");

    // Block 2 (blue score 2): still pre-activation (score <= 2)
    // Attempting P2SH output in Block 2 must fail!
    let tx_fail = Transaction::signed(
        &[(current_coin, &keys[0])],
        vec![TxOutput::new(900, p2sh_addr)],
        b"b2_fail".to_vec(),
    );
    let err = ledger
        .insert(vec![parent], 1, 2, 0, &[tx_fail])
        .unwrap_err();
    assert!(matches!(
        err,
        LedgerInsertError::State(LedgerError::PreActivationMultisig {
            blue_score: 2,
            activation_score: 2,
            ..
        })
    ));

    // Submit valid P2PK tx for Block 2
    let tx2 = Transaction::signed(
        &[(current_coin, &keys[0])],
        vec![TxOutput::new(900, keys[0].address())],
        b"b2".to_vec(),
    );
    current_coin = OutPoint::new(tx2.id(), 0);
    parent = ledger
        .insert(vec![parent], 1, 2, 0, &[tx2])
        .expect("b2 valid");

    // Block 3 (blue score 3): post-activation (score 3 > 2)!
    // P2SH output is now accepted!
    let tx3 = Transaction::signed(
        &[(current_coin, &keys[0])],
        vec![TxOutput::new(850, p2sh_addr)],
        b"b3".to_vec(),
    );
    let p2sh_coin = OutPoint::new(tx3.id(), 0);
    parent = ledger
        .insert(vec![parent], 1, 3, 0, &[tx3])
        .expect("b3 valid post-activation");

    // Block 4 (blue score 4): P2SH spend is accepted!
    let spend_tx = build_multisig_spend(
        p2sh_coin,
        script.encode(),
        &[&keys[0]],
        vec![TxOutput::new(800, keys[0].address())],
        b"b4".to_vec(),
    );
    let res = ledger.insert(vec![parent], 1, 4, 0, &[spend_tx]);
    assert!(res.is_ok(), "b4 spend valid post-activation");
}

#[test]
fn test_legacy_p2pk_permanently_valid_post_activation() {
    let alice = KeyPair::from_u64(1);
    let bob = KeyPair::from_u64(2);

    let (mut ledger, coin) = funded_ledger(alice.address(), 1_000);
    ledger.set_multisig_activation_score(0); // Active from start

    let transfer = Transaction::signed(
        &[(coin, &alice)],
        vec![TxOutput::new(900, bob.address())],
        b"p2pk".to_vec(),
    );
    let id = ledger.insert(vec![ledger.genesis()], 1, 1, 0, &[transfer]);
    assert!(id.is_ok());
    assert_eq!(ledger.ledger_state().balance(&bob.address()), 900);
}

// =========================================================================
// Category 9: Mixed Transaction Blocks & Mixed Inputs
// =========================================================================

#[test]
fn test_mixed_block_p2pk_and_p2sh_transactions_coexist() {
    let kp_a = KeyPair::from_u64(1);
    let kp_b = KeyPair::from_u64(2);
    let script = MultisigScript::new(1, vec![*kp_a.address().payload()]).unwrap();
    let p2sh_addr = script.address();

    let mut utxo = UtxoSet::new();
    let cb1 = Transaction::coinbase(
        vec![
            TxOutput::new(1_000, kp_a.address()),
            TxOutput::new(2_000, p2sh_addr),
        ],
        b"cb".to_vec(),
    );
    let coin_p2pk = OutPoint::new(cb1.id(), 0);
    let coin_p2sh = OutPoint::new(cb1.id(), 1);
    apply_block(&mut utxo, &[cb1], 3_000).unwrap();

    // Tx 1: P2PK -> P2SH
    let tx1 = Transaction::signed(
        &[(coin_p2pk, &kp_a)],
        vec![TxOutput::new(900, p2sh_addr)],
        b"tx1".to_vec(),
    );
    // Tx 2: P2SH -> P2PK
    let tx2 = build_multisig_spend(
        coin_p2sh,
        script.encode(),
        &[&kp_a],
        vec![TxOutput::new(1_900, kp_b.address())],
        b"tx2".to_vec(),
    );

    let res = apply_block(&mut utxo, &[tx1, tx2], 0);
    assert!(res.is_ok());
    assert_eq!(utxo.balance(&kp_b.address()), 1_900);
    assert_eq!(utxo.balance(&p2sh_addr), 900);
}

#[test]
fn test_single_tx_mixed_inputs_p2pk_and_p2sh() {
    let kp_a = KeyPair::from_u64(1);
    let kp_b = KeyPair::from_u64(2);
    let script = MultisigScript::new(
        2,
        vec![*kp_a.address().payload(), *kp_b.address().payload()],
    )
    .unwrap();
    let p2sh_addr = script.address();

    let mut utxo = UtxoSet::new();
    let cb = Transaction::coinbase(
        vec![
            TxOutput::new(1_000, kp_a.address()), // P2PK
            TxOutput::new(2_000, p2sh_addr),      // P2SH
        ],
        b"cb".to_vec(),
    );
    let coin_p2pk = OutPoint::new(cb.id(), 0);
    let coin_p2sh = OutPoint::new(cb.id(), 1);
    apply_block(&mut utxo, &[cb], 3_000).unwrap();

    // Construct transaction spending both inputs together
    let mut tx = Transaction::new(
        vec![
            TxInput {
                outpoint: coin_p2pk,
                witness: Vec::new(),
            },
            TxInput {
                outpoint: coin_p2sh,
                witness: Vec::new(),
            },
        ],
        vec![TxOutput::new(2_900, kp_b.address())],
        b"mixed".to_vec(),
    );
    let sighash = tx.sighash();

    // Input 0: P2PK witness (1 item)
    tx.inputs_mut()[0].witness = vec![kp_a.sign(&sighash).to_vec()];
    // Input 1: P2SH witness (1 script + 2 signatures)
    tx.inputs_mut()[1].witness = vec![
        script.encode(),
        kp_a.sign(&sighash).to_vec(),
        kp_b.sign(&sighash).to_vec(),
    ];

    let res = apply_block(&mut utxo, &[tx], 0);
    assert!(res.is_ok());
    assert_eq!(utxo.balance(&kp_b.address()), 2_900);
}

// =========================================================================
// Category 10: Cross-Type Witness Mismatches & DAG Properties
// =========================================================================

#[test]
fn test_p2pk_spent_with_multisig_witness_rejected() {
    let kp = KeyPair::from_u64(1);
    let mut utxo = UtxoSet::new();
    let cb = Transaction::coinbase(vec![TxOutput::new(1_000, kp.address())], b"cb".to_vec());
    let coin = OutPoint::new(cb.id(), 0);
    apply_block(&mut utxo, &[cb], 1_000).unwrap();

    // Attach 2-item witness to P2PK spend
    let tx = Transaction::new(
        vec![TxInput {
            outpoint: coin,
            witness: vec![vec![0u8; 64], vec![0u8; 64]], // 2 items
        }],
        vec![TxOutput::new(900, kp.address())],
        b"m".to_vec(),
    );

    let err = apply_block(&mut utxo, &[tx], 0).unwrap_err();
    assert!(matches!(
        err,
        LedgerError::InvalidWitnessCount {
            expected: 1,
            actual: 2,
            ..
        }
    ));
}

#[test]
fn test_p2sh_spent_with_single_sig_witness_rejected() {
    let kp = KeyPair::from_u64(1);
    let script = MultisigScript::new(1, vec![*kp.address().payload()]).unwrap();

    let mut utxo = UtxoSet::new();
    let cb = Transaction::coinbase(vec![TxOutput::new(1_000, script.address())], b"cb".to_vec());
    let coin = OutPoint::new(cb.id(), 0);
    apply_block(&mut utxo, &[cb], 1_000).unwrap();

    // Provide single signature without script to P2SH spend
    let tx = Transaction::new(
        vec![TxInput {
            outpoint: coin,
            witness: vec![vec![0u8; 64]], // 1 item (a signature, not the redeem script)
        }],
        vec![TxOutput::new(900, kp.address())],
        b"m".to_vec(),
    );

    let err = apply_block(&mut utxo, &[tx], 0).unwrap_err();
    assert!(matches!(err, LedgerError::ScriptHashMismatch { .. }));
}

#[test]
fn test_multisig_double_spend_in_parallel_blocks_resolved_by_linearization() {
    let miner = KeyPair::from_u64(1);
    let kp = KeyPair::from_u64(2);
    let script = MultisigScript::new(1, vec![*kp.address().payload()]).unwrap();
    let p2sh_addr = script.address();

    // Genesis funds miner (P2PK)
    let genesis_cb =
        Transaction::coinbase(vec![TxOutput::new(1_000, miner.address())], b"gen".to_vec());
    let coin_gen = OutPoint::new(genesis_cb.id(), 0);

    let genesis_block = Block::genesis(1, 0, 0, encode_block_payload(&[genesis_cb]));
    let genesis_id = genesis_block.id();
    let mut dag = Dag::new(3, genesis_block);

    // Block 1 transfers miner -> P2SH address
    let fund_p2sh = Transaction::signed(
        &[(coin_gen, &miner)],
        vec![TxOutput::new(950, p2sh_addr)],
        b"fund".to_vec(),
    );
    let coin_p2sh = OutPoint::new(fund_p2sh.id(), 0);
    let block_1 = Block::new(
        vec![genesis_id],
        1,
        1,
        0,
        encode_block_payload(&[fund_p2sh]),
    );
    let id_1 = dag.insert(block_1).unwrap();

    let alice = KeyPair::from_u64(10).address();
    let bob = KeyPair::from_u64(20).address();

    // Block A spends coin to Alice
    let spend_a = build_multisig_spend(
        coin_p2sh,
        script.encode(),
        &[&kp],
        vec![TxOutput::new(900, alice)],
        b"a".to_vec(),
    );
    let block_a = Block::new(vec![id_1], 10, 2, 0, encode_block_payload(&[spend_a]));
    let id_a = dag.insert(block_a).unwrap();

    // Block B spends SAME coin to Bob in parallel
    let spend_b = build_multisig_spend(
        coin_p2sh,
        script.encode(),
        &[&kp],
        vec![TxOutput::new(900, bob)],
        b"b".to_vec(),
    );
    let block_b = Block::new(vec![id_1], 5, 2, 0, encode_block_payload(&[spend_b]));
    let id_b = dag.insert(block_b).unwrap();

    // Linearize and apply DAG
    let order = dag.linearize();
    let (winner, loser, winner_addr, loser_addr) =
        if order.iter().position(|b| *b == id_a) < order.iter().position(|b| *b == id_b) {
            (id_a, id_b, alice, bob)
        } else {
            (id_b, id_a, bob, alice)
        };

    let run = apply_dag(&dag, 1_000);
    assert_eq!(run.accepted.len(), 3); // Genesis + Block 1 + winner
    assert_eq!(run.rejected.len(), 1); // Loser
    assert_eq!(run.accepted[2], winner);
    assert_eq!(run.rejected[0].0, loser);
    assert!(matches!(run.rejected[0].1, LedgerError::MissingInput(_)));

    assert_eq!(run.utxo.balance(&winner_addr), 900);
    assert_eq!(run.utxo.balance(&loser_addr), 0);
}

#[test]
fn test_multisig_ledger_snapshot_and_replay_roundtrip() {
    let kp = KeyPair::from_u64(1);
    let script = MultisigScript::new(1, vec![*kp.address().payload()]).unwrap();

    let (mut ledger, coin) = funded_ledger(script.address(), 1_000);

    let recipient = KeyPair::from_u64(5).address();
    let spend = build_multisig_spend(
        coin,
        script.encode(),
        &[&kp],
        vec![TxOutput::new(900, recipient)],
        b"snap".to_vec(),
    );
    ledger
        .insert(vec![ledger.genesis()], 1, 1, 0, &[spend])
        .unwrap();

    // Snapshot write & read
    let snapshot_bytes = ledger.write_snapshot();
    let restored_ledger = Ledger::read_snapshot(&snapshot_bytes).expect("valid snapshot restore");

    assert_eq!(
        ledger.ledger_state().balance(&recipient),
        restored_ledger.ledger_state().balance(&recipient)
    );
    assert_eq!(restored_ledger.ledger_state().balance(&recipient), 900);
}
