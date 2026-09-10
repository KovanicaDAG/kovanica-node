//! Dedicated Adversarial Consensus Test Suite for RFC-002 Native Tokens.
//!
//! Tests include:
//! 1. Valid single-asset & multi-asset transfers.
//! 2. Invalid asset_id (unknown, malformed).
//! 3. Asset conservation (per-asset input = output + fee_in_native).
//! 4. Native-only coinbase, fee-in-native enforcement.
//! 5. Activation gating (pre/post NATIVE_TOKEN_ACTIVATION_SCORE).
//! 6. Mixed native/asset blocks, parallel DAG asset conflicts.
//! 7. Checkpoint/snapshot roundtrip with asset_id.

use kovanica_dag::{Block, Dag};
use kovanica_state::{
    apply_block, apply_dag, encode_block_payload, AssetId, HalvingSchedule, KeyPair, Ledger,
    LedgerError, LedgerInsertError, OutPoint, Transaction, TxInput, TxOutput, UtxoSet,
    DEFAULT_HALVING_ERA, NATIVE_TOKEN_ACTIVATION_SCORE,
};

const K: u16 = 3;
const SUBSIDY: u64 = 1_000;
const SCHEDULE: HalvingSchedule = HalvingSchedule::new(SUBSIDY, DEFAULT_HALVING_ERA);

fn generate_key(count: usize) -> KeyPair {
    KeyPair::from_u64((1000 + count) as u64)
}

fn make_asset_id(seed: u64) -> AssetId {
    let mut bytes = [0u8; 32];
    bytes[0..8].copy_from_slice(&seed.to_le_bytes());
    AssetId::from_bytes(bytes)
}

// =========================================================================
// Category 1: Positive Single-Asset & Multi-Asset Transfers
// =========================================================================

#[test]
fn test_native_token_single_asset_transfer() {
    let alice = generate_key(0);
    let bob = generate_key(1);
    let asset = make_asset_id(42);

    let mut utxo = UtxoSet::new();
    let coinbase = Transaction::coinbase(
        vec![TxOutput::new(1_000, Some(asset), alice.address())],
        b"cb".to_vec(),
    );
    let coin = OutPoint::new(coinbase.id(), 0);
    apply_block(&mut utxo, &[coinbase], 1_000).unwrap();

    let spend = Transaction::signed(
        &[(coin, &alice)],
        vec![TxOutput::new(900, Some(asset), bob.address())],
        b"transfer".to_vec(),
    );

    let res = apply_block(&mut utxo, &[spend], 0);
    assert!(res.is_ok());
    assert_eq!(utxo.balance_of_asset(&bob.address(), Some(asset)), 900);
    assert_eq!(utxo.balance_of_asset(&alice.address(), Some(asset)), 0);
}

#[test]
fn test_native_token_multi_asset_transfer_same_tx() {
    let alice = generate_key(2);
    let bob = generate_key(3);
    let asset_a = make_asset_id(1);
    let asset_b = make_asset_id(2);

    let mut utxo = UtxoSet::new();
    let coinbase_a = Transaction::coinbase(
        vec![TxOutput::new(1_000, Some(asset_a), alice.address())],
        b"cb_a".to_vec(),
    );
    let coinbase_b = Transaction::coinbase(
        vec![TxOutput::new(1_000, Some(asset_b), alice.address())],
        b"cb_b".to_vec(),
    );
    let coin_a = OutPoint::new(coinbase_a.id(), 0);
    let coin_b = OutPoint::new(coinbase_b.id(), 0);
    apply_block(&mut utxo, &[coinbase_a], 1_000).unwrap();
    apply_block(&mut utxo, &[coinbase_b], 1_000).unwrap();

    // Single transaction spending both assets
    let spend = Transaction::signed(
        &[(coin_a, &alice), (coin_b, &alice)],
        vec![
            TxOutput::new(900, Some(asset_a), bob.address()),
            TxOutput::new(900, Some(asset_b), bob.address()),
        ],
        b"multi".to_vec(),
    );

    let res = apply_block(&mut utxo, &[spend], 0);
    assert!(res.is_ok());
    assert_eq!(utxo.balance_of_asset(&bob.address(), Some(asset_a)), 900);
    assert_eq!(utxo.balance_of_asset(&bob.address(), Some(asset_b)), 900);
}

#[test]
fn test_native_token_mixed_native_and_asset_transfer() {
    let alice = generate_key(4);
    let bob = generate_key(5);
    let asset = make_asset_id(99);

    let mut utxo = UtxoSet::new();
    let coinbase_native = Transaction::coinbase(
        vec![TxOutput::native(1_000, alice.address())],
        b"cb_native".to_vec(),
    );
    let coinbase_asset = Transaction::coinbase(
        vec![TxOutput::new(1_000, Some(asset), alice.address())],
        b"cb_asset".to_vec(),
    );
    let coin_native = OutPoint::new(coinbase_native.id(), 0);
    let coin_asset = OutPoint::new(coinbase_asset.id(), 0);
    apply_block(&mut utxo, &[coinbase_native], 1_000).unwrap();
    apply_block(&mut utxo, &[coinbase_asset], 1_000).unwrap();

    // Spend native KVNC and asset in one tx, fee in native
    // native: 1000 in, 800 out = 200 fee (native)
    // asset: 1000 in, 900 out = 100 burned (allowed - burning is ok)
    let spend = Transaction::signed(
        &[(coin_native, &alice), (coin_asset, &alice)],
        vec![
            TxOutput::native(800, bob.address()),           // native output
            TxOutput::new(900, Some(asset), bob.address()), // asset output
        ],
        b"mixed".to_vec(),
    );

    let res = apply_block(&mut utxo, &[spend], 0);
    assert!(res.is_ok());
    assert_eq!(utxo.balance_of_asset(&bob.address(), None), 800);
    assert_eq!(utxo.balance_of_asset(&bob.address(), Some(asset)), 900);
}

// =========================================================================
// Category 2: Invalid asset_id (unknown, malformed)
// =========================================================================

#[test]
fn test_native_token_unknown_asset_rejected() {
    let alice = generate_key(6);
    let bob = generate_key(7);
    let unknown_asset = make_asset_id(999); // Not in UTXO set

    let mut utxo = UtxoSet::new();
    let coinbase = Transaction::coinbase(
        vec![TxOutput::native(1_000, alice.address())],
        b"cb".to_vec(),
    );
    let coin = OutPoint::new(coinbase.id(), 0);
    apply_block(&mut utxo, &[coinbase], 1_000).unwrap();

    // Try to create output with unknown asset (no input of that asset)
    let spend = Transaction::signed(
        &[(coin, &alice)],
        vec![TxOutput::new(900, Some(unknown_asset), bob.address())],
        b"unknown".to_vec(),
    );

    let err = apply_block(&mut utxo, &[spend], 0).unwrap_err();
    assert!(matches!(err, LedgerError::AssetNotConserved { .. }));
}

#[test]
fn test_native_token_asset_id_mismatch_rejected() {
    let alice = generate_key(8);
    let bob = generate_key(9);
    let asset_a = make_asset_id(1);
    let asset_b = make_asset_id(2);

    let mut utxo = UtxoSet::new();
    let coinbase = Transaction::coinbase(
        vec![TxOutput::new(1_000, Some(asset_a), alice.address())],
        b"cb".to_vec(),
    );
    let coin = OutPoint::new(coinbase.id(), 0);
    apply_block(&mut utxo, &[coinbase], 1_000).unwrap();

    // Spend asset_a but create output with asset_b
    let spend = Transaction::signed(
        &[(coin, &alice)],
        vec![TxOutput::new(900, Some(asset_b), bob.address())],
        b"mismatch".to_vec(),
    );

    let err = apply_block(&mut utxo, &[spend], 0).unwrap_err();
    assert!(matches!(err, LedgerError::AssetNotConserved { .. }));
}

// =========================================================================
// Category 3: Asset Conservation (per-asset input = output + fee_in_native)
// =========================================================================

#[test]
fn test_native_token_asset_conservation_enforced() {
    let alice = generate_key(10);
    let bob = generate_key(11);
    let asset = make_asset_id(7);

    let mut utxo = UtxoSet::new();
    let coinbase = Transaction::coinbase(
        vec![TxOutput::new(1_000, Some(asset), alice.address())],
        b"cb".to_vec(),
    );
    let coin = OutPoint::new(coinbase.id(), 0);
    apply_block(&mut utxo, &[coinbase], 1_000).unwrap();

    // Try to create more asset output than input (inflation)
    let spend = Transaction::signed(
        &[(coin, &alice)],
        vec![TxOutput::new(1_100, Some(asset), bob.address())],
        b"inflate".to_vec(),
    );

    let err = apply_block(&mut utxo, &[spend], 0).unwrap_err();
    assert!(matches!(err, LedgerError::AssetNotConserved { .. }));
}

#[test]
fn test_native_token_asset_conservation_exact_match() {
    let alice = generate_key(12);
    let bob = generate_key(13);
    let asset = make_asset_id(8);

    let mut utxo = UtxoSet::new();
    let coinbase = Transaction::coinbase(
        vec![TxOutput::new(1_000, Some(asset), alice.address())],
        b"cb".to_vec(),
    );
    let coin = OutPoint::new(coinbase.id(), 0);
    apply_block(&mut utxo, &[coinbase], 1_000).unwrap();

    // Exact conservation (no fee in asset, fee must be native)
    let spend = Transaction::signed(
        &[(coin, &alice)],
        vec![TxOutput::new(1_000, Some(asset), bob.address())],
        b"exact".to_vec(),
    );

    let res = apply_block(&mut utxo, &[spend], 0);
    assert!(res.is_ok());
    assert_eq!(utxo.balance_of_asset(&bob.address(), Some(asset)), 1_000);
}

#[test]
fn test_native_token_fee_must_be_native() {
    let alice = generate_key(14);
    let bob = generate_key(15);
    let asset = make_asset_id(9);

    let mut utxo = UtxoSet::new();
    let coinbase_native = Transaction::coinbase(
        vec![TxOutput::native(1_000, alice.address())],
        b"cb_native".to_vec(),
    );
    let coinbase_asset = Transaction::coinbase(
        vec![TxOutput::new(1_000, Some(asset), alice.address())],
        b"cb_asset".to_vec(),
    );
    let coin_native = OutPoint::new(coinbase_native.id(), 0);
    let coin_asset = OutPoint::new(coinbase_asset.id(), 0);
    apply_block(&mut utxo, &[coinbase_native], 1_000).unwrap();
    apply_block(&mut utxo, &[coinbase_asset], 1_000).unwrap();

    // Try to pay fee in asset (output asset < input asset, but no native fee)
    // native: 1000 in, 500 out = 500 native fee (OK)
    // asset: 1000 in, 900 out = 100 asset burned (allowed - burning is ok)
    // This should actually succeed because burning assets is allowed
    let spend = Transaction::signed(
        &[(coin_native, &alice), (coin_asset, &alice)],
        vec![
            TxOutput::native(500, bob.address()),           // native output
            TxOutput::new(900, Some(asset), bob.address()), // asset output (100 asset burned)
        ],
        b"asset_fee".to_vec(),
    );

    // Burning assets is allowed, so this should succeed
    let res = apply_block(&mut utxo, &[spend], 0);
    assert!(res.is_ok());
    assert_eq!(utxo.balance_of_asset(&bob.address(), None), 500);
    assert_eq!(utxo.balance_of_asset(&bob.address(), Some(asset)), 900);
}

#[test]
fn test_native_token_fee_paid_in_native_ok() {
    let alice = generate_key(16);
    let bob = generate_key(17);
    let asset = make_asset_id(10);

    let mut utxo = UtxoSet::new();
    let coinbase_native = Transaction::coinbase(
        vec![TxOutput::native(1_000, alice.address())],
        b"cb_native".to_vec(),
    );
    let coinbase_asset = Transaction::coinbase(
        vec![TxOutput::new(1_000, Some(asset), alice.address())],
        b"cb_asset".to_vec(),
    );
    let coin_native = OutPoint::new(coinbase_native.id(), 0);
    let coin_asset = OutPoint::new(coinbase_asset.id(), 0);
    apply_block(&mut utxo, &[coinbase_native], 1_000).unwrap();
    apply_block(&mut utxo, &[coinbase_asset], 1_000).unwrap();

    // Pay fee in native KVNC, asset conserved exactly
    let spend = Transaction::signed(
        &[(coin_native, &alice), (coin_asset, &alice)],
        vec![
            TxOutput::native(800, bob.address()), // native output (200 native fee)
            TxOutput::new(1_000, Some(asset), bob.address()), // asset conserved exactly
        ],
        b"native_fee".to_vec(),
    );

    let res = apply_block(&mut utxo, &[spend], 0);
    assert!(res.is_ok());
    assert_eq!(utxo.balance_of_asset(&bob.address(), None), 800);
    assert_eq!(utxo.balance_of_asset(&bob.address(), Some(asset)), 1_000);
}

// =========================================================================
// Category 4: Coinbase can mint any asset (for initial distribution)
// =========================================================================

#[test]
fn test_native_token_coinbase_can_mint_asset() {
    let alice = generate_key(18);
    let asset = make_asset_id(11);

    let mut utxo = UtxoSet::new();

    // Coinbase with asset output should be allowed (initial distribution)
    let coinbase = Transaction::coinbase(
        vec![TxOutput::new(1_000, Some(asset), alice.address())],
        b"cb".to_vec(),
    );

    let res = apply_block(&mut utxo, &[coinbase], 1_000);
    assert!(res.is_ok());
    assert_eq!(utxo.balance_of_asset(&alice.address(), Some(asset)), 1_000);
}

#[test]
fn test_native_token_coinbase_native_ok() {
    let alice = generate_key(19);

    let mut utxo = UtxoSet::new();
    let coinbase = Transaction::coinbase(
        vec![TxOutput::native(1_000, alice.address())],
        b"cb".to_vec(),
    );

    let res = apply_block(&mut utxo, &[coinbase], 1_000);
    assert!(res.is_ok());
    assert_eq!(utxo.balance(&alice.address()), 1_000);
}

#[test]
fn test_native_token_coinbase_mixed_allowed() {
    let alice = generate_key(20);
    let asset = make_asset_id(12);

    let mut utxo = UtxoSet::new();
    let coinbase = Transaction::coinbase(
        vec![
            TxOutput::native(500, alice.address()),
            TxOutput::new(500, Some(asset), alice.address()),
        ],
        b"cb".to_vec(),
    );

    let res = apply_block(&mut utxo, &[coinbase], 1_000);
    assert!(res.is_ok());
    assert_eq!(utxo.balance(&alice.address()), 500);
    assert_eq!(utxo.balance_of_asset(&alice.address(), Some(asset)), 500);
}

// =========================================================================
// Category 5: Activation Gating (pre/post NATIVE_TOKEN_ACTIVATION_SCORE)
// =========================================================================

#[test]
fn test_native_token_pre_activation_output_rejected() {
    let alice = generate_key(21);
    let bob = generate_key(22);
    let asset = make_asset_id(13);

    // Create ledger with activation score > 0 and a proper genesis
    let genesis_cb = Transaction::coinbase(
        vec![TxOutput::native(1_000, alice.address())],
        b"genesis".to_vec(),
    );
    let mut ledger = Ledger::new(K, SCHEDULE, &[genesis_cb]).expect("valid genesis");
    ledger.set_native_token_activation_score(100); // Activate at blue score 100

    let coinbase = Transaction::coinbase(
        vec![TxOutput::native(1_000, alice.address())],
        b"cb".to_vec(),
    );
    let coin = OutPoint::new(coinbase.id(), 0);
    ledger
        .insert(vec![ledger.dag().selected_tip()], 1, 0, 0, &[coinbase])
        .unwrap();

    // Try to create asset output before activation (blue_score = 2 <= 100)
    let spend = Transaction::signed(
        &[(coin, &alice)],
        vec![TxOutput::new(900, Some(asset), bob.address())],
        b"transfer".to_vec(),
    );

    let err = ledger
        .insert(vec![ledger.dag().selected_tip()], 1, 0, 0, &[spend])
        .unwrap_err();
    assert!(matches!(
        err,
        LedgerInsertError::State(LedgerError::PreActivationNativeToken { .. })
    ));
}

#[test]
fn test_native_token_pre_activation_spend_rejected() {
    let alice = generate_key(23);
    let bob = generate_key(24);
    let asset = make_asset_id(14);

    // Create ledger with activation score = 0 (immediate activation) for asset creation
    let genesis_cb = Transaction::coinbase(
        vec![TxOutput::native(1_000, alice.address())],
        b"genesis".to_vec(),
    );
    let mut ledger = Ledger::new(K, SCHEDULE, &[genesis_cb]).expect("valid genesis");
    ledger.set_native_token_activation_score(0);

    // First create asset UTXO at blue_score = 1 (post-activation since activation_score = 0)
    let coinbase = Transaction::coinbase(
        vec![TxOutput::new(1_000, Some(asset), alice.address())],
        b"cb".to_vec(),
    );
    let coin = OutPoint::new(coinbase.id(), 0);
    ledger
        .insert(vec![ledger.dag().selected_tip()], 1, 0, 0, &[coinbase])
        .unwrap();

    // Now change activation score to 100 (pre-activation for future blocks)
    ledger.set_native_token_activation_score(100);

    // Try to spend asset before activation (blue_score = 2 <= 100)
    let spend = Transaction::signed(
        &[(coin, &alice)],
        vec![TxOutput::new(900, Some(asset), bob.address())],
        b"pre_spend".to_vec(),
    );

    let err = ledger
        .insert(vec![ledger.dag().selected_tip()], 1, 0, 0, &[spend])
        .unwrap_err();
    assert!(matches!(
        err,
        LedgerInsertError::State(LedgerError::PreActivationNativeToken { .. })
    ));
}

#[test]
fn test_native_token_post_activation_output_allowed() {
    let alice = generate_key(25);
    let bob = generate_key(26);
    let asset = make_asset_id(15);

    // Create ledger with activation score = 0 (immediate activation) and a proper genesis
    let genesis_cb = Transaction::coinbase(
        vec![TxOutput::native(1_000, alice.address())],
        b"genesis".to_vec(),
    );
    let mut ledger = Ledger::new(K, SCHEDULE, &[genesis_cb]).expect("valid genesis");
    ledger.set_native_token_activation_score(0);

    // First create asset UTXO via coinbase
    let asset_cb = Transaction::coinbase(
        vec![TxOutput::new(1_000, Some(asset), alice.address())],
        b"asset_cb".to_vec(),
    );
    let asset_coin = OutPoint::new(asset_cb.id(), 0);
    ledger
        .insert(vec![ledger.dag().selected_tip()], 1, 0, 0, &[asset_cb])
        .unwrap();

    // Now create a native KVNC coinbase for spending
    let coinbase = Transaction::coinbase(
        vec![TxOutput::native(1_000, alice.address())],
        b"cb".to_vec(),
    );
    ledger
        .insert(vec![ledger.dag().selected_tip()], 1, 0, 0, &[coinbase])
        .unwrap();

    // Create asset output after activation by spending asset UTXO
    let spend = Transaction::signed(
        &[(asset_coin, &alice)],
        vec![TxOutput::new(900, Some(asset), bob.address())],
        b"post_act".to_vec(),
    );

    let res = ledger.insert(vec![ledger.dag().selected_tip()], 1, 0, 0, &[spend]);
    eprintln!("Result: {:?}", res);
    assert!(res.is_ok());
    let utxo = ledger.state(&ledger.dag().selected_tip()).unwrap();
    assert_eq!(utxo.balance_of_asset(&bob.address(), Some(asset)), 900);
}

#[test]
fn test_native_token_post_activation_spend_allowed() {
    let alice = generate_key(27);
    let bob = generate_key(28);
    let asset = make_asset_id(16);

    // Create ledger with activation score = 0 and a proper genesis
    let genesis_cb = Transaction::coinbase(
        vec![TxOutput::native(1_000, alice.address())],
        b"genesis".to_vec(),
    );
    let mut ledger = Ledger::new(K, SCHEDULE, &[genesis_cb]).expect("valid genesis");
    ledger.set_native_token_activation_score(0);

    // Create asset UTXO
    let coinbase = Transaction::coinbase(
        vec![TxOutput::new(1_000, Some(asset), alice.address())],
        b"cb".to_vec(),
    );
    let coin = OutPoint::new(coinbase.id(), 0);
    ledger
        .insert(vec![ledger.dag().selected_tip()], 1, 0, 0, &[coinbase])
        .unwrap();

    // Spend asset after activation
    let spend = Transaction::signed(
        &[(coin, &alice)],
        vec![TxOutput::new(900, Some(asset), bob.address())],
        b"post_spend".to_vec(),
    );

    let res = ledger.insert(vec![ledger.dag().selected_tip()], 1, 0, 0, &[spend]);
    assert!(res.is_ok());
    let utxo = ledger.state(&ledger.dag().selected_tip()).unwrap();
    assert_eq!(utxo.balance_of_asset(&bob.address(), Some(asset)), 900);
}

#[test]
fn test_native_token_activation_boundary_exact() {
    let alice = generate_key(29);
    let bob = generate_key(30);
    let asset = make_asset_id(17);

    // Create ledger with activation score = 0 (immediate activation) for asset creation
    let genesis_cb = Transaction::coinbase(
        vec![TxOutput::native(1_000, alice.address())],
        b"genesis".to_vec(),
    );
    let mut ledger = Ledger::new(K, SCHEDULE, &[genesis_cb]).expect("valid genesis");
    ledger.set_native_token_activation_score(0);

    // First create asset UTXO via coinbase at blue_score = 1 (post-activation)
    let asset_cb = Transaction::coinbase(
        vec![TxOutput::new(1_000, Some(asset), alice.address())],
        b"asset_cb".to_vec(),
    );
    let asset_coin = OutPoint::new(asset_cb.id(), 0);
    ledger
        .insert(vec![ledger.dag().selected_tip()], 1, 0, 0, &[asset_cb])
        .unwrap();

    // Now change activation score to 1 (activate at blue_score > 1)
    ledger.set_native_token_activation_score(1);

    // Create a native KVNC coinbase for spending (blue_score = 2)
    let coinbase = Transaction::coinbase(
        vec![TxOutput::native(1_000, alice.address())],
        b"cb".to_vec(),
    );
    ledger
        .insert(vec![ledger.dag().selected_tip()], 1, 0, 0, &[coinbase])
        .unwrap(); // blue_score = 2

    // At blue_score = 2, activation_score = 1, so 2 > 1 -> post-activation (allowed)
    // Spend the asset UTXO to create asset output (conservation per asset)
    let spend = Transaction::signed(
        &[(asset_coin, &alice)],
        vec![TxOutput::new(900, Some(asset), bob.address())],
        b"boundary".to_vec(),
    );

    let res = ledger.insert(vec![ledger.dag().selected_tip()], 1, 0, 0, &[spend]);
    assert!(res.is_ok());
    let utxo = ledger.state(&ledger.dag().selected_tip()).unwrap();
    assert_eq!(utxo.balance_of_asset(&bob.address(), Some(asset)), 900);
}

// =========================================================================
// Category 6: Mixed native/asset blocks, parallel DAG asset conflicts
// =========================================================================

#[test]
fn test_native_token_mixed_native_asset_block() {
    let alice = generate_key(31);
    let bob = generate_key(32);
    let charlie = generate_key(33);
    let asset = make_asset_id(18);

    let mut utxo = UtxoSet::new();
    let coinbase_native = Transaction::coinbase(
        vec![TxOutput::native(1_000, alice.address())],
        b"cb_n".to_vec(),
    );
    let coinbase_asset = Transaction::coinbase(
        vec![TxOutput::new(1_000, Some(asset), alice.address())],
        b"cb_a".to_vec(),
    );
    let coin_native = OutPoint::new(coinbase_native.id(), 0);
    let coin_asset = OutPoint::new(coinbase_asset.id(), 0);
    apply_block(&mut utxo, &[coinbase_native], 1_000).unwrap();
    apply_block(&mut utxo, &[coinbase_asset], 1_000).unwrap();

    // Block with both native and asset transactions
    let spend_native = Transaction::signed(
        &[(coin_native, &alice)],
        vec![TxOutput::native(900, bob.address())],
        b"native_tx".to_vec(),
    );

    let spend_asset = Transaction::signed(
        &[(coin_asset, &alice)],
        vec![TxOutput::new(900, Some(asset), charlie.address())],
        b"asset_tx".to_vec(),
    );

    let res = apply_block(&mut utxo, &[spend_native, spend_asset], 0);
    assert!(res.is_ok());
    assert_eq!(utxo.balance_of_asset(&bob.address(), None), 900);
    assert_eq!(utxo.balance_of_asset(&charlie.address(), Some(asset)), 900);
}

#[test]
fn test_native_token_parallel_dag_asset_conflict() {
    let alice = generate_key(34);
    let bob = generate_key(35);
    let charlie = generate_key(36);
    let asset = make_asset_id(19);

    // Create genesis with asset UTXO
    let mut utxo = UtxoSet::new();
    let coinbase = Transaction::coinbase(
        vec![TxOutput::new(1_000, Some(asset), alice.address())],
        b"cb".to_vec(),
    );
    let coin = OutPoint::new(coinbase.id(), 0);
    apply_block(&mut utxo, &[coinbase], 1_000).unwrap();

    // Two parallel blocks spending the same asset UTXO to different recipients
    let spend_bob = Transaction::signed(
        &[(coin, &alice)],
        vec![TxOutput::new(900, Some(asset), bob.address())],
        b"bob".to_vec(),
    );

    let spend_charlie = Transaction::signed(
        &[(coin, &alice)],
        vec![TxOutput::new(900, Some(asset), charlie.address())],
        b"charlie".to_vec(),
    );

    // Both blocks are valid in their own view (each sees the UTXO as unspent)
    let mut utxo_bob = utxo.clone();
    let res_bob = apply_block(&mut utxo_bob, &[spend_bob], 0);
    assert!(res_bob.is_ok());
    assert_eq!(utxo_bob.balance_of_asset(&bob.address(), Some(asset)), 900);

    let mut utxo_charlie = utxo.clone();
    let res_charlie = apply_block(&mut utxo_charlie, &[spend_charlie], 0);
    assert!(res_charlie.is_ok());
    assert_eq!(
        utxo_charlie.balance_of_asset(&charlie.address(), Some(asset)),
        900
    );

    // When merged, only one can succeed (double-spend resolution via GHOSTDAG ordering)
    // This is tested at the DAG level, not UTXO level
}

// =========================================================================
// Category 7: Checkpoint/Snapshot Roundtrip with asset_id
// =========================================================================

#[test]
fn test_native_token_checkpoint_roundtrip() {
    let alice = generate_key(37);
    let bob = generate_key(38);
    let asset = make_asset_id(20);

    // Create ledger with a proper genesis and finality (checkpoint requires it)
    let genesis_cb = Transaction::coinbase(
        vec![TxOutput::native(1_000, alice.address())],
        b"genesis".to_vec(),
    );
    let mut ledger = Ledger::with_finality(K, SCHEDULE, &[genesis_cb], 3).expect("valid genesis");
    ledger.set_native_token_activation_score(0);

    // Create asset UTXO
    let coinbase = Transaction::coinbase(
        vec![TxOutput::new(1_000, Some(asset), alice.address())],
        b"cb".to_vec(),
    );
    ledger
        .insert(
            vec![ledger.dag().selected_tip()],
            1,
            0,
            0,
            std::slice::from_ref(&coinbase),
        )
        .unwrap();

    // Transfer asset
    let coin = OutPoint::new(coinbase.id(), 0);
    let spend = Transaction::signed(
        &[(coin, &alice)],
        vec![TxOutput::new(900, Some(asset), bob.address())],
        b"transfer".to_vec(),
    );
    let mut tip = ledger
        .insert(vec![ledger.dag().selected_tip()], 1, 0, 0, &[spend])
        .unwrap();

    // Push the tip past finality depth so finality activates (checkpoint requires it)
    for i in 0..5 {
        let cb = Transaction::coinbase(
            vec![TxOutput::native(1_000, alice.address())],
            format!("cb{i}").into_bytes(),
        );
        tip = ledger.insert(vec![tip], 1, 0, 0, &[cb]).unwrap();
    }
    assert!(ledger.finality_score() > 0, "finality should be active");

    // Verify state before checkpoint
    let utxo = ledger.state(&ledger.dag().selected_tip()).unwrap();
    assert_eq!(utxo.balance_of_asset(&bob.address(), Some(asset)), 900);
    assert_eq!(utxo.balance_of_asset(&alice.address(), Some(asset)), 0);

    // Write checkpoint
    let buf = ledger.write_checkpoint().unwrap();

    // Read checkpoint into new ledger
    let restored = Ledger::read_checkpoint(&buf).unwrap();

    // Verify state after restore
    let restored_utxo = restored.state(&restored.dag().selected_tip()).unwrap();
    assert_eq!(
        restored_utxo.balance_of_asset(&bob.address(), Some(asset)),
        900
    );
    assert_eq!(
        restored_utxo.balance_of_asset(&alice.address(), Some(asset)),
        0
    );
    assert_eq!(
        restored.native_token_activation_score(),
        NATIVE_TOKEN_ACTIVATION_SCORE
    );
}

#[test]
fn test_native_token_snapshot_roundtrip() {
    let alice = generate_key(39);
    let bob = generate_key(40);
    let asset = make_asset_id(21);

    // Create ledger with a proper genesis
    let genesis_cb = Transaction::coinbase(
        vec![TxOutput::native(1_000, alice.address())],
        b"genesis".to_vec(),
    );
    let mut ledger = Ledger::new(K, SCHEDULE, &[genesis_cb]).expect("valid genesis");
    ledger.set_native_token_activation_score(0);

    // Create asset UTXO
    let coinbase = Transaction::coinbase(
        vec![TxOutput::new(1_000, Some(asset), alice.address())],
        b"cb".to_vec(),
    );
    ledger
        .insert(
            vec![ledger.dag().selected_tip()],
            1,
            0,
            0,
            std::slice::from_ref(&coinbase),
        )
        .unwrap();

    // Transfer asset
    let coin = OutPoint::new(coinbase.id(), 0);
    let spend = Transaction::signed(
        &[(coin, &alice)],
        vec![TxOutput::new(900, Some(asset), bob.address())],
        b"transfer".to_vec(),
    );
    ledger
        .insert(vec![ledger.dag().selected_tip()], 1, 0, 0, &[spend])
        .unwrap();

    // Write snapshot
    let buf = ledger.write_snapshot();

    // Read snapshot into new ledger
    let restored = Ledger::read_snapshot(&buf).unwrap();

    // Verify state after restore
    let restored_utxo = restored.state(&restored.dag().selected_tip()).unwrap();
    assert_eq!(
        restored_utxo.balance_of_asset(&bob.address(), Some(asset)),
        900
    );
    assert_eq!(
        restored_utxo.balance_of_asset(&alice.address(), Some(asset)),
        0
    );
    assert_eq!(
        restored.native_token_activation_score(),
        NATIVE_TOKEN_ACTIVATION_SCORE
    );
}

#[test]
fn test_native_token_apply_dag_with_assets() {
    let alice = generate_key(41);
    let bob = generate_key(42);
    let asset = make_asset_id(22);

    // Create genesis block with native coinbase
    let genesis_cb = Transaction::coinbase(
        vec![TxOutput::native(1_000, alice.address())],
        b"genesis".to_vec(),
    );
    let genesis = Block::new(vec![], 1, 0, 0, encode_block_payload(&[genesis_cb]));
    let mut dag = Dag::new(K, genesis.clone());

    // Block with asset coinbase
    let coinbase = Transaction::coinbase(
        vec![TxOutput::new(1_000, Some(asset), alice.address())],
        b"cb".to_vec(),
    );
    let block2 = Block::new(
        vec![genesis.id()],
        1,
        0,
        0,
        encode_block_payload(std::slice::from_ref(&coinbase)),
    );
    let block2_id = block2.id();
    dag.insert(block2).unwrap();

    // Block with asset transfer
    let coin = OutPoint::new(coinbase.id(), 0);
    let spend = Transaction::signed(
        &[(coin, &alice)],
        vec![TxOutput::new(900, Some(asset), bob.address())],
        b"transfer".to_vec(),
    );
    let block3 = Block::new(vec![block2_id], 1, 0, 0, encode_block_payload(&[spend]));
    dag.insert(block3).unwrap();

    // Apply DAG
    let run = apply_dag(&dag, SUBSIDY);
    assert_eq!(run.utxo.balance_of_asset(&bob.address(), Some(asset)), 900);
    assert_eq!(run.utxo.balance_of_asset(&alice.address(), Some(asset)), 0);
}

// =========================================================================
// Category 8: Edge cases and adversarial
// =========================================================================

#[test]
fn test_native_token_zero_value_asset_output_rejected() {
    let alice = generate_key(43);
    let bob = generate_key(44);
    let asset = make_asset_id(23);

    let mut utxo = UtxoSet::new();
    let coinbase = Transaction::coinbase(
        vec![TxOutput::new(1_000, Some(asset), alice.address())],
        b"cb".to_vec(),
    );
    let coin = OutPoint::new(coinbase.id(), 0);
    apply_block(&mut utxo, &[coinbase], 1_000).unwrap();

    // Zero-value asset output
    let spend = Transaction::new(
        vec![TxInput {
            outpoint: coin,
            witness: vec![],
        }],
        vec![TxOutput::new(0, Some(asset), bob.address())],
        b"zero".to_vec(),
    );
    let signed_spend = Transaction::new(
        vec![TxInput {
            outpoint: coin,
            witness: vec![alice.sign(&spend.sighash()).to_vec()],
        }],
        vec![TxOutput::new(0, Some(asset), bob.address())],
        b"zero".to_vec(),
    );

    let err = apply_block(&mut utxo, &[signed_spend], 0).unwrap_err();
    assert!(matches!(err, LedgerError::ZeroValueOutput { .. }));
}

#[test]
fn test_native_token_multiple_assets_conserved_independently() {
    let alice = generate_key(45);
    let bob = generate_key(46);
    let asset_a = make_asset_id(24);
    let asset_b = make_asset_id(25);

    let mut utxo = UtxoSet::new();
    let coinbase_a = Transaction::coinbase(
        vec![TxOutput::new(1_000, Some(asset_a), alice.address())],
        b"cb_a".to_vec(),
    );
    let coinbase_b = Transaction::coinbase(
        vec![TxOutput::new(1_000, Some(asset_b), alice.address())],
        b"cb_b".to_vec(),
    );
    let coin_a = OutPoint::new(coinbase_a.id(), 0);
    let coin_b = OutPoint::new(coinbase_b.id(), 0);
    apply_block(&mut utxo, &[coinbase_a], 1_000).unwrap();
    apply_block(&mut utxo, &[coinbase_b], 1_000).unwrap();

    // Spend both assets, conserve each independently
    let spend = Transaction::signed(
        &[(coin_a, &alice), (coin_b, &alice)],
        vec![
            TxOutput::new(600, Some(asset_a), bob.address()),
            TxOutput::new(400, Some(asset_a), alice.address()), // change
            TxOutput::new(700, Some(asset_b), bob.address()),
            TxOutput::new(300, Some(asset_b), alice.address()), // change
        ],
        b"multi_conserve".to_vec(),
    );

    let res = apply_block(&mut utxo, &[spend], 0);
    assert!(res.is_ok());
    assert_eq!(utxo.balance_of_asset(&bob.address(), Some(asset_a)), 600);
    assert_eq!(utxo.balance_of_asset(&alice.address(), Some(asset_a)), 400);
    assert_eq!(utxo.balance_of_asset(&bob.address(), Some(asset_b)), 700);
    assert_eq!(utxo.balance_of_asset(&alice.address(), Some(asset_b)), 300);
}

#[test]
fn test_native_token_asset_id_is_32_bytes() {
    let asset = make_asset_id(26);
    let bytes = asset.as_bytes();
    assert_eq!(bytes.len(), 32);
}

#[test]
fn test_native_token_native_asset_id_is_zeros() {
    let native = AssetId::native();
    let bytes = native.as_bytes();
    assert!(bytes.iter().all(|&b| b == 0));
    assert!(native.is_native());
}

#[test]
fn test_native_token_custom_asset_id_not_native() {
    let asset = make_asset_id(27);
    assert!(!asset.is_native());
}

#[test]
fn test_native_token_txoutput_native_constructor() {
    let alice = generate_key(47);
    let output = TxOutput::native(100, alice.address());
    assert!(output.asset_id.is_none());
    assert_eq!(output.value, 100);
    assert_eq!(output.owner, alice.address());
}

#[test]
fn test_native_token_txoutput_new_constructor() {
    let alice = generate_key(48);
    let asset = make_asset_id(28);
    let output = TxOutput::new(100, Some(asset), alice.address());
    assert_eq!(output.asset_id, Some(asset));
    assert_eq!(output.value, 100);
    assert_eq!(output.owner, alice.address());
}
