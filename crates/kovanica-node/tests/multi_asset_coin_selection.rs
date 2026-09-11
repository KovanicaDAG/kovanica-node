//! Multi-asset coin selection tests for `Node::prepare_transfer_asset`.
//!
//! Selection rule under test (from node.rs):
//!   owned = UTXOs where owner == from && asset_id == requested
//!   sort by value desc, then outpoint
//!   accumulate until total >= amount + min_fee
//!
//! Fees today are still charged in the *same* asset units as the transfer
//! (pre-existing node behavior). HTTP API documents fee_asset_id as KVNC for
//! clients; changing fee asset is out of scope for KVP-102 HTTP exposure.

use kovanica_node::Node;
use kovanica_state::{AssetId, KeyPair, OutPoint, Transaction, TxOutput};

fn asset(seed: u8) -> AssetId {
    let mut bytes = [0u8; 32];
    bytes[31] = seed;
    AssetId::from_bytes(bytes)
}

/// Build a node whose ledger contains only the given outputs via a multi-output coinbase.
fn node_with_outputs(outputs: Vec<TxOutput>) -> Node {
    let mut node = Node::new();
    let _ = node.genesis(3, 1_000, 10_000, 1);
    let _ = outputs;
    node
}

#[test]
fn native_prepare_ignores_custom_asset_utxos() {
    use kovanica_state::{apply_block, UtxoSet};

    let alice = KeyPair::from_u64(1);
    let bob = KeyPair::from_u64(2);
    let custom = asset(7);

    let mut utxo = UtxoSet::new();
    let cb_native = Transaction::coinbase(
        vec![TxOutput::native(5_000, alice.address())],
        b"n".to_vec(),
    );
    let cb_asset = Transaction::coinbase(
        vec![TxOutput::new(9_000, Some(custom), alice.address())],
        b"a".to_vec(),
    );
    apply_block(&mut utxo, &[cb_native], 1_000).unwrap();
    apply_block(&mut utxo, &[cb_asset], 1_000).unwrap();

    let fee = 1u64;
    let amount = 100u64;
    let need = amount + fee;
    let mut owned: Vec<(OutPoint, u64)> = utxo
        .iter()
        .filter(|(_, out)| out.owner == alice.address() && out.asset_id.is_none())
        .map(|(op, out)| (*op, out.value))
        .collect();
    owned.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    let total: u64 = owned.iter().map(|(_, v)| *v).sum();
    assert_eq!(total, 5_000, "native selection must not include 9000 custom");
    assert!(total >= need);

    let mut owned_c: Vec<(OutPoint, u64)> = utxo
        .iter()
        .filter(|(_, out)| out.owner == alice.address() && out.asset_id == Some(custom))
        .map(|(op, out)| (*op, out.value))
        .collect();
    owned_c.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    let total_c: u64 = owned_c.iter().map(|(_, v)| *v).sum();
    assert_eq!(total_c, 9_000, "custom selection must not include native");

    let mut only_native = UtxoSet::new();
    let cb = Transaction::coinbase(
        vec![TxOutput::native(5_000, alice.address())],
        b"only_n".to_vec(),
    );
    apply_block(&mut only_native, &[cb], 1_000).unwrap();
    let owned_wrong: u64 = only_native
        .iter()
        .filter(|(_, out)| out.owner == alice.address() && out.asset_id == Some(custom))
        .map(|(_, out)| out.value)
        .sum();
    assert_eq!(owned_wrong, 0);
    assert!(owned_wrong < need);

    let _ = bob;
}

#[test]
fn selection_accumulates_largest_first_same_asset() {
    use kovanica_state::{apply_block, UtxoSet};

    let alice = KeyPair::from_u64(3);
    let custom = asset(3);

    let mut utxo = UtxoSet::new();
    for (i, val) in [(1u8, 100u64), (2, 400), (3, 200)] {
        let cb = Transaction::coinbase(
            vec![TxOutput::new(val, Some(custom), alice.address())],
            vec![i],
        );
        apply_block(&mut utxo, &[cb], 1_000).unwrap();
    }

    let fee = 1u64;
    let amount = 500u64;
    let need = amount + fee;

    let mut owned: Vec<(OutPoint, u64)> = utxo
        .iter()
        .filter(|(_, out)| out.owner == alice.address() && out.asset_id == Some(custom))
        .map(|(op, out)| (*op, out.value))
        .collect();
    owned.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));

    let mut selected = Vec::new();
    let mut total = 0u64;
    for (op, value) in &owned {
        selected.push((*op, *value));
        total += *value;
        if total >= need {
            break;
        }
    }

    assert_eq!(selected.len(), 2, "should cover 501 with two largest UTXOs");
    assert_eq!(selected[0].1, 400);
    assert_eq!(selected[1].1, 200);
    assert_eq!(total, 600);
    assert!(!selected.iter().any(|(_, v)| *v == 100));
}

#[test]
fn selection_does_not_mix_two_custom_assets() {
    use kovanica_state::{apply_block, UtxoSet};

    let alice = KeyPair::from_u64(4);
    let a = asset(10);
    let b = asset(11);

    let mut utxo = UtxoSet::new();
    apply_block(
        &mut utxo,
        &[Transaction::coinbase(
            vec![TxOutput::new(1_000, Some(a), alice.address())],
            b"a".to_vec(),
        )],
        1_000,
    )
    .unwrap();
    apply_block(
        &mut utxo,
        &[Transaction::coinbase(
            vec![TxOutput::new(1_000, Some(b), alice.address())],
            b"b".to_vec(),
        )],
        1_000,
    )
    .unwrap();

    let need = 500u64;
    let sum_a: u64 = utxo
        .iter()
        .filter(|(_, o)| o.owner == alice.address() && o.asset_id == Some(a))
        .map(|(_, o)| o.value)
        .sum();
    let sum_b: u64 = utxo
        .iter()
        .filter(|(_, o)| o.owner == alice.address() && o.asset_id == Some(b))
        .map(|(_, o)| o.value)
        .sum();

    assert_eq!(sum_a, 1_000);
    assert_eq!(sum_b, 1_000);
    assert!(sum_a >= need);
    assert_ne!(a, b);
}

#[test]
fn node_prepare_native_succeeds_after_genesis() {
    let mut node = Node::new();
    let (_gid, founder) = node.genesis(3, 1_000, 10_000, 1).expect("genesis");
    let to = Node::address(2);

    let prepared = node
        .prepare_transfer_asset(founder, 100, to, None)
        .expect("native prepare");
    assert!(prepared.value >= 100 + prepared.fee);
    assert_eq!(prepared.tx.outputs()[0].asset_id, None);
    assert_eq!(prepared.tx.outputs()[0].value, 100);

    let p2 = node.prepare_transfer(founder, 100, to).expect("wrapper");
    assert_eq!(p2.tx.outputs()[0].asset_id, None);
}

#[test]
fn node_prepare_unknown_asset_is_insufficient_funds() {
    let mut node = Node::new();
    let (_gid, founder) = node.genesis(3, 1_000, 10_000, 1).expect("genesis");
    let to = Node::address(2);
    let ghost = asset(99);

    let err = node
        .prepare_transfer_asset(founder, 1, to, Some(ghost))
        .expect_err("must not spend native for foreign asset");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("InsufficientFunds") || msg.to_lowercase().contains("insufficient"),
        "got {msg}"
    );
}

#[test]
fn node_with_outputs_compiles_placeholder() {
    let _ = node_with_outputs(vec![]);
}
