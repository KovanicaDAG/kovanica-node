//! Tests for the FFI surface — the exact API foreign bindings expose. If a
//! flow works here it works from Kotlin/Swift; anything unreachable through
//! `LightNode` is deliberately not part of the mobile contract.

use kovanica_ffi::{BlockKind, LightConfig, LightNode, U128Parts};

const NOMINAL_WORK: U128Parts = U128Parts { high: 0, low: 7 };

fn fresh() -> LightNode {
    LightNode::new(LightConfig::default()).expect("genesis ok")
}

/// A light node with a validator identity and hybrid admission active.
fn validator_node() -> LightNode {
    let node = fresh();
    node.set_validator_seed(vec![0xAB; 32]).unwrap();
    node.enable_hybrid(1, 1, NOMINAL_WORK, false).unwrap();
    node
}

fn temp_path(label: &str) -> String {
    use std::sync::atomic::{AtomicU32, Ordering};
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let mut p = std::env::temp_dir();
    p.push(format!(
        "kovanica-ffi-{}-{n}-{label}.snapshot",
        std::process::id()
    ));
    p.to_string_lossy().into_owned()
}

#[test]
fn genesis_lifecycle_and_queries() {
    let node = fresh();
    assert_eq!(node.balance_of_seed(1).unwrap(), "1000");
    assert!(!node.hybrid_enabled());
    assert_eq!(node.block_count().unwrap(), 1);

    // Tip ids are well-formed hex.
    let tip = node.selected_tip().unwrap();
    assert_eq!(hex::decode(&tip).unwrap().len(), 32);
    assert!(!node.tips().unwrap().is_empty());

    // Address-form balance query accepts the founder's own rendering.
    let addr_hex = kovanica_node::Node::address(1).to_hex();
    assert_eq!(node.balance_of_address(addr_hex).unwrap(), "1000");
}

#[test]
fn seed_length_is_validated() {
    let node = fresh();
    let err = node.set_validator_seed(vec![1; 31]).unwrap_err();
    assert!(err.to_string().contains("32 bytes"), "{err}");
}

#[test]
fn bonding_requires_validator_identity() {
    let node = fresh();
    node.enable_hybrid(1, 1, NOMINAL_WORK, false).unwrap();
    let err = node.bond_stake(1, 500).unwrap_err();
    assert!(err.to_string().contains("set_validator_seed"), "{err}");
}

#[test]
fn bond_splits_then_freezes_and_staked_block_wins() {
    let node = validator_node();

    // The founder holds one coin of exactly 1000; bonding 500 forces a sizing
    // split (500 frozen + 500 spendable), then the bond transaction itself.
    assert_eq!(node.total_stake().unwrap(), 0);
    let bond_tx_hex = node.bond_stake(1, 500).unwrap();
    assert_eq!(hex::decode(&bond_tx_hex).unwrap().len(), 32);

    assert_eq!(node.total_stake().unwrap(), 500);
    assert_eq!(node.my_stake().unwrap(), 500);

    // Steady-state heartbeat with an empty mempool: the draw wins.
    let info = node.produce_empty_block().unwrap();
    assert_eq!(info.kind, BlockKind::Staked, "full bonded share must win");
    assert_eq!(
        info.work, NOMINAL_WORK,
        "staked blocks pinned to nominal work"
    );

    // The split remainder is still spendable: transfer part of it onward.
    let receipt = node.send(1, 400, 2).unwrap();
    let sealed = node
        .block_by_id(receipt.block_id_hex.clone())
        .unwrap()
        .expect("send's block is known");
    assert_eq!(sealed.id_hex, receipt.block_id_hex);
}

#[test]
fn rebonding_skips_frozen_coins_and_refills_from_coinbase() {
    let node = validator_node();
    node.bond_stake(1, 500).unwrap();

    // Only an unfrozen 500-coin remains: a second 500-bond must reuse it
    // exactly (no split needed), not try to spend the frozen output.
    node.bond_stake(1, 500).unwrap();
    assert_eq!(node.total_stake().unwrap(), 1000);

    // Unfrozen funds are exhausted — but this node is also the miner, and the
    // sizing/bond flow's own blocks pay founder coinbase, so a third bond is
    // funded from freshly mined coins while frozen outputs stay untouched.
    node.bond_stake(1, 500).unwrap();
    assert_eq!(node.total_stake().unwrap(), 1500);

    // A wallet-less actor genuinely cannot bond: nothing to size or spend.
    assert!(node.bond_stake(9, 500).is_err());
}

#[test]
fn unbonded_validator_falls_back_to_pow() {
    let node = validator_node(); // identity set, NOTHING bonded
    let info = node.produce_empty_block().unwrap();
    assert_eq!(
        info.kind,
        BlockKind::Pow,
        "missed draw must fall back to PoW"
    );
    // Without a retargeting policy the PoW path carries the ledger's legacy
    // fixed work target — deliberately NOT the staked nominal weight.
    assert_ne!(info.work, NOMINAL_WORK);
}

#[test]
fn sync_blob_between_two_nodes_converges() {
    let producer = validator_node();
    producer.bond_stake(1, 500).unwrap();
    producer.produce_empty_block().unwrap();
    producer.send(1, 400, 2).unwrap();
    let staked_tip_before = producer.selected_tip().unwrap();

    // The peer starts identical (genesis) and catches up purely from bytes.
    let peer = fresh();
    peer.set_validator_seed(vec![0xCD; 32]).unwrap();
    peer.enable_hybrid(1, 1, NOMINAL_WORK, false).unwrap();

    let applied = peer.receive_blocks(producer.export_blocks()).unwrap();
    assert!(
        applied >= 4,
        "split+bond+staked+send at minimum, got {applied}"
    );
    assert_eq!(peer.selected_tip().unwrap(), staked_tip_before);
    assert_eq!(peer.total_stake().unwrap(), 500);
    assert_eq!(
        peer.balance_of_seed(2).unwrap(),
        producer.balance_of_seed(2).unwrap()
    );

    // Idempotent: re-offering the same history adopts nothing new
    // (known blocks re-validate as no-ops rather than erroring).
    let before = peer.block_count().unwrap();
    let _ = peer.receive_blocks(producer.export_blocks()).unwrap();
    assert_eq!(peer.block_count().unwrap(), before);
}

#[test]
fn garbage_sync_blob_is_rejected_not_panicked_on() {
    let peer = fresh();
    let err = peer.receive_blocks(vec![0xFF; 64]).unwrap_err();
    assert!(
        err.to_string().to_lowercase().contains("blob") || err.to_string().contains("undecodable")
    );
}

#[test]
fn snapshot_roundtrip_preserves_staked_ids_and_keeps_producing() {
    let node = validator_node();
    node.bond_stake(1, 500).unwrap();
    let staked = node.produce_empty_block().unwrap();
    assert_eq!(staked.kind, BlockKind::Staked);

    let path = temp_path("roundtrip");
    node.save_snapshot(path.clone()).unwrap();

    // Restore into a brand-new node that runs the same policy BEFORE loading:
    // hybrid replay keeps every staked id intact.
    let restored = validator_node();
    restored.load_snapshot(path.clone()).unwrap();
    assert_eq!(
        restored.selected_tip().unwrap(),
        node.selected_tip().unwrap()
    );

    let back = restored
        .block_by_id(staked.id_hex.clone())
        .unwrap()
        .expect("staked id survived");
    assert_eq!(back.kind, BlockKind::Staked);
    assert_eq!(restored.total_stake().unwrap(), 500);

    // And the restored validator can keep producing immediately.
    let next = restored.produce_empty_block().unwrap();
    assert_eq!(next.kind, BlockKind::Staked);

    let _ = std::fs::remove_file(&path);
}

#[test]
fn send_from_uses_imported_secret_without_storing_it() {
    let node = fresh();

    // The demo founder's secret is from_u64(1): le bytes zero-padded.
    let mut founder_secret = [0u8; 32];
    founder_secret[..8].copy_from_slice(&1u64.to_le_bytes());

    let to_addr = kovanica_node::Node::address(2).to_hex();
    let receipt = node
        .send_from(hex::encode(founder_secret), 400, to_addr.clone())
        .unwrap();
    assert_eq!(node.balance_of_seed(2).unwrap(), "400");
    assert!(node.block_by_id(receipt.block_id_hex).unwrap().is_some());

    // Wrong-length secrets are rejected up front.
    let err = node.send_from("abcd".to_string(), 1, to_addr).unwrap_err();
    assert!(err.to_string().contains("32 bytes"), "{err}");
}

#[test]
fn unbond_through_ffi_requires_maturity() {
    let node = validator_node();
    node.bond_stake(1, 500).unwrap();
    assert!(node.pending_unbond_height().unwrap().is_some());
    assert!(node.chain_height().unwrap() > 0);

    // Nothing matured yet: typed InsufficientStake, nothing released.
    let err = node.unbond(1, 300).unwrap_err();
    assert!(
        err.to_string().contains("insufficient matured stake"),
        "{err}"
    );
    assert_eq!(node.my_stake().unwrap(), 500);
}

#[test]
fn retarget_enabled_hybrid_pins_pow_and_syncs() {
    let producer = fresh();
    producer.set_validator_seed(vec![0xAB; 32]).unwrap();
    producer.enable_hybrid(1, 1, NOMINAL_WORK, true).unwrap();

    // Nothing bonded: PoW fallback under an active retarget policy. The block
    // must pin the policy's target — NOT the nominal staked work — and the
    // peer-side check below proves it exactly (WorkTargetMismatch otherwise).
    let pow = producer.produce_empty_block().unwrap();
    assert_eq!(pow.kind, BlockKind::Pow);
    assert_ne!(pow.work, NOMINAL_WORK);

    producer.bond_stake(1, 500).unwrap();
    let staked = producer.produce_empty_block().unwrap();
    assert_eq!(staked.kind, BlockKind::Staked);
    assert_eq!(staked.work, NOMINAL_WORK);

    let peer = fresh();
    peer.set_validator_seed(vec![0xCD; 32]).unwrap();
    peer.enable_hybrid(1, 1, NOMINAL_WORK, true).unwrap();
    let _applied = peer.receive_blocks(producer.export_blocks()).unwrap();
    assert_eq!(
        peer.selected_tip().unwrap(),
        producer.selected_tip().unwrap()
    );
}

#[test]
fn light_sync_filters_and_proofs_end_to_end() {
    let producer = fresh();
    producer.send(1, 300, 2).unwrap(); // a real payment to watch

    // Phone receives the selected chain as headers + filters only.
    let phone = fresh();
    let blob = producer.export_light_sync();
    let accepted = phone.receive_light_sync(blob.clone()).unwrap();
    assert_eq!(accepted, producer.block_count().unwrap());
    assert!(phone.synced_height().is_some());

    // Idempotent re-sync.
    let before = phone.synced_height();
    phone.receive_light_sync(blob).unwrap();
    assert_eq!(phone.synced_height(), before);

    // The payment's recipient address shows up in exactly that block's filter.
    let receipt = producer.send(1, 100, 3).unwrap();
    let _ = phone
        .receive_light_sync(producer.export_light_sync())
        .unwrap();
    let addr3 = kovanica_node::Node::address(3);
    match phone
        .synced_filter_matches(receipt.block_id_hex.clone(), addr3.to_hex())
        .unwrap()
    {
        Some(hit) => assert!(hit, "recipient must hit the filter"),
        None => panic!("block should be synced"),
    }
    // A stranger's address misses (definitive).
    let stranger = kovanica_node::Node::address(42);
    assert_eq!(
        phone
            .synced_filter_matches(receipt.block_id_hex.clone(), stranger.to_hex())
            .unwrap(),
        Some(false)
    );

    // Inclusion proof: verifies against the synced header root.
    let tx_hex = receipt.tx_id_hex.clone();
    let proof = producer
        .prove_tx(receipt.block_id_hex.clone(), tx_hex.clone())
        .unwrap()
        .expect("tx in block");
    assert!(phone
        .verify_tx_proof(proof, receipt.block_id_hex.clone())
        .unwrap());

    // Tampered proof is rejected. Single-tx blocks prove as bare leaves
    // (empty path, len 84), so corrupt the merkle-root region itself.
    let mut bad = producer
        .prove_tx(receipt.block_id_hex.clone(), tx_hex)
        .unwrap()
        .unwrap();
    assert_eq!(bad.len(), 84, "single-payload-tx block ⇒ leaf-only proof");
    bad[40] ^= 0xFF;
    assert!(!phone.verify_tx_proof(bad, receipt.block_id_hex).unwrap());
}

#[test]
fn standalone_filter_blob_roundtrips_and_matches() {
    let node = fresh();
    let tip = node.selected_tip().unwrap(); // genesis: founder-funded output
    let filter = node.block_filter(tip.clone()).unwrap();
    let founder = kovanica_node::Node::address(1);
    assert!(node
        .filter_matches(filter.clone(), founder.to_hex())
        .unwrap());
    let stranger = kovanica_node::Node::address(77);
    assert!(!node.filter_matches(filter, stranger.to_hex()).unwrap());
}

#[test]
fn garbage_light_sync_is_rejected_not_panicked_on() {
    let phone = fresh();
    assert!(phone.receive_light_sync(vec![0u8; 40]).is_err());
}

#[test]
fn history_over_ffi_matches_utxo_semantics() {
    let node = fresh();
    node.send(1, 400, 2).unwrap();

    let founder_hex = kovanica_node::Node::address(1).to_hex();
    let hist = node.history_of(founder_hex.clone(), 0).unwrap();
    let summary: Vec<(String, bool)> = hist
        .iter()
        .map(|e| {
            (
                e.amount.clone(),
                e.direction == kovanica_ffi::TxDirection::Received,
            )
        })
        .collect();
    assert_eq!(
        summary,
        vec![
            ("1000".into(), true),  // genesis coinbase
            ("1000".into(), false), // coin consumed by the send
            ("599".into(), true),   // change (fee = 1)
        ]
    );
    for e in &hist {
        assert_eq!(hex::decode(&e.tx_id_hex).unwrap().len(), 32);
        assert_eq!(hex::decode(&e.block_id_hex).unwrap().len(), 32);
    }

    // The human `kvnc…dag` address form parses too.
    let kvnc = kovanica_node::Node::address(1).to_kvnc();
    assert_eq!(node.history_of(kvnc, 0).unwrap().len(), 3);

    // Uninvolved address and bounded scans behave.
    assert!(node
        .history_of(kovanica_node::Node::address(9).to_hex(), 0)
        .unwrap()
        .is_empty());
    assert_eq!(node.history_of(founder_hex, 1).unwrap().len(), 1);
}

#[test]
fn filter_matches_any_batches_watch_addresses() {
    let node = fresh();
    let tip = node.selected_tip().unwrap(); // genesis
    let blob = node.block_filter(tip).unwrap();

    let founder = kovanica_node::Node::address(1).to_hex();
    let bystander = kovanica_node::Node::address(7).to_hex();

    // Batch hit when any watched address matches…
    assert!(node
        .filter_matches_any(blob.clone(), vec![bystander.clone(), founder.clone()])
        .unwrap());
    // …and batch agrees with the single-address query.
    assert_eq!(
        node.filter_matches_any(blob.clone(), vec![founder.clone()])
            .unwrap(),
        node.filter_matches(blob.clone(), founder.clone()).unwrap()
    );

    // Empty watch list never matches; malformed filters error cleanly.
    assert!(!node.filter_matches_any(blob.clone(), vec![]).unwrap());
    assert!(node
        .filter_matches_any(vec![0u8; 9], vec![founder])
        .is_err());
}

#[test]
fn bond_and_unbond_from_secret_spend_wallet_funds() {
    let node = validator_node();

    // The deterministic founder actor (seed 1) is funded by genesis. Its
    // Ed25519 secret is the little-endian encoding of 1 padded to 32 bytes.
    let founder_secret = "0100000000000000000000000000000000000000000000000000000000000000";

    // Bonding from the wallet secret freezes the founder's own coins and
    // returns change to the same wallet address.
    let bond_tx_hex = node
        .bond_stake_from_secret(founder_secret.into(), 500)
        .unwrap();
    assert_eq!(hex::decode(&bond_tx_hex).unwrap().len(), 32);
    assert_eq!(node.total_stake().unwrap(), 500);
    assert_eq!(node.my_stake().unwrap(), 500);

    // Immature unbond fails.
    let err = node
        .unbond_from_secret(founder_secret.into(), 300)
        .unwrap_err();
    assert!(
        err.to_string().contains("insufficient matured stake"),
        "{err}"
    );
    assert_eq!(node.my_stake().unwrap(), 500);

    // Mine enough blocks to mature the bond (`UNBOND_MATURITY` = 100).
    for _ in 0..105 {
        let _ = node.produce_empty_block().unwrap();
    }

    let receipt = node.unbond_from_secret(founder_secret.into(), 300).unwrap();
    assert!(!receipt.block_id_hex.is_empty());
    assert!(!receipt.tx_id_hex.is_empty());
    assert_eq!(node.my_stake().unwrap(), 0);
    // The remaining 200 atoms were returned as an unfrozen change output.
    assert_eq!(node.total_stake().unwrap(), 0);
}
