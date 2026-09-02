//! Integration tests for C1 incremental persistence.
//!
//! These exercise [`Node::persist_incremental`] and [`Node::load_log`]: a node
//! is rebuilt from its append-only replay log, derived state is recomputed from
//! the records, and the chain can continue afterwards.

use std::fs;

use kovanica_node::Node;
use kovanica_state::{HybridConfig, KeyPair};

fn temp_log(name: &str) -> String {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "kovanica-incr-{}-{}-{}",
        name,
        std::process::id(),
        rand::random::<u64>()
    ));
    path.set_extension("log");
    path.to_str().unwrap().to_string()
}

fn remove_log(path: &str) {
    let _ = fs::remove_file(path);
}

#[test]
fn log_roundtrip_recovers_blocks_and_continues() {
    let log_path = temp_log("roundtrip");
    let founder = KeyPair::from_u64(1);
    let recipient = KeyPair::from_u64(2);

    // Produce blocks on the original node and persist incrementally.
    let mut node = Node::new();
    node.genesis(3, 1_000, 1_000, 1).unwrap();
    node.set_miner(founder.address());
    node.produce_empty().unwrap();
    node.pool(1, 100, 2).unwrap();
    node.produce_block().unwrap().unwrap();
    let headers_before: Vec<_> = node.export_headers().iter().map(|h| h.id).collect();
    node.persist_incremental(&log_path).unwrap();

    // Rebuild from the log and verify the same non-genesis blocks are present
    // in the same order.
    let mut recovered = Node::load_log(&log_path).unwrap();
    let headers_after: Vec<_> = recovered.export_headers().iter().map(|h| h.id).collect();
    assert_eq!(
        headers_before, headers_after,
        "block ids must match across restart"
    );
    assert_eq!(
        recovered.balance(&recipient.address()).unwrap(),
        100u128,
        "recipient balance must be recovered from replay"
    );

    // The recovered chain must accept new blocks.
    recovered.set_miner(founder.address());
    recovered.produce_empty().unwrap();
    assert!(
        recovered.block_count().unwrap() > node.block_count().unwrap(),
        "recovered chain must continue"
    );

    remove_log(&log_path);
}

#[test]
fn hybrid_log_preserves_staked_block_id() {
    let log_path = temp_log("hybrid");
    let cfg = HybridConfig {
        rate_num: 1,
        rate_den: 1,
        stake_nominal_work: 1,
        use_epoch_beacon: true,
        retarget: None,
    };
    let founder = KeyPair::from_u64(1);

    // Bond the founder's coin so the validator can win a staked-VRF block.
    let mut node = Node::new();
    node.genesis(3, 1_000, 1_000, 1).unwrap();
    node.enable_hybrid(cfg.clone()).unwrap();
    node.set_validator_seed([7u8; 32]);

    let (coin, _) = node
        .utxos_of(&founder.address())
        .unwrap()
        .first()
        .copied()
        .unwrap();
    let pk = *node.validator_public_key().unwrap().as_bytes();
    let bond = kovanica_state::Transaction::signed(
        &[(coin, &founder)],
        vec![kovanica_state::TxOutput::new(1_000, founder.address())],
        kovanica_state::stake::bond_tag(&pk),
    );
    node.submit_tx(bond).unwrap();
    node.produce_block().unwrap().unwrap();

    // Produce the staked-VRF empty block.
    let staked_id = node.produce_empty().unwrap();
    node.persist_incremental(&log_path).unwrap();

    // Replay under the same hybrid policy: the staked block must keep its id.
    let recovered = Node::load_log_with_hybrid(&log_path, cfg).unwrap();
    let header_ids: Vec<_> = recovered.export_headers().iter().map(|h| h.id).collect();
    assert!(
        header_ids.contains(&staked_id),
        "staked block id must be preserved across hybrid replay"
    );

    remove_log(&log_path);
}
