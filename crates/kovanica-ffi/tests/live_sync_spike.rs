//! Slice-9a spike: can a phone `LightNode` import the LIVE kovanica testnet
//! chain? The whole app depends on the FFI node reproducing the network
//! genesis — if local genesis diverges, `receive_blocks` cannot anchor.
//!
//! Fixture `tests/fixtures/live-alpha-blocks.bin` is a capture of the first 9
//! post-genesis records of `GET /api/blocks` from seed1 (the public testnet
//! node; re-captured 2026-09-14 for the RFC-006 chain). Constants below were
//! read from `GET /api/bootstrap` on the same host:
//!   genesis 9565fc20…, k=3, subsidy 10 KVNC, premine 200_000 KVNC
//!   (RFC006_PREMINE), founder_seed 1, `kovanica-testnet`.
//!
//! If this test starts failing off the fixture, re-capture the endpoint and
//! revisit the genesis config — the network may have booted a new chain.

use kovanica_ffi::{LightConfig, LightNode};

/// Live network constants (RFC-006, read from
/// `GET https://explorer.kovanica.online/api/bootstrap` 2026-09-14):
/// genesis 9565fc20…, k=3, subsidy 10 KVNC, premine 200_000 KVNC
/// (RFC006_PREMINE), founder_seed 1, finality 100, payload pruning 1000.
/// The fixture tip is the 9th post-genesis record of `/api/blocks`.
const LIVE_GENESIS: &str = "9565fc20cb465eec0198a65c07da6b825e4211c4060d581a2c7dac6c96bafc97";
const LIVE_TIP: &str = "c62cd17cd79762036f1ae5f6dd0bba3d7c1aa437082d7199965bd3075cd3d154";
const LIVE_BLOCKS: u32 = 10;
const ATOM: u64 = 100_000_000;

fn fixture_path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("live-alpha-blocks.bin")
}

fn live_config() -> LightConfig {
    LightConfig {
        k: 3,
        subsidy: 10 * ATOM,             // RFC-006 genesis subsidy (10 KVNC)
        founder_amount: 200_000 * ATOM, // RFC006_PREMINE (200_000 KVNC)
        founder_seed: 1,
        finality_depth: 100,
        payload_pruning_depth: 1000,
    }
}

#[test]
fn default_config_genesis_diverges_from_live_network() {
    let node = LightNode::new(LightConfig::default()).expect("genesis ok");
    // The FFI default (subsidy 1000, premine 1000) does NOT reproduce the
    // live network: its genesis block id differs from the testnet genesis.
    assert!(node
        .block_by_id(LIVE_GENESIS.to_string())
        .unwrap()
        .is_none());
}

#[test]
fn live_params_reproduce_testnet_genesis() {
    let node = LightNode::new(live_config()).expect("genesis ok");
    assert_eq!(node.balance_of_seed(1).unwrap(), "20000000000000");
    // Genesis parity without syncing: the local node booted to the same
    // genesis block the public network anchors on.
    let genesis = node
        .block_by_id(LIVE_GENESIS.to_string())
        .unwrap()
        .expect("phone genesis must equal live network genesis");
    assert_eq!(genesis.id_hex, LIVE_GENESIS);
}

#[test]
fn light_node_imports_live_testnet_chain() {
    let node = LightNode::new(live_config()).expect("genesis ok");
    let blob = std::fs::read(fixture_path()).expect("fetch tests/fixtures and commit it");
    let applied = node.receive_blocks(blob).expect("blob must decode");
    assert!(applied > 0, "expected the blob to apply records");

    // Converged on the live chain: full DAG size, selected tip and a
    // present tip block all match `GET /api/state` / `/api/bootstrap`.
    assert_eq!(node.block_count().unwrap(), LIVE_BLOCKS);
    assert_eq!(node.selected_tip().unwrap(), LIVE_TIP);
    assert!(node.block_by_id(LIVE_TIP.to_string()).unwrap().is_some());
}
