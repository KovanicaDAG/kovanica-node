//! Slice-9a spike: can a phone `LightNode` import the LIVE kovanica testnet
//! chain? The whole app depends on the FFI node reproducing the network
//! genesis — if local genesis diverges, `receive_blocks` cannot anchor.
//!
//! Fixture `tests/fixtures/live-alpha-blocks.bin` is a fresh capture of
//! `GET /api/blocks` from seed1 (the public testnet node). Constants below
//! were read from `GET /api/bootstrap` / `GET /api/state` on the same host:
//!   genesis 596874eac2…, tip 4927b982…, k=3, `kovanica-testnet`.
//!
//! If this test starts failing off the fixture, re-capture the endpoint and
//! revisit the genesis config — the network may have booted a new chain.

use kovanica_ffi::{LightConfig, LightNode};

/// Live network constants (see `crates/kovanica-node/src/explorer.rs`:
/// `genesis(3, 200*ATOM, 200*ATOM, 1)` — founder seed 1, 200 KVNC premine,
/// 200 KVNC subsidy, ATOM = 100_000_000, k = 3).
const LIVE_GENESIS: &str = "596874eac2d08723b12fc3cac8f891493139200da4818594c6632b3fe4d0048f";
const LIVE_TIP: &str = "4927b9826ff6e731e11a0390acad0c3f231d78faa2f5b19285e3e5fbec293ee6";
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
        subsidy: 200 * ATOM,
        founder_amount: 200 * ATOM,
        founder_seed: 1,
        finality_depth: u64::MAX,
        payload_pruning_depth: u64::MAX,
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
    assert_eq!(node.balance_of_seed(1).unwrap(), "20000000000");
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
