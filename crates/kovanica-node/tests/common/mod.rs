//! Common test utilities for kovanica-node integration tests.

use kovanica_node::Node;
use kovanica_state::spv::BlockHeader as SpvHeader;
use kovanica_state::KeyPair;

/// Create a node with standard genesis (k=3, subsidy=1000, amount=1000, founder=1).
pub fn genesis_node() -> Node {
    let mut node = Node::new();
    node.genesis(3, 1000, 1000, 1, None).unwrap();
    node
}

/// Get the genesis SPV header from a fresh genesis node.
pub fn get_genesis_header() -> SpvHeader {
    let node = genesis_node();
    let gen_id = node.genesis_id().unwrap();
    node.spv_header(&gen_id).unwrap()
}

/// Create a node with standard genesis and mine `n` empty blocks to mature the coinbase.
/// Returns the node and the founder's address.
/// Note: each empty block produces a coinbase with 100-block maturity, so we need
/// to mine at least 200 blocks for the first 100 coinbases to mature.
pub fn mature_node(n: u64) -> (Node, kovanica_state::Address) {
    let mut node = genesis_node();
    let founder = Node::address(1);
    for _ in 0..n {
        node.produce_empty().unwrap();
    }
    (node, founder)
}

/// Create a node with mature coinbase (500 blocks mined so first 400 coinbases mature).
/// Returns the node and the founder's address.
pub fn mature_node_100() -> (Node, kovanica_state::Address) {
    mature_node(500)
}

/// Send from founder (actor 1) to another actor, assuming coinbase is mature.
pub fn send_from_founder(node: &mut Node, amount: u64, to_seed: u64) -> kovanica_node::Sent {
    node.send(1, amount, to_seed).unwrap()
}

/// Send from a specific keypair.
pub fn send_with_kp(
    node: &mut Node,
    kp: &KeyPair,
    amount: u64,
    to: kovanica_state::Address,
) -> kovanica_node::Sent {
    node.send_with(kp, amount, to).unwrap()
}
