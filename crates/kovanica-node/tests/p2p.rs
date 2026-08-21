//! Integration tests for continuous in-process gossip: peer discovery, the
//! relay loop, transaction dissemination, and mempool eviction of spent txs.

use kovanica_node::{GossipKind, Mesh, Node};

fn genesis_node() -> Node {
    let mut node = Node::new();
    node.set_now_ms(1_000);
    node.genesis(3, 1000, 1000, 1).unwrap();
    node
}

/// Line topology: alpha → beta → gamma. Hellos should close the missing edges.
fn line_mesh() -> Mesh {
    let mut mesh = Mesh::new();
    mesh.add("alpha", genesis_node());
    mesh.add("beta", genesis_node());
    mesh.add("gamma", genesis_node());
    mesh.connect("alpha", "beta").unwrap();
    mesh.connect("beta", "gamma").unwrap();
    mesh
}

#[test]
fn hellos_discover_the_missing_edge() {
    let mut mesh = line_mesh();
    mesh.drain(16);

    let alpha_peers = mesh.peers_of("alpha");
    let gamma_peers = mesh.peers_of("gamma");
    assert!(
        alpha_peers.iter().any(|p| p == "gamma"),
        "alpha should discover gamma via beta's advertisement, got {alpha_peers:?}"
    );
    assert!(
        gamma_peers.iter().any(|p| p == "alpha"),
        "gamma should discover alpha, got {gamma_peers:?}"
    );

    let hellos = mesh
        .events()
        .iter()
        .filter(|e| e.kind == GossipKind::Hello)
        .count();
    assert!(hellos >= 2, "expected discovery hellos, got {hellos}");
}

#[test]
fn a_produced_block_relays_to_the_far_node() {
    let mut mesh = line_mesh();
    mesh.drain(16); // finish discovery first

    mesh.send("alpha", 1, 400, 2).unwrap();
    mesh.drain(16);

    let alpha = mesh.node("alpha").unwrap();
    let gamma = mesh.node("gamma").unwrap();
    assert_eq!(gamma.block_count().unwrap(), alpha.block_count().unwrap());
    assert_eq!(gamma.selected_tip().unwrap(), alpha.selected_tip().unwrap());
    assert_eq!(gamma.balance(&Node::address(2)).unwrap(), 400);
}

#[test]
fn a_pooled_tx_relays_then_lands_in_a_far_block() {
    let mut mesh = line_mesh();
    mesh.drain(16);

    let tx = mesh.pool("alpha", 1, 250, 3).unwrap();
    mesh.drain(16);

    assert!(
        mesh.node("gamma").unwrap().mempool_tx(&tx).is_some(),
        "gamma should hold the relayed tx before producing"
    );

    mesh.produce("gamma").unwrap();
    mesh.drain(16);

    let alpha = mesh.node("alpha").unwrap();
    let gamma = mesh.node("gamma").unwrap();
    assert_eq!(alpha.selected_tip().unwrap(), gamma.selected_tip().unwrap());
    assert_eq!(alpha.balance(&Node::address(3)).unwrap(), 250);
    assert_eq!(alpha.pending_count(), 0);
    assert_eq!(gamma.pending_count(), 0);
}

#[test]
fn relay_flood_terminates() {
    let mut mesh = line_mesh();
    mesh.drain(16);
    mesh.send("alpha", 1, 400, 2).unwrap();
    let delivered = mesh.drain(64);
    assert!(mesh.is_idle(), "flood should drain; delivered={delivered}");
    let extra = mesh.drain(8);
    assert_eq!(extra, 0, "no leftover envelopes after the flood");
}

#[test]
fn spent_mempool_tx_is_evicted_after_the_competing_block_arrives() {
    let mut mesh = Mesh::new();
    mesh.add("alpha", genesis_node());
    mesh.add("beta", genesis_node());
    mesh.connect("alpha", "beta").unwrap();
    mesh.connect("beta", "alpha").unwrap();
    mesh.drain(8);

    // Both nodes independently pool a spend of the same founder output.
    let tx_a = mesh.pool("alpha", 1, 400, 2).unwrap();
    let tx_b = mesh.pool("beta", 1, 300, 3).unwrap();
    mesh.drain(8);
    // After relay both mempools hold both txs.
    assert!(mesh.node("alpha").unwrap().mempool_tx(&tx_b).is_some());
    assert!(mesh.node("beta").unwrap().mempool_tx(&tx_a).is_some());

    // Alpha produces (includes one of the two, deterministically by tx id).
    mesh.produce("alpha").unwrap();
    mesh.drain(8);

    let alpha = mesh.node("alpha").unwrap();
    let beta = mesh.node("beta").unwrap();
    // The included tx is gone; the loser is evicted because its input is spent.
    assert_eq!(alpha.pending_count(), 0);
    assert_eq!(beta.pending_count(), 0);
    assert!(alpha.mempool_tx(&tx_a).is_none());
    assert!(alpha.mempool_tx(&tx_b).is_none());
}
