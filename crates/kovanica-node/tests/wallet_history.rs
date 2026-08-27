//! Wallet history reconstruction: `Node::history_of` scans stored blocks in
//! canonical order and rebuilds credits/debits for an address from the UTXO
//! graph alone (no index, no client-side cache).
//!
//! Debit semantics: spending consumes whole coins, so a debit carries the
//! FULL value of the owner's inputs consumed; the change returns as its own
//! credit. Net effect per send: −fee.

use kovanica_node::{Node, WalletDirection};

fn node() -> Node {
    let mut n = Node::new();
    n.genesis(3, 1_000, 1_000, 1).unwrap();
    n
}

fn summary(hist: &[kovanica_node::WalletEvent]) -> Vec<(WalletDirection, u64)> {
    hist.iter().map(|e| (e.direction, e.amount)).collect()
}

#[test]
fn credits_debits_and_change_appear_in_canonical_order() {
    let mut n = node();
    n.send(1, 400, 2).unwrap();

    let founder = Node::address(1);
    let hist = n.history_of(&founder, 0).unwrap();
    assert_eq!(
        summary(&hist),
        vec![
            (WalletDirection::Received, 1_000), // genesis coinbase
            (WalletDirection::Sent, 1_000),     // its coin consumed by the send
            (WalletDirection::Received, 599),   // change (fee = 1)
        ]
    );
    // The send's debit and change share one sealing block+tx; the coinbase
    // credit is its own earlier transaction.
    assert_ne!(hist[0].tx_id, hist[1].tx_id);
    assert_eq!(hist[1].tx_id, hist[2].tx_id);
    assert_eq!(hist[1].block_id, hist[2].block_id);

    let peer_hist = n.history_of(&Node::address(2), 0).unwrap();
    assert_eq!(summary(&peer_hist), vec![(WalletDirection::Received, 400)]);

    // Uninvolved address: empty history.
    assert!(n.history_of(&Node::address(9), 0).unwrap().is_empty());
}

#[test]
fn spending_received_coins_produces_followup_debit() {
    let mut n = node();
    n.send(1, 400, 2).unwrap();
    n.send(2, 150, 3).unwrap();

    let hist = n.history_of(&Node::address(2), 0).unwrap();
    assert_eq!(
        summary(&hist),
        vec![
            (WalletDirection::Received, 400),
            (WalletDirection::Sent, 400), // the whole 400-coin was consumed
            (WalletDirection::Received, 249),
        ]
    );
}

#[test]
fn max_blocks_bounds_the_scan_window() {
    let mut n = node();
    n.send(1, 400, 2).unwrap();

    let founder = Node::address(1);
    // Only the first scanned block (genesis) is considered.
    let bounded = n.history_of(&founder, 1).unwrap();
    assert_eq!(summary(&bounded), vec![(WalletDirection::Received, 1_000)]);
}
