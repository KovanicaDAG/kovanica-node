//! Integration tests for the RFC-005 vault node surface: `create_vault`,
//! `release_vault`, `balance_of_vault`, and the three line-RPC commands.
//!
//! Reference protocols: Bitcoin BIP-65 (CLTV / absolute locktime), BIP-68 /
//! BIP-112 (CSV / relative locktime against the output's creation height,
//! which the ledger tracks per-UTXO — RFC-005 §3.2). The template and address
//! shape mirror RFC-001 P2SH / RFC-003 script v2 / RFC-004 HTLC; the node
//! surface mirrors the HTLC helpers.
//!
//! Height semantics: a vault spend is valid iff **its own block's** height
//! satisfies both gates — `height >= unlock_height` and
//! `height >= creation_height + csv`. A release's own block advances the
//! chain, so walls are measured from the post-release tip.

use kovanica_node::{rpc, Node, NodeError};
use kovanica_state::{KeyPair, LedgerError, LedgerInsertError, VaultScript};

/// The owner who will eventually release the vault (seeded deterministically).
fn owner(seed: u64) -> KeyPair {
    KeyPair::from_u64(seed)
}

/// Fund a vault on `node` from seed `1` with a 300-KVNC lock and return the
/// funding info (template, outpoint) plus the tx id hex and script hex.
fn create(
    node: &mut Node,
    unlock_height: u32,
    csv: u32,
) -> (VaultScript, kovanica_state::OutPoint) {
    let alice = owner(1);
    let info = node
        .create_vault(&alice, 300, unlock_height, csv, *alice.address().payload())
        .unwrap();
    assert_eq!(node.balance_of_vault(&info.script), 300);
    (info.script, info.outpoint)
}

#[test]
fn vault_absolute_gate_enforced() {
    // An absolute-lock vault (CLTV-style): the release spend's own block must
    // sit at height >= unlock_height.
    let mut node = Node::new();
    node.genesis(3, 2000, 2000, 1).unwrap();

    // unlock_height = pre-funding tip + 3: the funding block consumes one
    // height, so the first release attempt sits below the gate.
    let height_before_funding = node.chain_height().unwrap();
    let unlock_height = (height_before_funding + 3) as u32;
    let (script, outpoint) = create(&mut node, unlock_height, 0);
    let alice = owner(1);

    // Early release: the next block would sit below unlock_height.
    let err = node
        .release_vault(&alice, outpoint, &script, alice.address())
        .unwrap_err();
    assert!(matches!(
        err,
        NodeError::Insert(LedgerInsertError::State(
            LedgerError::VaultAbsoluteNotReached { .. }
        ))
    ));
    assert_eq!(node.balance_of_vault(&script), 300);

    // Extend the chain past the unlock height, then release.
    while node.chain_height().unwrap() < unlock_height as u64 {
        node.produce_empty().unwrap();
    }
    node.release_vault(&alice, outpoint, &script, alice.address())
        .unwrap();
    assert_eq!(node.balance_of_vault(&script), 0);
    // The 300 KVNC arrive at the owner, minus the protocol fee.
    assert!(node.balance(&alice.address()).unwrap() >= 299);
}

#[test]
fn vault_relative_gate_enforced() {
    // A relative-lock vault (CSV-style): release requires the spend block to
    // be `csv` blocks above this output's creation height.
    let mut node = Node::new();
    node.genesis(3, 2000, 2000, 1).unwrap();

    let (script, outpoint) = create(&mut node, 0, 4);
    let alice = owner(1);

    // Immediately after funding the vault and its own block, the next block
    // is 1 above creation, far below the 4-block csv gate.
    let err = node
        .release_vault(&alice, outpoint, &script, alice.address())
        .unwrap_err();
    assert!(matches!(
        err,
        NodeError::Insert(LedgerInsertError::State(
            LedgerError::VaultRelativeNotReached { .. }
        ))
    ));

    // Three more blocks put the release's block exactly at creation + csv.
    node.produce_empty().unwrap();
    node.produce_empty().unwrap();
    node.produce_empty().unwrap();
    node.release_vault(&alice, outpoint, &script, alice.address())
        .unwrap();
    assert_eq!(node.balance_of_vault(&script), 0);
}

#[test]
fn vault_both_locks_compose() {
    // With both locks set, the later gate wins. unlock_height sits far ahead,
    // so an early release is blocked even though the relative gate has passed.
    let mut node = Node::new();
    node.genesis(3, 2000, 2000, 1).unwrap();

    let height_before_funding = node.chain_height().unwrap();
    let (script, outpoint) = create(&mut node, (height_before_funding + 10) as u32, 2);
    let alice = owner(1);

    // csv=2 elapsed, but absolute height not reached → rejected.
    node.produce_empty().unwrap();
    node.produce_empty().unwrap();
    let err = node
        .release_vault(&alice, outpoint, &script, alice.address())
        .unwrap_err();
    assert!(matches!(
        err,
        NodeError::Insert(LedgerInsertError::State(
            LedgerError::VaultAbsoluteNotReached { .. }
        ))
    ));
}

#[test]
fn vault_requires_owner_signature() {
    // A spend signed by a key that is not the template owner is rejected as a
    // bad signature (the ledger verifies `owner_pk` against the sighash).
    let mut node = Node::new();
    node.genesis(3, 2000, 2000, 1).unwrap();

    let (script, outpoint) = create(&mut node, 0, 1);
    let mallory = owner(2);

    // Wait out the relative lock, then have the wrong key try to release.
    node.produce_empty().unwrap();
    let err = node
        .release_vault(&mallory, outpoint, &script, mallory.address())
        .unwrap_err();
    assert!(matches!(
        err,
        NodeError::Insert(LedgerInsertError::State(LedgerError::BadSignature { .. }))
    ));
}

#[test]
fn vault_rpc_commands() {
    // The three line-RPC commands end-to-end: create → balance → release →
    // balance, plus the help-text listing.
    let mut node = Node::new();
    node.genesis(3, 2000, 2000, 1).unwrap();

    let alice = owner(1);
    let owner_pk_hex = hex::encode(alice.address().payload());
    // unlock_height = pre-funding tip + 3 so the first release attempt
    // (right after the funding block) still sits below the gate.
    let height_before_funding = node.chain_height().unwrap();
    let unlock_height = (height_before_funding + 3) as u32;

    // vault_create: Alice (seed 1) locks 300 with an absolute gate.
    let resp = rpc::execute_line(
        &mut node,
        &format!("vault_create 1 300 {unlock_height} 0 {owner_pk_hex}"),
    );
    assert!(resp.starts_with("ok "), "resp: {resp}");
    let parts: Vec<&str> = resp.split_whitespace().collect();
    assert_eq!(
        parts.len(),
        4,
        "expected `ok <tx-id> <script-hex> <address>`"
    );
    let (tx_id_hex, script_hex, vault_addr) = (parts[1], parts[2], parts[3]);
    assert_eq!(tx_id_hex.len(), 64);
    assert_eq!(script_hex.len(), 80); // 40-byte template
    assert!(vault_addr.starts_with("kvnc") || vault_addr.len() == 66);

    // vault_balance: early release is rejected, balance stays 300.
    let resp = rpc::execute_line(
        &mut node,
        &format!(
            "vault_release 1 {tx_id_hex} 0 {script_hex} {}",
            alice.address()
        ),
    );
    assert!(resp.starts_with("err "), "expected err, got: {resp}");
    let resp = rpc::execute_line(&mut node, &format!("vault_balance {script_hex}"));
    assert_eq!(resp, "ok 300");

    // Extend past the unlock, then release through the RPC line.
    while node.chain_height().unwrap() < unlock_height as u64 {
        node.produce_empty().unwrap();
    }
    let resp = rpc::execute_line(
        &mut node,
        &format!(
            "vault_release 1 {tx_id_hex} 0 {script_hex} {}",
            alice.address()
        ),
    );
    assert!(resp.starts_with("ok "), "resp: {resp}");
    let resp = rpc::execute_line(&mut node, &format!("vault_balance {script_hex}"));
    assert_eq!(resp, "ok 0");

    // The help text lists the new commands.
    let help = rpc::execute_line(&mut node, "help");
    assert!(help.contains("vault_create"));
    assert!(help.contains("vault_release"));
    assert!(help.contains("vault_balance"));
}
