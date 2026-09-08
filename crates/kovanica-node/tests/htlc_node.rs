//! Integration tests for the RFC-004 HTLC node surface: `create_htlc`,
//! `redeem_htlc`, `refund_htlc`, `balance_of_htlc`, `scan_for_htlc_redeem`,
//! the `atomic_swap` orchestration library, and the four line-RPC commands.
//!
//! Reference protocols: Bitcoin HTLC (BIP-199), Tier Nolan atomic swap
//! (preimage revelation), Lightning (preimage-based settlement). The template
//! and address shape mirror RFC-001 P2SH / RFC-003 script v2; the node surface
//! mirrors `send_to_script_v2` / `build_transfer_with_outputs`.
//!
//! Timeout semantics: a refund is valid iff **its own block's** height is
//! `>= timeout`. A release's own block advances the chain, so timeout windows
//! are measured from the post-release tip.

use kovanica_node::{
    preimage_hash, rpc, Node, NodeError, SwapError, SwapParams, SwapRole, SwapSession,
};
use kovanica_state::{KeyPair, LedgerError, LedgerInsertError};

/// A fixed preimage for deterministic tests (production uses
/// [`kovanica_node::generate_preimage`]).
const PREIMAGE: [u8; 32] = [0x42u8; 32];

/// A two-party swap of native KVNC: Alice swaps 500 for Bob's 400.
fn swap_params(timeout_a: u32, timeout_b: u32) -> SwapParams {
    SwapParams {
        amount_a: 500,
        asset_a: None,
        amount_b: 400,
        asset_b: None,
        timeout_a,
        timeout_b,
    }
}

#[test]
fn swap_e2e_same_chain() {
    // Full Tier Nolan swap on one node: Alice funds HTLC-A, Bob verifies it
    // on-chain and funds HTLC-B, Alice redeems B (revealing the preimage),
    // Bob extracts the preimage and redeems A. Both parties end up with the
    // counterparty's funds, minus the five protocol fees.
    let mut node = Node::new();
    node.genesis(3, 2000, 2000, 1).unwrap(); // 2000 to Alice (seed 1)

    let alice = KeyPair::from_u64(1);
    let bob = KeyPair::from_u64(2);

    // Alice funds Bob so he can lock HTLC-B.
    node.send_with(&alice, 1000, bob.address()).unwrap();

    let session = SwapSession::new(
        &swap_params(3, 1),
        *alice.address().payload(),
        *bob.address().payload(),
        PREIMAGE,
    )
    .unwrap();

    // Step 2: Alice funds HTLC-A (recipient = Bob, sender = Alice).
    let htlc_a = node
        .create_htlc(
            &alice,
            500,
            None,
            *bob.address().payload(),
            session.preimage_hash,
            session.htlc_a.timeout(),
        )
        .unwrap();
    assert_eq!(node.balance_of_htlc(&session.htlc_a), 500);

    // Step 3: Bob verifies HTLC-A on-chain before funding HTLC-B.
    assert!(session.verify_against(&htlc_a.script, SwapRole::Bob));

    // Step 4: Bob funds HTLC-B (recipient = Alice, sender = Bob).
    let htlc_b = node
        .create_htlc(
            &bob,
            400,
            None,
            *alice.address().payload(),
            session.preimage_hash,
            session.htlc_b.timeout(),
        )
        .unwrap();
    assert_eq!(node.balance_of_htlc(&session.htlc_b), 400);

    // Step 5: Alice redeems HTLC-B with the preimage — no time constraint
    // (BIP-199), even though the chain has long passed T_B.
    node.redeem_htlc(
        &alice,
        htlc_b.outpoint,
        &session.htlc_b,
        &session.preimage,
        alice.address(),
    )
    .unwrap();
    assert_eq!(node.balance_of_htlc(&session.htlc_b), 0);

    // Step 6: Bob extracts the preimage from the on-chain redeem and redeems
    // HTLC-A with it.
    let (redeem_tx, revealed) = node
        .scan_for_htlc_redeem(&session.htlc_b, 0)
        .expect("Bob finds Alice's redeem on-chain");
    assert_eq!(revealed, session.preimage.to_vec());
    assert!(node.tx_confirmation(&redeem_tx).unwrap().is_some());
    node.redeem_htlc(
        &bob,
        htlc_a.outpoint,
        &session.htlc_a,
        &revealed,
        bob.address(),
    )
    .unwrap();
    assert_eq!(node.balance_of_htlc(&session.htlc_a), 0);

    // Both parties hold their counterparty's funds, minus the five fees:
    // Alice: 2000 - 1000(send) - 1 - 500(HTLC-A) - 1 + 400(redeem B) - 1 = 897
    // Bob:   1000 - 400(HTLC-B) - 1 + 500(redeem A) - 1 = 1098
    assert_eq!(node.balance(&alice.address()).unwrap(), 897);
    assert_eq!(node.balance(&bob.address()).unwrap(), 1098);
}

#[test]
fn swap_refund_path() {
    // Alice never redeems. Bob refunds HTLC-B after T_B; Alice refunds HTLC-A
    // after T_A. An early refund of HTLC-A is rejected with
    // `HtlcTimeoutNotReached` (the refund block's height is below the timeout).
    let mut node = Node::new();
    node.genesis(3, 2000, 2000, 1).unwrap();

    let alice = KeyPair::from_u64(1);
    let bob = KeyPair::from_u64(2);

    node.send_with(&alice, 1000, bob.address()).unwrap();

    // T_A = 5, T_B = 1. HTLC-A is created at height 2; the earliest refund
    // block would sit at height 3, so a refund before height 5 is rejected.
    let session = SwapSession::new(
        &swap_params(5, 1),
        *alice.address().payload(),
        *bob.address().payload(),
        PREIMAGE,
    )
    .unwrap();

    let htlc_a = node
        .create_htlc(
            &alice,
            500,
            None,
            *bob.address().payload(),
            session.preimage_hash,
            session.htlc_a.timeout(),
        )
        .unwrap();
    let htlc_b = node
        .create_htlc(
            &bob,
            400,
            None,
            *alice.address().payload(),
            session.preimage_hash,
            session.htlc_b.timeout(),
        )
        .unwrap();

    // Alice's refund of HTLC-A is rejected: the refund block would sit at
    // height 4, below timeout_a = 5.
    let err = node
        .refund_htlc(&alice, htlc_a.outpoint, &session.htlc_a, alice.address())
        .unwrap_err();
    assert!(matches!(
        err,
        NodeError::Insert(LedgerInsertError::State(
            LedgerError::HtlcTimeoutNotReached { .. }
        ))
    ));
    assert_eq!(node.balance_of_htlc(&session.htlc_a), 500);

    // Bob refunds HTLC-B after T_B (height 5 >= 1).
    node.refund_htlc(&bob, htlc_b.outpoint, &session.htlc_b, bob.address())
        .unwrap();
    assert_eq!(node.balance_of_htlc(&session.htlc_b), 0);

    // Alice refunds HTLC-A after T_A (height 6 >= 5).
    node.refund_htlc(&alice, htlc_a.outpoint, &session.htlc_a, alice.address())
        .unwrap();
    assert_eq!(node.balance_of_htlc(&session.htlc_a), 0);

    // Both parties recovered their locked funds, minus the five fees:
    // Alice: 2000 - 1000(send) - 1 - 500(HTLC-A) - 1 + 500(refund A) - 1 = 997
    // Bob:   1000 - 400(HTLC-B) - 1 + 400(refund B) - 1 = 998
    assert_eq!(node.balance(&alice.address()).unwrap(), 997);
    assert_eq!(node.balance(&bob.address()).unwrap(), 998);
}

#[test]
fn swap_timeout_ordering_enforced() {
    // The safety invariant of the Tier Nolan protocol: Bob's refund must
    // unlock strictly before Alice's, or Bob could take Alice's funds and
    // still refund his own.
    let alice = KeyPair::from_u64(1);
    let bob = KeyPair::from_u64(2);

    // Equal timeouts → rejected.
    let params = swap_params(3, 3);
    assert_eq!(
        SwapSession::new(
            &params,
            *alice.address().payload(),
            *bob.address().payload(),
            PREIMAGE,
        ),
        Err(SwapError::TimeoutOrdering)
    );

    // Bob's timeout later than Alice's → rejected.
    let params = swap_params(3, 4);
    assert_eq!(
        SwapSession::new(
            &params,
            *alice.address().payload(),
            *bob.address().payload(),
            PREIMAGE,
        ),
        Err(SwapError::TimeoutOrdering)
    );

    // Same party → rejected.
    let pk = *alice.address().payload();
    assert_eq!(
        SwapSession::new(&swap_params(3, 1), pk, pk, PREIMAGE),
        Err(SwapError::SameParty)
    );
}

#[test]
fn htlc_rpc_commands() {
    // The four line-RPC commands end-to-end: create → balance → redeem →
    // balance, then a second create → refund → balance.
    let mut node = Node::new();
    node.genesis(3, 2000, 2000, 1).unwrap();

    let bob = KeyPair::from_u64(2);
    let bob_pk_hex = hex::encode(bob.address().payload());
    let hash_hex = hex::encode(preimage_hash(&PREIMAGE));

    // htlc_create: Alice (seed 1) locks 500 to Bob with timeout 3.
    let resp = rpc::execute_line(
        &mut node,
        &format!("htlc_create 1 500 {bob_pk_hex} {hash_hex} 3"),
    );
    assert!(resp.starts_with("ok "), "resp: {resp}");
    let parts: Vec<&str> = resp.split_whitespace().collect();
    assert_eq!(
        parts.len(),
        4,
        "expected `ok <tx-id> <script-hex> <address>`"
    );
    let (tx_id_hex, script_hex, htlc_addr) = (parts[1], parts[2], parts[3]);
    assert_eq!(tx_id_hex.len(), 64);
    assert_eq!(script_hex.len(), 200); // 100-byte template
    assert!(htlc_addr.starts_with("kvnc") || htlc_addr.len() == 66);

    // htlc_balance: the script holds 500.
    let resp = rpc::execute_line(&mut node, &format!("htlc_balance {script_hex}"));
    assert_eq!(resp, "ok 500");

    // htlc_redeem: Bob (seed 2) redeems with the preimage to his own address.
    let resp = rpc::execute_line(
        &mut node,
        &format!(
            "htlc_redeem 2 {tx_id_hex} 0 {script_hex} {} {}",
            hex::encode(PREIMAGE),
            bob.address(),
        ),
    );
    assert!(resp.starts_with("ok "), "resp: {resp}");

    // htlc_balance: now empty.
    let resp = rpc::execute_line(&mut node, &format!("htlc_balance {script_hex}"));
    assert_eq!(resp, "ok 0");

    // htlc_refund: Alice locks a second HTLC (timeout 1) and refunds it after
    // the chain passes T = 1.
    let resp = rpc::execute_line(
        &mut node,
        &format!("htlc_create 1 300 {bob_pk_hex} {hash_hex} 1"),
    );
    assert!(resp.starts_with("ok "), "resp: {resp}");
    let parts: Vec<&str> = resp.split_whitespace().collect();
    let (tx2_hex, script2_hex) = (parts[1], parts[2]);

    let resp = rpc::execute_line(
        &mut node,
        &format!(
            "htlc_refund 1 {tx2_hex} 0 {script2_hex} {}",
            KeyPair::from_u64(1).address(),
        ),
    );
    assert!(resp.starts_with("ok "), "resp: {resp}");

    let resp = rpc::execute_line(&mut node, &format!("htlc_balance {script2_hex}"));
    assert_eq!(resp, "ok 0");

    // The help text lists the new commands.
    let help = rpc::execute_line(&mut node, "help");
    assert!(help.contains("htlc_create"));
    assert!(help.contains("htlc_redeem"));
    assert!(help.contains("htlc_refund"));
    assert!(help.contains("htlc_balance"));
}
