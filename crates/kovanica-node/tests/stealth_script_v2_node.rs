//! Integration tests for the RFC-003 script v2 (0x02) and stealth (0x03)
//! node surface: `send_to_script_v2`, `send_to_stealth`, `balance_of_script`,
//! and `balance_of_stealth`.
//!
//! These exercise the full path: fund → send → balance check, using the
//! deterministic demo keys (seed-derived) so every assertion is reproducible.

use kovanica_node::Node;
use kovanica_state::{KeyPair, StealthAddress};

/// A script v2 program: a minimal, well-formed script. The exact opcodes don't
/// matter for the node surface — the address is just `BLAKE3(script)`.
const SCRIPT_V2: &[u8] = &[0x01, 0x02, 0x03, 0x04, 0x05];

#[test]
fn send_to_script_v2_funds_and_balances() {
    let mut node = Node::new();
    node.genesis(3, 1000, 1000, 1).unwrap();

    // Fund actor 1 with a spendable coin (genesis already did: 1000).
    let kp = KeyPair::from_u64(1);

    // Send 200 to the script-v2 address.
    let tx_id = node.send_to_script_v2(&kp, 200, SCRIPT_V2).unwrap();

    // The script-v2 address now holds 200; the sender's change is 1000-200-1(fee).
    assert_eq!(node.balance_of_script(SCRIPT_V2), 200);
    assert_eq!(node.balance(&kp.address()).unwrap(), 799);

    // The tx id is well-formed (32 bytes).
    assert_eq!(tx_id.as_bytes().len(), 32);
}

#[test]
fn send_to_stealth_funds_and_balances() {
    let mut node = Node::new();
    node.genesis(3, 1000, 1000, 1).unwrap();

    // Recipient's stealth address: scan key from seed 2, spend key from seed 3.
    let scan_kp = KeyPair::from_u64(2);
    let spend_kp = KeyPair::from_u64(3);
    let stealth = StealthAddress::new(*scan_kp.address().payload(), *spend_kp.address().payload());

    // Sender is actor 1.
    let kp = KeyPair::from_u64(1);

    // Send 300 to the stealth address.
    let tx_id = node.send_to_stealth(&kp, 300, &stealth).unwrap();

    // The stealth address (its 33-byte on-chain owner) now holds 300.
    assert_eq!(node.balance_of_stealth(&stealth), 300);
    assert_eq!(node.balance(&stealth.address()).unwrap(), 300);
    // Sender's change: 1000 - 300 - 1(fee).
    assert_eq!(node.balance(&kp.address()).unwrap(), 699);

    // Tx id is well-formed.
    assert_eq!(tx_id.as_bytes().len(), 32);
}

#[test]
fn stealth_send_is_deterministic_and_distinct_per_send() {
    let mut node = Node::new();
    node.genesis(3, 1000, 1000, 1).unwrap();

    let scan_kp = KeyPair::from_u64(2);
    let spend_kp = KeyPair::from_u64(3);
    let stealth = StealthAddress::new(*scan_kp.address().payload(), *spend_kp.address().payload());
    let kp = KeyPair::from_u64(1);

    // Two sends of the same amount to the same stealth address must produce
    // distinct tx ids (the per-send counter varies the ephemeral secret r).
    let tx1 = node.send_to_stealth(&kp, 100, &stealth).unwrap();
    let tx2 = node.send_to_stealth(&kp, 100, &stealth).unwrap();
    assert_ne!(tx1, tx2);

    // Both land at the stealth address.
    assert_eq!(node.balance_of_stealth(&stealth), 200);
}

#[test]
fn zero_amount_stealth_send_rejected() {
    let mut node = Node::new();
    node.genesis(3, 1000, 1000, 1).unwrap();

    let scan_kp = KeyPair::from_u64(2);
    let spend_kp = KeyPair::from_u64(3);
    let stealth = StealthAddress::new(*scan_kp.address().payload(), *spend_kp.address().payload());
    let kp = KeyPair::from_u64(1);

    assert!(matches!(
        node.send_to_stealth(&kp, 0, &stealth),
        Err(kovanica_node::NodeError::ZeroAmount)
    ));
}
