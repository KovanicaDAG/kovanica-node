//! Node-layer multisig integration tests.
//!
//! These exercise the M-of-N P2SH helpers end-to-end through [`Node`]:
//! address creation, funding, spend building, partial signing, combination,
//! and mempool submission. They also include adversarial cases from
//! RFC-001/AGENTS.md §5 (duplicate signatures, unauthorized signers,
//! threshold shortfall, wrong redeem script).

use kovanica_node::Node;
use kovanica_state::{Address, KeyPair, TxOutput};

fn secret_for(seed: u64) -> String {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&seed.to_le_bytes());
    hex::encode(bytes)
}

fn make_2of3(node: &mut Node) -> (Address, String) {
    let pks: Vec<[u8; 32]> = (1..=3)
        .map(|s| *KeyPair::from_u64(s).address().payload())
        .collect();
    let (addr, script) = node.create_multisig_address(2, pks).unwrap();
    (addr, hex::encode(script))
}

#[test]
fn two_of_three_create_fund_spend() {
    let mut node = Node::new();
    node.genesis(3, 1_000, 1_000, 1).unwrap();
    let (ms_addr, _script) = make_2of3(&mut node);

    // Fund the multisig address with a single coin.
    node.send_to(1, 500, ms_addr).unwrap();
    assert_eq!(node.balance(&ms_addr).unwrap(), 500);

    // Build a spend to actor 9.
    let recipient = Node::address(9);
    let unsigned = node
        .build_multisig_spend(ms_addr, vec![TxOutput::new(400, recipient)])
        .unwrap();
    assert_eq!(unsigned.inputs().len(), 1);
    assert!(!unsigned.inputs()[0].witness.is_empty()); // redeem script attached

    // Sign with key 1 and key 3.
    let sig1 = node
        .sign_multisig_partial(&unsigned, &secret_for(1))
        .unwrap();
    let sig3 = node
        .sign_multisig_partial(&unsigned, &secret_for(3))
        .unwrap();

    // Combine exactly M=2 valid partial signatures.
    let signed = node
        .combine_multisig_sigs(&unsigned, vec![sig1, sig3])
        .unwrap();
    assert_eq!(signed.inputs()[0].witness.len(), 3); // script + 2 sigs

    // Submit and mine.
    let tx_id = node.submit_multisig_tx(signed).unwrap();
    let _block = node.produce_block().unwrap().expect("mines the spend");

    // Recipient got the funds; change returned to the multisig address.
    assert_eq!(node.balance(&recipient).unwrap(), 400);
    // Change = 500 - 400 - fee(1)
    assert_eq!(node.balance(&ms_addr).unwrap(), 99);

    // The tx id reported by submit matches the mempool/mined tx.
    assert!(node.mempool_tx(&tx_id).is_none()); // mined and evicted
}

#[test]
fn multisig_spend_fails_with_one_signature() {
    let mut node = Node::new();
    node.genesis(3, 1_000, 1_000, 1).unwrap();
    let (ms_addr, _script) = make_2of3(&mut node);
    node.send_to(1, 500, ms_addr).unwrap();

    let unsigned = node
        .build_multisig_spend(ms_addr, vec![TxOutput::new(400, Node::address(9))])
        .unwrap();
    let sig1 = node
        .sign_multisig_partial(&unsigned, &secret_for(1))
        .unwrap();

    let err = node
        .combine_multisig_sigs(&unsigned, vec![sig1])
        .unwrap_err();
    assert!(
        err.to_string().contains("insufficient multisig signatures"),
        "{err}"
    );
}

#[test]
fn multisig_spend_rejects_unauthorized_signer() {
    let mut node = Node::new();
    node.genesis(3, 1_000, 1_000, 1).unwrap();
    let (ms_addr, _script) = make_2of3(&mut node);
    node.send_to(1, 500, ms_addr).unwrap();

    let unsigned = node
        .build_multisig_spend(ms_addr, vec![TxOutput::new(400, Node::address(9))])
        .unwrap();
    let sig1 = node
        .sign_multisig_partial(&unsigned, &secret_for(1))
        .unwrap();
    let sig_bad = node
        .sign_multisig_partial(&unsigned, &secret_for(99))
        .unwrap();

    let err = node
        .combine_multisig_sigs(&unsigned, vec![sig1, sig_bad])
        .unwrap_err();
    assert!(err.to_string().contains("multisig error"), "{err}");
}

#[test]
fn multisig_spend_rejects_duplicate_signature() {
    let mut node = Node::new();
    node.genesis(3, 1_000, 1_000, 1).unwrap();
    let (ms_addr, _script) = make_2of3(&mut node);
    node.send_to(1, 500, ms_addr).unwrap();

    let unsigned = node
        .build_multisig_spend(ms_addr, vec![TxOutput::new(400, Node::address(9))])
        .unwrap();
    let sig1 = node
        .sign_multisig_partial(&unsigned, &secret_for(1))
        .unwrap();

    // Two copies of the same valid signature should not satisfy a 2-of-3.
    let err = node
        .combine_multisig_sigs(&unsigned, vec![sig1, sig1])
        .unwrap_err();
    assert!(
        err.to_string().contains("multisig error") || err.to_string().contains("threshold"),
        "{err}"
    );
}

#[test]
fn multisig_spend_rejects_wrong_redeem_script() {
    let mut node = Node::new();
    node.genesis(3, 1_000, 1_000, 1).unwrap();
    let (ms_addr, _script) = make_2of3(&mut node);
    node.send_to(1, 500, ms_addr).unwrap();

    let mut unsigned = node
        .build_multisig_spend(ms_addr, vec![TxOutput::new(400, Node::address(9))])
        .unwrap();
    // Corrupt the redeem script embedded in the witness.
    unsigned.inputs_mut()[0].witness[0][4] ^= 0xFF;

    let sig1 = node
        .sign_multisig_partial(&unsigned, &secret_for(1))
        .unwrap();
    let sig2 = node
        .sign_multisig_partial(&unsigned, &secret_for(2))
        .unwrap();

    let err = node
        .combine_multisig_sigs(&unsigned, vec![sig1, sig2])
        .unwrap_err();
    assert!(err.to_string().contains("multisig error"), "{err}");
}

#[test]
fn snapshot_roundtrip_preserves_multisig_utxo() {
    use std::time::{SystemTime, UNIX_EPOCH};
    let path = {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("kovanica-node-multisig-{nanos}.snap"))
    };
    let path_str = path.to_str().unwrap();

    let mut node = Node::new();
    node.genesis(3, 1_000, 1_000, 1).unwrap();
    let (ms_addr, _script) = make_2of3(&mut node);
    node.send_to(1, 500, ms_addr).unwrap();
    node.save(path_str).unwrap();

    // Fresh node loads the snapshot and must re-register the script to spend.
    let mut restored = Node::new();
    restored.load(path_str).unwrap();
    assert_eq!(restored.balance(&ms_addr).unwrap(), 500);

    // Re-register the redeem script so the node can build the spend.
    restored
        .create_multisig_address(
            2,
            vec![
                *KeyPair::from_u64(1).address().payload(),
                *KeyPair::from_u64(2).address().payload(),
                *KeyPair::from_u64(3).address().payload(),
            ],
        )
        .unwrap();

    let unsigned = restored
        .build_multisig_spend(ms_addr, vec![TxOutput::new(400, Node::address(9))])
        .unwrap();
    let sig1 = restored
        .sign_multisig_partial(&unsigned, &secret_for(1))
        .unwrap();
    let sig2 = restored
        .sign_multisig_partial(&unsigned, &secret_for(2))
        .unwrap();
    let signed = restored
        .combine_multisig_sigs(&unsigned, vec![sig1, sig2])
        .unwrap();
    restored.submit_multisig_tx(signed).unwrap();
    restored
        .produce_block()
        .unwrap()
        .expect("mines after restore");

    assert_eq!(restored.balance(&Node::address(9)).unwrap(), 400);

    let _ = std::fs::remove_file(&path);
}

#[test]
fn create_multisig_rejects_bad_threshold() {
    let mut node = Node::new();
    node.genesis(3, 1_000, 1_000, 1).unwrap();
    let pks: Vec<[u8; 32]> = (1..=3)
        .map(|s| *KeyPair::from_u64(s).address().payload())
        .collect();
    assert!(node.create_multisig_address(0, pks.clone()).is_err());
    assert!(node.create_multisig_address(4, pks).is_err());
}
