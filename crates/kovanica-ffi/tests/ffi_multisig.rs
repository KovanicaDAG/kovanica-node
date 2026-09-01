//! FFI-level multisig flow tests — mirror the Kotlin/Swift surface exactly.

use kovanica_ffi::{LightConfig, LightNode, MultisigSpendOutput};
use kovanica_state::KeyPair;

fn fresh() -> LightNode {
    LightNode::new(LightConfig::default()).expect("genesis ok")
}

fn secret_for(seed: u64) -> String {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&seed.to_le_bytes());
    hex::encode(bytes)
}

fn pubkey_hex(seed: u64) -> String {
    hex::encode(KeyPair::from_u64(seed).address().payload())
}

#[test]
fn ffi_two_of_three_create_fund_spend() {
    let node = fresh();

    let ms = node
        .create_multisig_address(2, vec![pubkey_hex(1), pubkey_hex(2), pubkey_hex(3)])
        .unwrap();
    assert!(ms.address.starts_with("kvnc") && ms.address.ends_with("dag"));
    assert_eq!(
        hex::decode(&ms.redeem_script_hex).unwrap().len(),
        2 + 32 * 3
    );

    // Fund from the founder seed (actor 1).
    node.send_from(secret_for(1), 500, ms.address.clone())
        .unwrap();
    assert_eq!(node.balance_of_address(ms.address.clone()).unwrap(), "500");

    // Build spend to actor 9.
    let unsigned_blob = node
        .build_multisig_spend(
            ms.address.clone(),
            vec![MultisigSpendOutput {
                value: 400,
                address: kovanica_node::Node::address(9).to_hex(),
            }],
        )
        .unwrap();

    // Partial signatures from two cosigners.
    let sig1 = node
        .sign_multisig_partial(unsigned_blob.clone(), secret_for(1))
        .unwrap();
    let sig2 = node
        .sign_multisig_partial(unsigned_blob.clone(), secret_for(2))
        .unwrap();

    // Combine and submit.
    let signed_blob = node
        .combine_multisig_sigs(unsigned_blob, vec![sig1, sig2])
        .unwrap();
    let tx_id = node.submit_multisig_tx(signed_blob).unwrap();
    assert_eq!(hex::decode(&tx_id).unwrap().len(), 32);

    node.produce_block().unwrap().expect("mines the spend");
    assert_eq!(node.balance_of_seed(9).unwrap(), "400");
    assert_eq!(node.balance_of_address(ms.address).unwrap(), "99"); // 500 - 400 - fee(1)
}

#[test]
fn ffi_multisig_rejects_bad_threshold() {
    let node = fresh();
    // Threshold (2) exceeds key count (1).
    let err = node
        .create_multisig_address(2, vec![pubkey_hex(1)])
        .unwrap_err();
    assert!(
        err.to_string().contains("threshold") || err.to_string().contains("M"),
        "{err}"
    );
}

#[test]
fn ffi_multisig_rejects_bad_pubkey_hex() {
    let node = fresh();
    let err = node
        .create_multisig_address(1, vec!["nothex".to_string()])
        .unwrap_err();
    assert!(
        err.to_string().contains("hex") || err.to_string().contains("pubkey"),
        "{err}"
    );
}

#[test]
fn ffi_combine_rejects_duplicate_signatures() {
    let node = fresh();
    let ms = node
        .create_multisig_address(2, vec![pubkey_hex(1), pubkey_hex(2), pubkey_hex(3)])
        .unwrap();
    node.send_from(secret_for(1), 500, ms.address.clone())
        .unwrap();

    let unsigned = node
        .build_multisig_spend(
            ms.address,
            vec![MultisigSpendOutput {
                value: 400,
                address: kovanica_node::Node::address(9).to_hex(),
            }],
        )
        .unwrap();
    let sig1 = node
        .sign_multisig_partial(unsigned.clone(), secret_for(1))
        .unwrap();

    let err = node
        .combine_multisig_sigs(unsigned, vec![sig1.clone(), sig1])
        .unwrap_err();
    assert!(
        err.to_string().contains("multisig") || err.to_string().contains("duplicate"),
        "{err}"
    );
}
