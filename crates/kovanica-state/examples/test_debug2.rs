use kovanica_state::{
    apply_block, AssetId, KeyPair, OutPoint, Transaction, TxInput, TxOutput, UtxoSet,
};

fn generate_key(count: usize) -> KeyPair {
    KeyPair::from_u64((1000 + count) as u64)
}

fn make_asset_id(seed: u64) -> AssetId {
    let mut bytes = [0u8; 32];
    bytes[0..8].copy_from_slice(&seed.to_le_bytes());
    AssetId::from_bytes(bytes)
}

fn main() {
    let alice = generate_key(6);
    let bob = generate_key(7);
    let unknown_asset = make_asset_id(999); // Not in UTXO set

    let mut utxo = UtxoSet::new();
    let coinbase = Transaction::coinbase(
        vec![TxOutput::native(1_000, alice.address())],
        b"cb".to_vec(),
    );
    let coin = OutPoint::new(coinbase.id(), 0);
    apply_block(&mut utxo, &[coinbase], 1_000).unwrap();

    // Try to create output with unknown asset (no input of that asset)
    let spend = Transaction::new(
        vec![TxInput {
            outpoint: coin,
            witness: vec![],
        }],
        vec![TxOutput::new(900, Some(unknown_asset), bob.address())],
        b"unknown".to_vec(),
    );

    let signed_spend = Transaction::new(
        vec![TxInput {
            outpoint: coin,
            witness: vec![alice.sign(&spend.sighash()).to_vec()],
        }],
        vec![TxOutput::new(900, Some(unknown_asset), bob.address())],
        b"unknown".to_vec(),
    );

    let err = apply_block(&mut utxo, &[signed_spend], 0).unwrap_err();
    println!("Error: {:?}", err);
}
