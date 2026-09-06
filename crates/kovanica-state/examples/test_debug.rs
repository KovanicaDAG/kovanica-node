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
    let alice = generate_key(0);
    let bob = generate_key(1);
    let asset = make_asset_id(42);

    let mut utxo = UtxoSet::new();
    let coinbase = Transaction::coinbase(
        vec![TxOutput::new(1_000, Some(asset), alice.address())],
        b"cb".to_vec(),
    );
    let coin = OutPoint::new(coinbase.id(), 0);
    let res = apply_block(&mut utxo, &[coinbase], 1_000);
    println!("Coinbase result: {:?}", res);

    let spend = Transaction::new(
        vec![TxInput {
            outpoint: coin,
            witness: vec![],
        }],
        vec![TxOutput::new(900, Some(asset), bob.address())],
        b"transfer".to_vec(),
    );

    let signed_spend = Transaction::new(
        vec![TxInput {
            outpoint: coin,
            witness: vec![alice.sign(&spend.sighash()).to_vec()],
        }],
        vec![TxOutput::new(900, Some(asset), bob.address())],
        b"transfer".to_vec(),
    );

    let res = apply_block(&mut utxo, &[signed_spend], 0);
    println!("Spend result: {:?}", res);
}
