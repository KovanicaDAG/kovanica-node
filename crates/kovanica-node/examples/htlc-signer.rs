//! Off-node signing for HTLC atomic-swap demos (M1.6).
//!
//! The web wallet signs in the browser; this binary stands in for that step in
//! a pure terminal demo so the secret key never has to reach the node.
//!
//! Usage:
//!   htlc-signer addr <key-index>            # print the derived address
//!   htlc-signer sign <key-index> <sighash-hex>   # Ed25519 signature over the sighash
//!   htlc-signer hash <preimage-hex>         # BLAKE3(preimage), the committed hash
//!
//! `key-index` derives a deterministic keypair (same scheme as the integration
//! tests: `KeyPair::from_u64(index)`); index 1 is the testnet founder that
//! holds the genesis grant.

use std::env;

fn main() {
    let mut args = env::args().skip(1);
    let mode = args.next().unwrap_or_default();
    match mode.as_str() {
        "addr" => {
            let idx: u64 = args.next().expect("addr <key-index>").parse().expect("key index");
            let kp = kovanica_state::KeyPair::from_u64(idx);
            println!("{}", kp.address().to_hex());
        }
        "sign" => {
            let idx: u64 = args.next().expect("sign <key-index> <sighash-hex>").parse().expect("key index");
            let sighash_hex = args.next().expect("sign <key-index> <sighash-hex>");
            let sighash: [u8; 32] = hex::decode(sighash_hex.trim())
                .expect("sighash hex")
                .try_into()
                .expect("sighash must be 32 bytes");
            let kp = kovanica_state::KeyPair::from_u64(idx);
            println!("{}", hex::encode(kp.sign(&sighash)));
        }
        "hash" => {
            let preimage_hex = args.next().expect("hash <preimage-hex>");
            let preimage = hex::decode(preimage_hex.trim()).expect("preimage hex");
            println!("{}", hex::encode(blake3::hash(&preimage).as_bytes()));
        }
        _ => eprintln!("usage: htlc-signer <addr|sign|hash> …"),
    }
}