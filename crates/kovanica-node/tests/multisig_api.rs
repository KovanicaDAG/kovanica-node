//! Integration tests for the multisig HTTP JSON API.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

use kovanica_node::explorer::{handle, Explorer};
use kovanica_state::{Address, KeyPair, Transaction};

const ATOM: u64 = 100_000_000;

/// Send a raw HTTP request through Explorer::handle over a real TCP loopback socket.
fn http_post(app: &mut Explorer, path: &str, body: &str) -> (u16, String, serde_json::Value) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");
    let mut client = TcpStream::connect(addr).expect("connect client");
    let (server_stream, _) = listener.accept().expect("accept server");

    let req = format!(
        "POST {} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        path,
        body.len(),
        body
    );
    client.write_all(req.as_bytes()).expect("write request");
    client
        .shutdown(std::net::Shutdown::Write)
        .expect("shutdown write");

    let _ = handle(app, server_stream);

    let mut resp = Vec::new();
    let _ = client.read_to_end(&mut resp);
    let resp_str = String::from_utf8_lossy(&resp).to_string();

    let status = resp_str
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);

    let body_text = if let Some(pos) = resp_str.find("\r\n\r\n") {
        resp_str[pos + 4..].to_string()
    } else {
        String::new()
    };

    let json_val = serde_json::from_str(&body_text).unwrap_or(serde_json::Value::Null);
    (status, body_text, json_val)
}

fn secret_hex_from_seed(seed: u64) -> String {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&seed.to_le_bytes());
    hex::encode(bytes)
}

fn pubkey_hex_from_seed(seed: u64) -> String {
    let kp = KeyPair::from_u64(seed);
    hex::encode(kp.address().payload())
}

/// A 2-of-3 multisig create → fund → build → sign → combine → submit flow.
#[test]
fn test_multisig_api_happy_path() {
    let mut app = Explorer::boot();

    // 1. Create a 2-of-3 multisig address.
    let pk1 = pubkey_hex_from_seed(10);
    let pk2 = pubkey_hex_from_seed(11);
    let pk3 = pubkey_hex_from_seed(12);
    let create_body = format!(
        "{{\"threshold\":2,\"pubkeys_hex\":[\"{}\",\"{}\",\"{}\"]}}",
        pk1, pk2, pk3
    );
    let (status, _text, json) = http_post(&mut app, "/api/multisig/create", &create_body);
    assert_eq!(status, 200, "create failed: {}", json["error"]);
    let address = json["address"].as_str().unwrap().to_string();
    let redeem_script_hex = json["redeem_script_hex"].as_str().unwrap().to_string();
    assert!(!address.is_empty());
    assert!(!redeem_script_hex.is_empty());

    // 2. Fund the multisig address from actor 1 (founder).
    {
        let node = app.mesh.node_mut("alpha").unwrap();
        let msig_addr = Address::parse(&address).unwrap();
        node.send_to(1, 50 * ATOM, msig_addr)
            .expect("fund multisig");
    }

    // 3. Build a spend back to actor 2.
    let recipient = KeyPair::from_u64(2).address().to_kvnc();
    let build_body = format!(
        "{{\"address\":\"{}\",\"outputs\":[{{\"address\":\"{}\",\"amount_atoms\":{}}}]}}",
        address,
        recipient,
        10 * ATOM
    );
    let (status, _text, json) = http_post(&mut app, "/api/multisig/build", &build_body);
    assert_eq!(status, 200, "build failed: {}", json["error"]);
    let tx_blob_hex = json["tx_blob_hex"].as_str().unwrap().to_string();
    let sighash_hex = json["sighash_hex"].as_str().unwrap().to_string();
    assert!(!tx_blob_hex.is_empty());
    assert!(!sighash_hex.is_empty());

    // Verify the sighash matches decoding the tx blob.
    {
        let tx_bytes = hex::decode(&tx_blob_hex).unwrap();
        let tx = Transaction::decode(&tx_bytes).unwrap();
        assert_eq!(hex::encode(tx.sighash()), sighash_hex);
    }

    // 4. Produce two partial signatures.
    let sign_body1 = format!(
        "{{\"tx_blob_hex\":\"{}\",\"secret_hex\":\"{}\"}}",
        tx_blob_hex,
        secret_hex_from_seed(10)
    );
    let (status, _text, sig1) = http_post(&mut app, "/api/multisig/sign", &sign_body1);
    assert_eq!(status, 200, "sign 1 failed: {}", sig1["error"]);
    let partial1 = sig1["partial_sig_hex"].as_str().unwrap().to_string();

    let sign_body2 = format!(
        "{{\"tx_blob_hex\":\"{}\",\"secret_hex\":\"{}\"}}",
        tx_blob_hex,
        secret_hex_from_seed(11)
    );
    let (status, _text, sig2) = http_post(&mut app, "/api/multisig/sign", &sign_body2);
    assert_eq!(status, 200, "sign 2 failed: {}", sig2["error"]);
    let partial2 = sig2["partial_sig_hex"].as_str().unwrap().to_string();

    // 5. Combine the partial signatures.
    let combine_body = format!(
        "{{\"tx_blob_hex\":\"{}\",\"partial_sigs_hex\":[\"{}\",\"{}\"]}}",
        tx_blob_hex, partial1, partial2
    );
    let (status, _text, combined) = http_post(&mut app, "/api/multisig/combine", &combine_body);
    assert_eq!(status, 200, "combine failed: {}", combined["error"]);
    let signed_tx_blob_hex = combined["signed_tx_blob_hex"].as_str().unwrap().to_string();
    assert!(!signed_tx_blob_hex.is_empty());

    // 6. Submit the fully-signed transaction.
    let submit_body = format!("{{\"signed_tx_blob_hex\":\"{}\"}}", signed_tx_blob_hex);
    let (status, _text, submitted) = http_post(&mut app, "/api/multisig/submit", &submit_body);
    assert_eq!(status, 200, "submit failed: {}", submitted["error"]);
    let tx_id_hex = submitted["tx_id_hex"].as_str().unwrap().to_string();
    assert!(!tx_id_hex.is_empty());

    // 7. Produce a block so the mempool tx is confirmed.
    {
        let node = app.mesh.node_mut("alpha").unwrap();
        node.produce_block().expect("produce block");
    }

    // The recipient balance should reflect the spend.
    let node = app.mesh.node("alpha").unwrap();
    let balance = node.balance(&KeyPair::from_u64(2).address()).unwrap();
    assert_eq!(balance, (10 * ATOM) as u128);
}

/// Reject creating a multisig with threshold > number of pubkeys.
#[test]
fn test_multisig_api_rejects_invalid_threshold() {
    let mut app = Explorer::boot();
    let pk1 = pubkey_hex_from_seed(20);
    let body = format!("{{\"threshold\":3,\"pubkeys_hex\":[\"{}\"]}}", pk1);
    let (status, _text, json) = http_post(&mut app, "/api/multisig/create", &body);
    assert_eq!(status, 400);
    assert!(json["error"].as_str().unwrap().contains("threshold"));
}
