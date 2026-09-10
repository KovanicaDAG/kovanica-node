//! Integration tests for the explorer detail endpoints:
//!   GET /api/block/:id
//!   GET /api/tx/:id
//!   GET /api/address/:address

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

use kovanica_node::explorer::{handle, Explorer};
use kovanica_state::KeyPair;

const ATOM: u64 = 100_000_000;

fn send_req(app: &mut Explorer, req: &str) -> (u16, String) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let mut client = TcpStream::connect(addr).unwrap();
    let (server_stream, _) = listener.accept().unwrap();

    client.write_all(req.as_bytes()).unwrap();
    client.shutdown(std::net::Shutdown::Write).unwrap();

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

    let body = if let Some(pos) = resp_str.find("\r\n\r\n") {
        resp_str[pos + 4..].to_string()
    } else {
        String::new()
    };
    (status, body)
}

#[test]
fn block_detail_includes_header_and_topology() {
    let mut app = Explorer::boot();
    app.mining = false;

    // Produce a block so we have a non-genesis block to query.
    app.mesh.pool("alpha", 1, ATOM, 3).unwrap();
    app.mesh.produce("alpha").unwrap();
    app.mesh.drain(8);

    let tip = app.mesh.node("alpha").unwrap().selected_tip().unwrap();
    let (status, body) = send_req(
        &mut app,
        &format!("GET /api/block/{} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n", tip),
    );
    assert_eq!(status, 200, "body: {}", body);

    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["id"].as_str().unwrap(), tip.to_string());
    assert!(json["prev_hash"].as_str().unwrap().len() == 64);
    assert!(json["merkle_root"].as_str().unwrap().len() == 64);
    assert!(json["height"].as_u64().unwrap() > 0);
    assert!(json["timestamp_ms"].as_u64().unwrap() > 0);
    assert!(json["blue_score"].as_u64().unwrap() > 0);
    assert!(json["chain_blue_work"].as_u64().unwrap() >= 1);
    assert!(json["work"].as_u64().unwrap() >= 1);
    assert!(!json["parents"].as_array().unwrap().is_empty());
    assert!(!json["txs"].as_array().unwrap().is_empty());
    assert!(json["kind"].as_str().unwrap() == "pow" || json["kind"].as_str().unwrap() == "staked");
    assert!(["genesis", "chain", "blue", "red"].contains(&json["colour"].as_str().unwrap()));
    assert!(["tip", "confirmed", "accepted", "pending"]
        .contains(&json["confirming_status"].as_str().unwrap()));
}

#[test]
fn block_detail_returns_404_for_unknown_block() {
    let mut app = Explorer::boot();
    let (status, body) = send_req(
        &mut app,
        "GET /api/block/0000000000000000000000000000000000000000000000000000000000000000 HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
    );
    assert_eq!(status, 404);
    assert!(body.contains("\"ok\":false"));
}

#[test]
fn tx_detail_reports_amount_fee_and_confirmations() {
    let mut app = Explorer::boot();
    app.mining = false;

    let to = KeyPair::from_u64(7);
    app.mesh.pool("alpha", 1, ATOM, 7).unwrap();
    app.mesh.produce("alpha").unwrap();
    app.mesh.drain(8);

    let tx_id = app
        .mesh
        .node("alpha")
        .unwrap()
        .history_of(&to.address(), 0)
        .unwrap()
        .into_iter()
        .find(|e| matches!(e.direction, kovanica_node::WalletDirection::Received))
        .map(|e| e.tx_id)
        .expect("receiver history entry");

    let (status, body) = send_req(
        &mut app,
        &format!("GET /api/tx/{} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n", tx_id),
    );
    assert_eq!(status, 200, "body: {}", body);

    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["id"].as_str().unwrap(), tx_id.to_string());
    assert_eq!(json["coinbase"].as_bool(), Some(false));
    assert_eq!(json["confirmed"].as_bool(), Some(true));
    assert!(json["confirmations"].as_u64().unwrap() >= 1);
    assert!(json["block"].as_str().is_some());
    assert!(json["blue_score"].as_u64().is_some());
    let outputs = json["outputs"].as_array().unwrap();
    let output_sum: u64 = outputs.iter().map(|o| o["value"].as_u64().unwrap()).sum();
    assert_eq!(json["amount"].as_u64().unwrap(), output_sum);
    assert!(outputs.iter().any(|o| o["value"].as_u64() == Some(ATOM)));
    assert!(json["fee"].as_u64().unwrap() >= 1);
    assert!(json["addresses"].as_array().unwrap().len() >= 2);
    assert!(!json["inputs"].as_array().unwrap().is_empty());
    assert!(!outputs.is_empty());
    assert!(json["size"].as_u64().unwrap() > 0);
}

#[test]
fn tx_detail_returns_404_for_unknown_tx() {
    let mut app = Explorer::boot();
    let (status, body) = send_req(
        &mut app,
        "GET /api/tx/0000000000000000000000000000000000000000000000000000000000000000 HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
    );
    assert_eq!(status, 404);
    assert!(body.contains("\"ok\":false"));
}

#[test]
fn address_detail_returns_balance_and_paginated_history() {
    let mut app = Explorer::boot();
    app.mining = false;

    let to = KeyPair::from_u64(8);
    app.mesh.pool("alpha", 1, ATOM, 8).unwrap();
    app.mesh.produce("alpha").unwrap();
    app.mesh.drain(8);

    let addr = to.address();
    let (status, body) = send_req(
        &mut app,
        &format!(
            "GET /api/address/{} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
            addr.to_hex()
        ),
    );
    assert_eq!(status, 200, "body: {}", body);

    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["address"].as_str().unwrap(), addr.to_hex());
    assert_eq!(json["balance"].as_u64().unwrap(), ATOM);
    assert_eq!(json["page"].as_u64(), Some(1));
    assert_eq!(json["per_page"].as_u64(), Some(20));
    assert!(json["total"].as_u64().unwrap() >= 1);
    assert!(json["pages"].as_u64().unwrap() >= 1);

    let txs = json["txs"].as_array().unwrap();
    assert!(!txs.is_empty());
    let first = &txs[0];
    assert!(first["tx"].as_str().is_some());
    assert!(first["block"].as_str().is_some());
    assert!(first["kind"].as_str().is_some());
    assert_eq!(first["amount"].as_u64().unwrap(), ATOM);
}

#[test]
fn address_detail_pagination_respects_per_page() {
    let mut app = Explorer::boot();
    app.mining = false;

    let to = KeyPair::from_u64(3);
    app.mesh.pool("alpha", 1, ATOM, 3).unwrap();
    app.mesh.produce("alpha").unwrap();
    app.mesh.drain(8);

    let addr = to.address();
    let (status, body) = send_req(
        &mut app,
        &format!(
            "GET /api/address/{}?per_page=5 HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
            addr.to_hex()
        ),
    );
    assert_eq!(status, 200, "body: {}", body);

    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["per_page"].as_u64(), Some(5));
    assert!(json["txs"].as_array().unwrap().len() <= 5);
}
