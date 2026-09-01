//! Fee-market integration tests: fee-rate eviction, RBF, and the fee estimate
//! endpoint.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::num::NonZeroUsize;

use kovanica_node::explorer::{handle, Explorer};
use kovanica_node::{MempoolConfig, Node};
use kovanica_state::{KeyPair, OutPoint, Transaction, TxOutput};

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

fn tx_spending(op: OutPoint, _input_value: u64, output_value: u64) -> Transaction {
    let kp = KeyPair::from_u64(1);
    Transaction::signed(
        &[(op, &kp)],
        vec![TxOutput::new(output_value, kp.address())],
        vec![],
    )
}

fn actor1_utxos(node: &Node) -> Vec<(OutPoint, u64)> {
    node.utxos_of(&Node::address(1)).unwrap()
}

#[test]
fn fee_rate_eviction_drops_lowest_rate_tx() {
    let config = MempoolConfig {
        max_txs: Some(NonZeroUsize::new(2).unwrap()),
        max_bytes: None,
        min_fee_rate: 0,
        ..Default::default()
    };
    let mut node = Node::with_mempool_config(config);
    node.genesis(3, 100_000, 100_000, 1).unwrap();

    // Produce two empty blocks to create additional actor-1 UTXOs.
    node.produce_empty().unwrap();
    node.produce_empty().unwrap();

    let mut utxos = actor1_utxos(&node);
    utxos.sort_by_key(|(_, v)| *v);
    utxos.reverse();
    assert!(utxos.len() >= 3, "need at least 3 utxos");

    let (op1, v1) = utxos[0];
    let (op2, v2) = utxos[1];
    let (op3, v3) = utxos[2];

    let tx_low = tx_spending(op1, v1, v1 - 1_000);
    let tx_mid = tx_spending(op2, v2, v2 - 10_000);
    let tx_high = tx_spending(op3, v3, v3 - 20_000);

    node.submit_tx(tx_low.clone()).unwrap();
    node.submit_tx(tx_mid.clone()).unwrap();

    // Adding the high-fee tx should evict the lowest-fee tx.
    node.submit_tx(tx_high.clone()).unwrap();

    assert_eq!(node.pending_count(), 2);
    assert!(!node.mempool_tx(&tx_low.id()).is_some());
    assert!(node.mempool_tx(&tx_mid.id()).is_some());
    assert!(node.mempool_tx(&tx_high.id()).is_some());
}

#[test]
fn replace_by_fee_succeeds_with_bump() {
    let config = MempoolConfig {
        min_fee_rate: 0,
        ..Default::default()
    };
    let mut node = Node::with_mempool_config(config);
    node.genesis(3, 100_000, 100_000, 1).unwrap();

    let utxos = actor1_utxos(&node);
    let (op, value) = utxos[0];

    let tx1 = tx_spending(op, value, value - 1_000);
    node.submit_tx(tx1.clone()).unwrap();

    let tx2 = tx_spending(op, value, value - 10_000);
    node.replace_by_fee(tx2.clone(), 1).unwrap();

    assert!(!node.mempool_tx(&tx1.id()).is_some());
    assert!(node.mempool_tx(&tx2.id()).is_some());
}

#[test]
fn replace_by_fee_rejects_insufficient_bump() {
    let config = MempoolConfig {
        min_fee_rate: 0,
        ..Default::default()
    };
    let mut node = Node::with_mempool_config(config);
    node.genesis(3, 100_000, 100_000, 1).unwrap();

    let utxos = actor1_utxos(&node);
    let (op, value) = utxos[0];

    let tx1 = tx_spending(op, value, value - 10_000);
    node.submit_tx(tx1.clone()).unwrap();

    // Lower fee rate; no bump.
    let tx2 = tx_spending(op, value, value - 5_000);
    let err = node.replace_by_fee(tx2.clone(), 1).unwrap_err();
    assert!(err.to_string().contains("insufficient fee bump"));

    assert!(node.mempool_tx(&tx1.id()).is_some());
    assert!(!node.mempool_tx(&tx2.id()).is_some());
}

#[test]
fn fee_estimate_endpoint_returns_rate() {
    let mut app = Explorer::boot();
    app.mining = false;

    let (status, body) = send_req(
        &mut app,
        "GET /api/fee_estimate HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
    );
    assert_eq!(status, 200, "body: {}", body);

    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert!(json["fee_rate"].as_u64().is_some());
    assert_eq!(json["unit"].as_str(), Some("atoms/byte"));
    assert!(json["mempool"].as_u64().is_some());
    assert!(json["bytes"].as_u64().is_some());
}
