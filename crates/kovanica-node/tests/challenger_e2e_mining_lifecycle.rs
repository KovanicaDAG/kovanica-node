//! Challenger 2: Empirical End-to-End External Mining Lifecycle & Consensus Integration Harness
//!
//! Objectives:
//! 1. Fetch template from `GET /api/mine/template`.
//! 2. Construct block with parents, target work, candidate timestamp, and solve for a valid nonce satisfying `meets_target`.
//! 3. Submit candidate block to `POST /api/mine/submit`.
//! 4. Verify HTTP 200 response with correct block ID.
//! 5. Verify block is accepted into DAG ledger, tips are updated, mempool transactions are included and evicted, and coinbase rewards are credited.
//! 6. Verify rejection of invalid nonces and idempotent acceptance of duplicate submissions.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use kovanica_dag::{pow, Block, BlockId};
use kovanica_node::explorer::{handle, Explorer};
use kovanica_state::{decode_block_payload, KeyPair};

const ATOM: u64 = 100_000_000;

fn http_exchange(app: &mut Explorer, req: &str) -> (u16, String, serde_json::Value) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let mut client = TcpStream::connect(addr).expect("connect");
    let (server_stream, _) = listener.accept().expect("accept");

    client.write_all(req.as_bytes()).expect("write");
    client.shutdown(std::net::Shutdown::Write).expect("shutdown");

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

    let json_val = serde_json::from_str(&body).unwrap_or(serde_json::Value::Null);
    (status, body, json_val)
}

#[test]
fn test_challenger_2_full_mining_lifecycle_and_consensus() {
    println!("\n=== [CHALLENGER 2 EMPIRICAL TEST HARNESS START] ===");
    let mut app = Explorer::boot();

    let node = app.mesh.node("alpha").unwrap();
    let initial_tip = node.selected_tip().unwrap();
    let initial_count = node.block_count().unwrap();
    println!("[INIT] Node: alpha, Initial Tip: {}, Block Count: {}", initial_tip, initial_count);

    // Setup actors and mempool tx
    let miner_kp = KeyPair::from_u64(101);
    let miner_addr = miner_kp.address();
    let sender_kp = KeyPair::from_u64(1);
    let sender_addr = sender_kp.address();
    let recipient_kp = KeyPair::from_u64(2);
    let recipient_addr = recipient_kp.address();

    let sender_bal_before = app.mesh.node("alpha").unwrap().balance(&sender_addr).unwrap();
    let recipient_bal_before = app.mesh.node("alpha").unwrap().balance(&recipient_addr).unwrap();
    let miner_bal_before = app.mesh.node("alpha").unwrap().balance(&miner_addr).unwrap();

    println!("[BALANCES BEFORE] Sender: {}, Recipient: {}, Miner: {}", sender_bal_before, recipient_bal_before, miner_bal_before);

    // Queue 1 mempool transaction: Actor 1 sends 25 KVNC to Actor 2
    let transfer_atoms = 25 * ATOM;
    app.mesh.pool("alpha", 1, transfer_atoms, 2).unwrap();
    assert_eq!(app.mesh.node("alpha").unwrap().pending_count(), 1);
    println!("[MEMPOOL] Enqueued 25 KVNC transfer. Pending count: 1");

    // =========================================================================
    // STEP 1: GET /api/mine/template?miner=<miner_addr>
    // =========================================================================
    let template_req = format!(
        "GET /api/mine/template?miner={} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
        miner_addr.to_hex()
    );
    let (t_status, _t_body, tmpl) = http_exchange(&mut app, &template_req);
    println!("[STEP 1] GET /api/mine/template -> HTTP {}", t_status);
    assert_eq!(t_status, 200, "Template fetch must return 200");
    assert_eq!(tmpl["ok"], true);

    let parents_raw = tmpl["parents"].as_array().expect("parents array");
    assert!(!parents_raw.is_empty());
    let parents: Vec<BlockId> = parents_raw
        .iter()
        .map(|p| {
            let b = hex::decode(p.as_str().unwrap()).unwrap();
            BlockId::from_bytes(b.try_into().unwrap())
        })
        .collect();
    assert!(parents.contains(&initial_tip));

    let work = tmpl["work"].as_u64().expect("work number") as u128;
    let timestamp_ms = tmpl["timestamp_ms"].as_u64().expect("timestamp_ms number");
    let payload_hex = tmpl["payload"].as_str().expect("payload hex");
    let payload_bytes = hex::decode(payload_hex).expect("valid hex payload");
    let subsidy = tmpl["subsidy"].as_u64().expect("subsidy");
    let fees = tmpl["fees"].as_u64().expect("fees");

    println!("[STEP 1 DETAILS] Parents: {:?}, Work: {}, Timestamp: {}, Subsidy: {}, Fees: {}",
        parents.iter().map(|p| p.to_hex()).collect::<Vec<_>>(), work, timestamp_ms, subsidy, fees);

    assert_eq!(tmpl["miner"], miner_addr.to_hex());
    let decoded_txs = decode_block_payload(&payload_bytes).expect("decodable payload");
    assert_eq!(decoded_txs.len(), 2, "Payload must contain coinbase + mempool tx");
    assert!(decoded_txs[0].is_coinbase());
    assert!(!decoded_txs[1].is_coinbase());
    assert!(fees > 0);

    // =========================================================================
    // STEP 2: Construct block & solve for valid nonce satisfying meets_target
    // =========================================================================
    let mut nonce = 0u64;
    let (valid_nonce, mined_block_id) = loop {
        let candidate = Block::new(parents.clone(), work, timestamp_ms, nonce, payload_bytes.clone());
        let id = candidate.id();
        if pow::meets_target(&id, work) {
            break (nonce, id);
        }
        nonce = nonce.checked_add(1).unwrap();
    };

    println!("[STEP 2] Mined Nonce: {}, Block ID: {}", valid_nonce, mined_block_id);
    assert!(pow::meets_target(&mined_block_id, work));

    // =========================================================================
    // STEP 3: POST /api/mine/submit
    // =========================================================================
    let submit_json = format!(
        "{{\"parents\":[{}],\"work\":{},\"timestamp_ms\":{},\"nonce\":{},\"payload\":\"{}\"}}",
        parents.iter().map(|p| format!("\"{}\"", p.to_hex())).collect::<Vec<_>>().join(","),
        work,
        timestamp_ms,
        valid_nonce,
        payload_hex
    );
    let submit_req = format!(
        "POST /api/mine/submit HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        submit_json.len(),
        submit_json
    );

    let (s_status, _s_body, s_json) = http_exchange(&mut app, &submit_req);
    println!("[STEP 3] POST /api/mine/submit -> HTTP {}", s_status);

    // =========================================================================
    // STEP 4: Verify HTTP 200 response with correct block ID
    // =========================================================================
    assert_eq!(s_status, 200);
    assert_eq!(s_json["ok"], true);
    assert_eq!(s_json["block"], mined_block_id.to_hex());
    println!("[STEP 4] Verified response: ok=true, block={}", s_json["block"]);

    // =========================================================================
    // STEP 5: Verify DAG ledger acceptance, tip update, mempool eviction, UTXO rewards
    // =========================================================================
    let node_after = app.mesh.node("alpha").unwrap();
    assert!(node_after.has_block(&mined_block_id), "Block must be in DAG ledger");
    assert_eq!(node_after.selected_tip().unwrap(), mined_block_id, "Tips must be updated to new block ID");
    assert_eq!(node_after.block_count().unwrap(), initial_count + 1, "Block count must increment by 1");
    assert_eq!(node_after.pending_count(), 0, "Mempool must be evicted");

    let sender_bal_after = node_after.balance(&sender_addr).unwrap();
    let recipient_bal_after = node_after.balance(&recipient_addr).unwrap();
    let miner_bal_after = node_after.balance(&miner_addr).unwrap();

    println!("[STEP 5] BALANCES AFTER: Sender: {}, Recipient: {}, Miner: {}", sender_bal_after, recipient_bal_after, miner_bal_after);
    assert_eq!(recipient_bal_after, recipient_bal_before + (transfer_atoms as u128));
    assert_eq!(miner_bal_after, (subsidy + fees) as u128);

    // =========================================================================
    // STEP 6: Verify rejection of invalid nonces & duplicate submission idempotency
    // =========================================================================
    // Part A: Duplicate submission of valid block
    let (dup_status, _dup_body, dup_json) = http_exchange(&mut app, &submit_req);
    println!("[STEP 6A] Duplicate submission -> HTTP {}", dup_status);
    assert_eq!(dup_status, 200);
    assert_eq!(dup_json["ok"], true);
    assert_eq!(dup_json["block"], mined_block_id.to_hex());
    assert_eq!(app.mesh.node("alpha").unwrap().block_count().unwrap(), initial_count + 1, "Duplicate must not increase block count");

    // Part B: Invalid nonce rejection when PoW is enforced
    let node_mut = app.mesh.node_mut("alpha").unwrap();
    node_mut.set_proof_of_work(true).unwrap();

    let invalid_nonce_submit = format!(
        "{{\"parents\":[{}],\"work\":1000000000000,\"timestamp_ms\":{},\"nonce\":0,\"payload\":\"{}\"}}",
        parents.iter().map(|p| format!("\"{}\"", p.to_hex())).collect::<Vec<_>>().join(","),
        timestamp_ms,
        payload_hex
    );
    let invalid_req = format!(
        "POST /api/mine/submit HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        invalid_nonce_submit.len(),
        invalid_nonce_submit
    );
    let (inv_status, _inv_body, inv_json) = http_exchange(&mut app, &invalid_req);
    println!("[STEP 6B] Invalid Nonce submission -> HTTP {}", inv_status);
    assert_eq!(inv_status, 400);
    assert_eq!(inv_json["ok"], false);
    assert_eq!(app.mesh.node("alpha").unwrap().block_count().unwrap(), initial_count + 1, "Invalid submission must not modify DAG");

    println!("=== [CHALLENGER 2 EMPIRICAL TEST HARNESS COMPLETED SUCCESSFULLY] ===\n");
}
