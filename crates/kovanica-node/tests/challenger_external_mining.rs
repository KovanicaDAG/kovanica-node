//! Empirical Challenger Test Suite for External Mining JSON Endpoints.
//!
//! Authored by: challenger_2
//!
//! Verifies:
//! 1. Full external mining loop (GET /api/mine/template -> PoW Search -> POST /api/mine/submit).
//! 2. Multi-block DAG progression across consecutive mining iterations.
//! 3. Adversarial invalid nonce rejection when PoW is enforced (meets_target == false -> 400, no DAG mutation).
//! 4. Duplicate block submission idempotency (returns 200 with same block ID, no duplicate DAG insertion).
//! 5. Mempool transaction packing, fee calculation, execution, UTXO updates, and mempool eviction.
//! 6. Custom miner address overrides in templates.
//! 7. Multi-node mesh block propagation upon submission.
//! 8. Robust error handling for malformed JSON, missing fields, invalid hex, and nonexistent parents.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

use kovanica_dag::{pow, Block, BlockId};
use kovanica_node::explorer::{handle, Explorer};
use kovanica_state::{decode_block_payload, KeyPair};

const ATOM: u64 = 100_000_000;

/// Helper to send an HTTP request through Explorer::handle over real TCP loopback.
fn send_http_request(app: &mut Explorer, req: &str) -> (u16, String, serde_json::Value) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");
    let mut client = TcpStream::connect(addr).expect("connect client");
    let (server_stream, _) = listener.accept().expect("accept server");

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

    let body = if let Some(pos) = resp_str.find("\r\n\r\n") {
        resp_str[pos + 4..].to_string()
    } else {
        String::new()
    };

    let json_val = serde_json::from_str(&body).unwrap_or(serde_json::Value::Null);
    (status, body, json_val)
}

/// Helper to mine a block candidate using genuine PoW search.
fn mine_template_candidate(
    parents: &[BlockId],
    work: u128,
    timestamp_ms: u64,
    payload_bytes: &[u8],
) -> (u64, BlockId) {
    let mut nonce = 0u64;
    loop {
        let block = Block::new(
            parents.to_vec(),
            work,
            timestamp_ms,
            nonce,
            payload_bytes.to_vec(),
        );
        let id = block.id();
        if pow::meets_target(&id, work) {
            return (nonce, id);
        }
        nonce = nonce.checked_add(1).expect("nonce overflow");
    }
}

// ============================================================================
// 1. FULL EXTERNAL MINING LOOP & CONSECUTIVE BLOCKS
// ============================================================================

#[test]
fn test_empirical_external_mining_loop_and_chain_growth() {
    let mut app = Explorer::boot();
    let node = app.mesh.node("alpha").unwrap();
    let initial_count = node.block_count().unwrap();
    let mut prev_tip = node.selected_tip().unwrap();

    let num_blocks_to_mine = 5;

    for i in 1..=num_blocks_to_mine {
        // Step 1: Fetch mining template
        let (status, _body, tmpl) = send_http_request(
            &mut app,
            "GET /api/mine/template HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
        );
        assert_eq!(status, 200, "Failed to get mining template on block {i}");
        assert_eq!(tmpl["ok"], true);

        // Step 2: Extract template fields
        let parents_raw = tmpl["parents"].as_array().expect("parents array");
        assert!(!parents_raw.is_empty(), "parents cannot be empty");
        let parents: Vec<BlockId> = parents_raw
            .iter()
            .map(|p| {
                let hex_str = p.as_str().unwrap();
                let b = hex::decode(hex_str).unwrap();
                BlockId::from_bytes(b.try_into().unwrap())
            })
            .collect();

        // Ensure parents include the previous tip
        assert!(
            parents.contains(&prev_tip),
            "Template on iteration {i} must build on previous tip {prev_tip}"
        );

        let work = tmpl["work"].as_u64().unwrap() as u128;
        let timestamp_ms = tmpl["timestamp_ms"].as_u64().unwrap();
        let payload_hex = tmpl["payload"].as_str().unwrap();
        let payload_bytes = hex::decode(payload_hex).unwrap();

        // Verify decoded transactions
        let txs = decode_block_payload(&payload_bytes).expect("decodable payload");
        assert!(!txs.is_empty());
        assert!(txs[0].is_coinbase());

        // Step 3: Perform genuine PoW search
        let (nonce, expected_block_id) =
            mine_template_candidate(&parents, work, timestamp_ms, &payload_bytes);
        assert!(
            pow::meets_target(&expected_block_id, work),
            "Mined block must satisfy meets_target"
        );

        // Step 4: Submit block candidate via POST /api/mine/submit
        let submit_payload = format!(
            "{{\"parents\":[{}],\"work\":{},\"timestamp_ms\":{},\"nonce\":{},\"payload\":\"{}\"}}",
            parents
                .iter()
                .map(|p| format!("\"{}\"", p.to_hex()))
                .collect::<Vec<_>>()
                .join(","),
            work,
            timestamp_ms,
            nonce,
            payload_hex
        );
        let submit_req = format!(
            "POST /api/mine/submit HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            submit_payload.len(),
            submit_payload
        );

        let (sub_status, _sub_body, sub_json) = send_http_request(&mut app, &submit_req);
        assert_eq!(sub_status, 200, "Submit failed on block {i}");
        assert_eq!(sub_json["ok"], true);
        assert_eq!(sub_json["block"], expected_block_id.to_hex());

        // Step 5: Verify DAG tips update and block admission
        let node_after = app.mesh.node("alpha").unwrap();
        assert!(node_after.has_block(&expected_block_id));
        let new_tip = node_after.selected_tip().unwrap();
        assert_eq!(new_tip, expected_block_id);
        assert_eq!(
            node_after.block_count().unwrap(),
            initial_count + (i as usize)
        );

        prev_tip = new_tip;
    }
}

// ============================================================================
// 2. ADVERSARIAL: INVALID NONCE REJECTION
// ============================================================================

#[test]
fn test_empirical_adversarial_invalid_nonce_rejection() {
    let mut app = Explorer::boot();
    // Enable proof of work enforcement
    let node = app.mesh.node_mut("alpha").unwrap();
    node.set_proof_of_work(true).unwrap();

    let tip_before = node.selected_tip().unwrap();
    let count_before = node.block_count().unwrap();

    // 1. Fetch valid template
    let (status, _, tmpl) = send_http_request(
        &mut app,
        "GET /api/mine/template HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
    );
    assert_eq!(status, 200);

    let parents_raw = tmpl["parents"].as_array().unwrap();
    let parents: Vec<BlockId> = parents_raw
        .iter()
        .map(|p| {
            let b = hex::decode(p.as_str().unwrap()).unwrap();
            BlockId::from_bytes(b.try_into().unwrap())
        })
        .collect();

    let work = 1_000_000_000_000u128;
    let timestamp_ms = tmpl["timestamp_ms"].as_u64().unwrap();
    let payload_hex = tmpl["payload"].as_str().unwrap();
    let _payload_bytes = hex::decode(payload_hex).unwrap();

    // With high work target, nonce 0 will not meet the target
    let bad_nonce = 0u64;

    // Submit invalid nonce
    let submit_payload = format!(
        "{{\"parents\":[{}],\"work\":{},\"timestamp_ms\":{},\"nonce\":{},\"payload\":\"{}\"}}",
        parents
            .iter()
            .map(|p| format!("\"{}\"", p.to_hex()))
            .collect::<Vec<_>>()
            .join(","),
        work,
        timestamp_ms,
        bad_nonce,
        payload_hex
    );
    let submit_req = format!(
        "POST /api/mine/submit HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        submit_payload.len(),
        submit_payload
    );

    let (sub_status, sub_body, sub_json) = send_http_request(&mut app, &submit_req);
    assert_eq!(
        sub_status, 400,
        "Submitting invalid PoW nonce must return HTTP 400"
    );
    assert_eq!(sub_json["ok"], false);
    assert!(
        sub_body.contains("proof of work target not met")
            || sub_body.contains("TargetNotMet")
            || sub_json["error"].is_string()
    );

    // Verify ledger / DAG is NOT modified
    let node_after = app.mesh.node("alpha").unwrap();
    assert_eq!(node_after.selected_tip().unwrap(), tip_before);
    assert_eq!(node_after.block_count().unwrap(), count_before);
}

// ============================================================================
// 3. ADVERSARIAL: DUPLICATE BLOCK SUBMISSION IDEMPOTENCY
// ============================================================================

#[test]
fn test_empirical_duplicate_block_submission_idempotent() {
    let mut app = Explorer::boot();

    // 1. Fetch template and mine valid block
    let (status, _, tmpl) = send_http_request(
        &mut app,
        "GET /api/mine/template HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
    );
    assert_eq!(status, 200);

    let parents: Vec<BlockId> = tmpl["parents"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| {
            let b = hex::decode(p.as_str().unwrap()).unwrap();
            BlockId::from_bytes(b.try_into().unwrap())
        })
        .collect();
    let work = tmpl["work"].as_u64().unwrap() as u128;
    let timestamp_ms = tmpl["timestamp_ms"].as_u64().unwrap();
    let payload_hex = tmpl["payload"].as_str().unwrap();
    let payload_bytes = hex::decode(payload_hex).unwrap();

    let (nonce, block_id) = mine_template_candidate(&parents, work, timestamp_ms, &payload_bytes);

    let submit_payload = format!(
        "{{\"parents\":[{}],\"work\":{},\"timestamp_ms\":{},\"nonce\":{},\"payload\":\"{}\"}}",
        parents
            .iter()
            .map(|p| format!("\"{}\"", p.to_hex()))
            .collect::<Vec<_>>()
            .join(","),
        work,
        timestamp_ms,
        nonce,
        payload_hex
    );
    let submit_req = format!(
        "POST /api/mine/submit HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        submit_payload.len(),
        submit_payload
    );

    // Initial submission
    let (status1, _, json1) = send_http_request(&mut app, &submit_req);
    assert_eq!(status1, 200);
    assert_eq!(json1["ok"], true);
    assert_eq!(json1["block"], block_id.to_hex());

    let count_after_first = app.mesh.node("alpha").unwrap().block_count().unwrap();

    // Duplicate submission of exact same block
    let (status2, _, json2) = send_http_request(&mut app, &submit_req);
    assert_eq!(
        status2, 200,
        "Duplicate block submission must return HTTP 200 (idempotent)"
    );
    assert_eq!(json2["ok"], true);
    assert_eq!(
        json2["block"],
        block_id.to_hex(),
        "Duplicate submission must return matching block ID"
    );

    // Block count must remain unchanged
    let count_after_second = app.mesh.node("alpha").unwrap().block_count().unwrap();
    assert_eq!(count_after_first, count_after_second);
}

// ============================================================================
// 4. MEMPOOL TRANSACTIONS: PACKING, EVICTION, UTXO APPLICATION
// ============================================================================

#[test]
fn test_empirical_mempool_packing_and_utxo_eviction() {
    let mut app = Explorer::boot();

    let sender_kp = KeyPair::from_u64(1);
    let recipient_kp = KeyPair::from_u64(2);
    let sender_addr = sender_kp.address();
    let recipient_addr = recipient_kp.address();

    let initial_sender_bal = app
        .mesh
        .node("alpha")
        .unwrap()
        .balance(&sender_addr)
        .unwrap();
    let initial_recipient_bal = app
        .mesh
        .node("alpha")
        .unwrap()
        .balance(&recipient_addr)
        .unwrap();

    // Enqueue a transaction into the mempool: Actor 1 sends 30 KVNC to Actor 2
    let transfer_amount = 30 * ATOM;
    app.mesh.pool("alpha", 1, transfer_amount, 2).unwrap();

    let node = app.mesh.node("alpha").unwrap();
    assert_eq!(node.pending_count(), 1, "Mempool should have 1 pending tx");

    // Fetch mining template — must contain coinbase + mempool transfer tx
    let (status, _, tmpl) = send_http_request(
        &mut app,
        "GET /api/mine/template HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
    );
    assert_eq!(status, 200);

    let txs_array = tmpl["transactions"].as_array().unwrap();
    assert_eq!(
        txs_array.len(),
        2,
        "Template must include 2 transactions: coinbase + mempool spend"
    );
    let fees = tmpl["fees"].as_u64().unwrap();
    assert!(fees > 0, "Template should record non-zero fees");

    let parents: Vec<BlockId> = tmpl["parents"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| {
            let b = hex::decode(p.as_str().unwrap()).unwrap();
            BlockId::from_bytes(b.try_into().unwrap())
        })
        .collect();
    let work = tmpl["work"].as_u64().unwrap() as u128;
    let timestamp_ms = tmpl["timestamp_ms"].as_u64().unwrap();
    let payload_hex = tmpl["payload"].as_str().unwrap();
    let payload_bytes = hex::decode(payload_hex).unwrap();

    // Mine and submit block containing the mempool tx
    let (nonce, block_id) = mine_template_candidate(&parents, work, timestamp_ms, &payload_bytes);

    let submit_payload = format!(
        "{{\"parents\":[{}],\"work\":{},\"timestamp_ms\":{},\"nonce\":{},\"payload\":\"{}\"}}",
        parents
            .iter()
            .map(|p| format!("\"{}\"", p.to_hex()))
            .collect::<Vec<_>>()
            .join(","),
        work,
        timestamp_ms,
        nonce,
        payload_hex
    );
    let submit_req = format!(
        "POST /api/mine/submit HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        submit_payload.len(),
        submit_payload
    );

    let (sub_status, _, sub_json) = send_http_request(&mut app, &submit_req);
    assert_eq!(sub_status, 200);
    assert_eq!(sub_json["block"], block_id.to_hex());

    // Verify Mempool is now empty (evicted)
    let node_after = app.mesh.node("alpha").unwrap();
    assert_eq!(
        node_after.pending_count(),
        0,
        "Mempool must be evicted after block submission"
    );

    // Verify UTXO balances are correctly updated
    let new_sender_bal = node_after.balance(&sender_addr).unwrap();
    let new_recipient_bal = node_after.balance(&recipient_addr).unwrap();

    assert_eq!(
        new_sender_bal,
        initial_sender_bal - (transfer_amount as u128) + (200 * ATOM as u128)
    );
    assert_eq!(
        new_recipient_bal,
        initial_recipient_bal + (transfer_amount as u128)
    );

    // Subsequent template fetch should only have coinbase tx (1 tx)
    let (tmpl2_status, _, tmpl2) = send_http_request(
        &mut app,
        "GET /api/mine/template HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
    );
    assert_eq!(tmpl2_status, 200);
    assert_eq!(
        tmpl2["transactions"].as_array().unwrap().len(),
        1,
        "Next template must have only coinbase tx"
    );
}

// ============================================================================
// 5. CUSTOM MINER ADDRESS OVERRIDE
// ============================================================================

#[test]
fn test_empirical_custom_miner_payout() {
    let mut app = Explorer::boot();
    let custom_kp = KeyPair::from_u64(999);
    let custom_miner = custom_kp.address();

    let initial_bal = app
        .mesh
        .node("alpha")
        .unwrap()
        .balance(&custom_miner)
        .unwrap();
    assert_eq!(initial_bal, 0);

    // Request template specifically targeting custom miner
    let req = format!(
        "GET /api/mine/template?miner={} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
        custom_miner.to_hex()
    );
    let (status, _, tmpl) = send_http_request(&mut app, &req);
    assert_eq!(status, 200);
    assert_eq!(tmpl["miner"], custom_miner.to_hex());

    let parents: Vec<BlockId> = tmpl["parents"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| {
            let b = hex::decode(p.as_str().unwrap()).unwrap();
            BlockId::from_bytes(b.try_into().unwrap())
        })
        .collect();
    let work = tmpl["work"].as_u64().unwrap() as u128;
    let timestamp_ms = tmpl["timestamp_ms"].as_u64().unwrap();
    let payload_hex = tmpl["payload"].as_str().unwrap();
    let payload_bytes = hex::decode(payload_hex).unwrap();

    let (nonce, block_id) = mine_template_candidate(&parents, work, timestamp_ms, &payload_bytes);

    let submit_payload = format!(
        "{{\"parents\":[{}],\"work\":{},\"timestamp_ms\":{},\"nonce\":{},\"payload\":\"{}\"}}",
        parents
            .iter()
            .map(|p| format!("\"{}\"", p.to_hex()))
            .collect::<Vec<_>>()
            .join(","),
        work,
        timestamp_ms,
        nonce,
        payload_hex
    );
    let submit_req = format!(
        "POST /api/mine/submit HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        submit_payload.len(),
        submit_payload
    );

    let (sub_status, _, sub_json) = send_http_request(&mut app, &submit_req);
    assert_eq!(sub_status, 200);
    assert_eq!(sub_json["block"], block_id.to_hex());

    // Verify custom miner received block subsidy
    let node_after = app.mesh.node("alpha").unwrap();
    let new_bal = node_after.balance(&custom_miner).unwrap();
    let subsidy = tmpl["subsidy"].as_u64().unwrap();
    assert_eq!(new_bal, subsidy as u128);
}

// ============================================================================
// 6. MULTI-NODE MESH PROPAGATION
// ============================================================================

#[test]
fn test_empirical_mesh_announcement_and_propagation() {
    let mut app = Explorer::boot();
    // Ensure we have a mesh with multiple nodes (alpha, beta, gamma)
    assert!(app.mesh.node("alpha").is_some());
    assert!(app.mesh.node("beta").is_some());

    // Get template from node "beta"
    let (status, _, tmpl) = send_http_request(
        &mut app,
        "GET /api/mine/template?node=beta HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
    );
    assert_eq!(status, 200);

    let parents: Vec<BlockId> = tmpl["parents"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| {
            let b = hex::decode(p.as_str().unwrap()).unwrap();
            BlockId::from_bytes(b.try_into().unwrap())
        })
        .collect();
    let work = tmpl["work"].as_u64().unwrap() as u128;
    let timestamp_ms = tmpl["timestamp_ms"].as_u64().unwrap();
    let payload_hex = tmpl["payload"].as_str().unwrap();
    let payload_bytes = hex::decode(payload_hex).unwrap();

    let (nonce, block_id) = mine_template_candidate(&parents, work, timestamp_ms, &payload_bytes);

    let submit_payload = format!(
        "{{\"parents\":[{}],\"work\":{},\"timestamp_ms\":{},\"nonce\":{},\"payload\":\"{}\"}}",
        parents
            .iter()
            .map(|p| format!("\"{}\"", p.to_hex()))
            .collect::<Vec<_>>()
            .join(","),
        work,
        timestamp_ms,
        nonce,
        payload_hex
    );
    let submit_req = format!(
        "POST /api/mine/submit?node=beta HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        submit_payload.len(),
        submit_payload
    );

    let (sub_status, _, sub_json) = send_http_request(&mut app, &submit_req);
    assert_eq!(sub_status, 200);
    assert_eq!(sub_json["block"], block_id.to_hex());

    // Let mesh deliver announcements across peers
    app.mesh.drain(16);

    // Verify block is known to beta, alpha, and other peers in mesh
    assert!(app.mesh.node("beta").unwrap().has_block(&block_id));
    assert!(
        app.mesh.node("alpha").unwrap().has_block(&block_id),
        "Block mined on beta must propagate to alpha via mesh announcement"
    );
}

// ============================================================================
// 7. ROBUSTNESS & MALFORMED INPUT REJECTION
// ============================================================================

#[test]
fn test_empirical_malformed_inputs_rejection() {
    let mut app = Explorer::boot();

    let cases = vec![
        // Empty body
        ("POST /api/mine/submit HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: 0\r\n\r\n", "empty body"),
        // Non-JSON body
        ("POST /api/mine/submit HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: 12\r\n\r\nhello_mining", "non-json"),
        // Missing parents
        ("POST /api/mine/submit HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: 48\r\n\r\n{\"work\":1,\"timestamp_ms\":100,\"nonce\":0,\"payload\":\"\"}", "missing parents"),
        // Empty parents array
        ("POST /api/mine/submit HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: 62\r\n\r\n{\"parents\":[],\"work\":1,\"timestamp_ms\":100,\"nonce\":0,\"payload\":\"\"}", "empty parents array"),
        // Non-hex parent ID
        ("POST /api/mine/submit HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: 72\r\n\r\n{\"parents\":[\"zzzz\"],\"work\":1,\"timestamp_ms\":100,\"nonce\":0,\"payload\":\"\"}", "non-hex parent"),
        // Short hex parent ID (not 32 bytes)
        ("POST /api/mine/submit HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: 72\r\n\r\n{\"parents\":[\"abcd\"],\"work\":1,\"timestamp_ms\":100,\"nonce\":0,\"payload\":\"\"}", "short parent"),
        // Non-existent parent ID
        ("POST /api/mine/submit HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: 132\r\n\r\n{\"parents\":[\"1111111111111111111111111111111111111111111111111111111111111111\"],\"work\":1,\"timestamp_ms\":100,\"nonce\":0,\"payload\":\"0000000000000000\"}", "nonexistent parent"),
        // Missing work
        ("POST /api/mine/submit HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: 50\r\n\r\n{\"parents\":[\"00\"],\"timestamp_ms\":100,\"payload\":\"00\"}", "missing work"),
        // Missing timestamp_ms
        ("POST /api/mine/submit HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: 42\r\n\r\n{\"parents\":[\"00\"],\"work\":1,\"payload\":\"00\"}", "missing timestamp"),
        // Missing nonce
        ("POST /api/mine/submit HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: 58\r\n\r\n{\"parents\":[\"00\"],\"work\":1,\"timestamp_ms\":100,\"payload\":\"00\"}", "missing nonce"),
        // Missing payload
        ("POST /api/mine/submit HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: 50\r\n\r\n{\"parents\":[\"00\"],\"work\":1,\"timestamp_ms\":100,\"nonce\":0}", "missing payload"),
        // Invalid hex in payload
        ("POST /api/mine/submit HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: 134\r\n\r\n{\"parents\":[\"0000000000000000000000000000000000000000000000000000000000000000\"],\"work\":1,\"timestamp_ms\":100,\"nonce\":0,\"payload\":\"nothex\"}", "invalid payload hex"),
        // Corrupt / undecodable payload bytes
        ("POST /api/mine/submit HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: 136\r\n\r\n{\"parents\":[\"0000000000000000000000000000000000000000000000000000000000000000\"],\"work\":1,\"timestamp_ms\":100,\"nonce\":0,\"payload\":\"deadbeef\"}", "corrupt payload bytes"),
        // Unknown node parameter in GET /api/mine/template
        ("GET /api/mine/template?node=ghost HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n", "unknown node get"),
        // Unknown node parameter in POST /api/mine/submit
        ("POST /api/mine/submit?node=ghost HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}", "unknown node post"),
    ];

    for (req, desc) in cases {
        let (status, _body, json) = send_http_request(&mut app, req);
        assert_eq!(
            status, 400,
            "Case '{}' must be rejected with HTTP 400. Got {}", desc, status
        );
        assert_eq!(
            json["ok"], false,
            "Case '{}' must return ok: false JSON", desc
        );
    }
}
