use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

use kovanica_dag::{pow, Block, BlockId};
use kovanica_node::explorer::{handle, Explorer};
use kovanica_state::{decode_block_payload, KeyPair};

const ATOM: u64 = 100_000_000;

fn send_request(app: &mut Explorer, req: &str) -> (u16, String) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");
    let mut client = TcpStream::connect(addr).expect("connect client");
    let (server_stream, _) = listener.accept().expect("accept server");

    client.write_all(req.as_bytes()).expect("write request");
    client.shutdown(std::net::Shutdown::Write).expect("shutdown write");

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
fn test_get_mining_template_endpoint() {
    let mut app = Explorer::boot();
    let (status, body) = send_request(
        &mut app,
        "GET /api/mine/template HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
    );
    assert_eq!(status, 200, "Template fetch failed: {body}");

    let v: serde_json::Value = serde_json::from_str(&body).expect("valid JSON template");
    assert_eq!(v["ok"], true);
    assert!(v["parents"].is_array());
    assert!(!v["parents"].as_array().unwrap().is_empty());
    assert!(v["work"].is_number() || v["work"].is_string());
    assert!(v["timestamp_ms"].is_number());
    assert!(v["payload"].is_string());
    assert!(v["transactions"].is_array());
    assert!(v["subsidy"].is_number());

    let payload_hex = v["payload"].as_str().unwrap();
    let payload_bytes = hex::decode(payload_hex).expect("valid hex payload");
    let txs = decode_block_payload(&payload_bytes).expect("valid decoded payload");
    assert!(!txs.is_empty(), "template must contain at least coinbase");
    assert!(txs[0].is_coinbase(), "first transaction must be coinbase");
}

#[test]
fn test_mine_and_submit_block() {
    let mut app = Explorer::boot();
    let node_before = app.mesh.node("alpha").unwrap();
    let tip_before = node_before.selected_tip().unwrap();

    // 1. Fetch template
    let (status, body) = send_request(
        &mut app,
        "GET /api/mine/template HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
    );
    assert_eq!(status, 200);
    let tmpl: serde_json::Value = serde_json::from_str(&body).unwrap();

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

    // 2. Mine nonce
    let template_block = Block::new(parents.clone(), work, timestamp_ms, 0, payload_bytes);
    let mined = pow::mine(&template_block);
    let nonce = mined.nonce();
    let block_id = mined.id();

    // 3. Submit block
    let submit_json = format!(
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
    let post_req = format!(
        "POST /api/mine/submit HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        submit_json.len(),
        submit_json
    );
    let (sub_status, sub_body) = send_request(&mut app, &post_req);
    assert_eq!(sub_status, 200, "Block submit failed: {sub_body}");

    let resp: serde_json::Value = serde_json::from_str(&sub_body).unwrap();
    assert_eq!(resp["ok"], true);
    assert_eq!(resp["block"], block_id.to_hex());

    // 4. Verify DAG tips advance
    let node_after = app.mesh.node("alpha").unwrap();
    assert!(node_after.has_block(&block_id));
    let tip_after = node_after.selected_tip().unwrap();
    assert_ne!(tip_before, tip_after);
    assert_eq!(tip_after, block_id);
}

#[test]
fn test_mine_block_with_mempool_transactions() {
    let mut app = Explorer::boot();

    // Pool transfer from actor 1 to actor 2
    let to_addr = KeyPair::from_u64(2).address();
    app.mesh.pool("alpha", 1, 50 * ATOM, 2).unwrap();

    // Fetch template — should pack the mempool transaction
    let (status, body) = send_request(
        &mut app,
        "GET /api/mine/template HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
    );
    assert_eq!(status, 200);
    let tmpl: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(tmpl["transactions"].as_array().unwrap().len(), 2);
    assert!(tmpl["fees"].as_u64().unwrap() > 0);

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

    // Mine and submit
    let template_block = Block::new(parents.clone(), work, timestamp_ms, 0, payload_bytes);
    let mined = pow::mine(&template_block);
    let nonce = mined.nonce();
    let block_id = mined.id();

    let submit_json = format!(
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
    let post_req = format!(
        "POST /api/mine/submit HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        submit_json.len(),
        submit_json
    );
    let (sub_status, sub_body) = send_request(&mut app, &post_req);
    assert_eq!(sub_status, 200, "Submit failed: {sub_body}");

    // Balance of recipient should be updated
    let node = app.mesh.node("alpha").unwrap();
    assert_eq!(node.balance(&to_addr).unwrap(), (50 * ATOM) as u128);
    assert_eq!(node.pending_count(), 0);
    assert!(node.has_block(&block_id));
}

#[test]
fn test_consecutive_blocks_mining() {
    let mut app = Explorer::boot();

    for i in 1..=3 {
        let (status, body) = send_request(
            &mut app,
            "GET /api/mine/template HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
        );
        assert_eq!(status, 200, "Fetch {i} failed");
        let tmpl: serde_json::Value = serde_json::from_str(&body).unwrap();

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

        let template_block = Block::new(parents.clone(), work, timestamp_ms, 0, payload_bytes);
        let mined = pow::mine(&template_block);

        let submit_json = format!(
            "{{\"parents\":[{}],\"work\":{},\"timestamp_ms\":{},\"nonce\":{},\"payload\":\"{}\"}}",
            parents
                .iter()
                .map(|p| format!("\"{}\"", p.to_hex()))
                .collect::<Vec<_>>()
                .join(","),
            work,
            timestamp_ms,
            mined.nonce(),
            payload_hex
        );
        let post_req = format!(
            "POST /api/mine/submit HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            submit_json.len(),
            submit_json
        );
        let (sub_status, sub_body) = send_request(&mut app, &post_req);
        assert_eq!(sub_status, 200, "Submit {i} failed: {sub_body}");
    }

    let node = app.mesh.node("alpha").unwrap();
    // Genesis + 3 mined blocks = 4 blocks total
    assert_eq!(node.block_count().unwrap(), 4);
}

#[test]
fn test_mining_template_custom_miner() {
    let mut app = Explorer::boot();
    let custom_miner = KeyPair::from_u64(42).address();
    let query_req = format!(
        "GET /api/mine/template?miner={} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
        custom_miner.to_hex()
    );
    let (status, body) = send_request(&mut app, &query_req);
    assert_eq!(status, 200);

    let tmpl: serde_json::Value = serde_json::from_str(&body).unwrap();
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

    let template_block = Block::new(parents.clone(), work, timestamp_ms, 0, payload_bytes);
    let mined = pow::mine(&template_block);

    let submit_json = format!(
        "{{\"parents\":[{}],\"work\":{},\"timestamp_ms\":{},\"nonce\":{},\"payload\":\"{}\"}}",
        parents
            .iter()
            .map(|p| format!("\"{}\"", p.to_hex()))
            .collect::<Vec<_>>()
            .join(","),
        work,
        timestamp_ms,
        mined.nonce(),
        payload_hex
    );
    let post_req = format!(
        "POST /api/mine/submit HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        submit_json.len(),
        submit_json
    );
    let (sub_status, sub_body) = send_request(&mut app, &post_req);
    assert_eq!(sub_status, 200, "Submit custom miner failed: {sub_body}");

    let node = app.mesh.node("alpha").unwrap();
    assert!(node.balance(&custom_miner).unwrap() > 0);
}

#[test]
fn test_negative_cases() {
    let mut app = Explorer::boot();

    // 1. Invalid JSON body
    let bad_json = "POST /api/mine/submit HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: 10\r\n\r\n{invalid}}";
    let (status, body) = send_request(&mut app, bad_json);
    assert_eq!(status, 400);
    assert!(body.contains("\"ok\":false"));

    // 2. Missing parents
    let no_parents = "POST /api/mine/submit HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: 35\r\n\r\n{\"work\":1,\"nonce\":0,\"payload\":\"00\"}";
    let (status, body) = send_request(&mut app, no_parents);
    assert_eq!(status, 400);
    assert!(body.contains("\"ok\":false"));

    // 3. Missing payload
    let no_payload = "POST /api/mine/submit HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: 45\r\n\r\n{\"parents\":[\"00\"],\"work\":1,\"timestamp_ms\":100}";
    let (status, body) = send_request(&mut app, no_payload);
    assert_eq!(status, 400);
    assert!(body.contains("\"ok\":false"));

    // 4. Invalid hex in parents
    let bad_hex_parent = "POST /api/mine/submit HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: 65\r\n\r\n{\"parents\":[\"not_a_hex\"],\"work\":1,\"timestamp_ms\":100,\"nonce\":0,\"payload\":\"00\"}";
    let (status, body) = send_request(&mut app, bad_hex_parent);
    assert_eq!(status, 400);
    assert!(body.contains("\"ok\":false"));

    // 5. Parent block ID not in DAG
    let fake_parent = BlockId::from_bytes([99u8; 32]).to_hex();
    let unknown_parent = format!(
        "POST /api/mine/submit HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{{\"parents\":[\"{fake_parent}\"],\"work\":1,\"timestamp_ms\":100,\"nonce\":0,\"payload\":\"0000000000000000\"}}",
        110 + fake_parent.len()
    );
    let (status, body) = send_request(&mut app, &unknown_parent);
    assert_eq!(status, 400);
    assert!(body.contains("\"ok\":false"));

    // 6. Invalid PoW nonce when PoW is enforced
    let node = app.mesh.node_mut("alpha").unwrap();
    node.set_proof_of_work(true).unwrap();

    let (tmpl_status, tmpl_body) = send_request(
        &mut app,
        "GET /api/mine/template HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
    );
    assert_eq!(tmpl_status, 200);
    let tmpl: serde_json::Value = serde_json::from_str(&tmpl_body).unwrap();
    let parents: Vec<String> = tmpl["parents"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p.as_str().unwrap().to_string())
        .collect();
    let payload_hex = tmpl["payload"].as_str().unwrap();

    // High work target to make arbitrary nonce invalid
    let hard_work = 1_000_000_000_000u128;
    let bad_pow_json = format!(
        "{{\"parents\":[{}],\"work\":{},\"timestamp_ms\":{},\"nonce\":0,\"payload\":\"{}\"}}",
        parents
            .iter()
            .map(|p| format!("\"{}\"", p))
            .collect::<Vec<_>>()
            .join(","),
        hard_work,
        tmpl["timestamp_ms"].as_u64().unwrap(),
        payload_hex
    );
    let bad_pow_req = format!(
        "POST /api/mine/submit HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        bad_pow_json.len(),
        bad_pow_json
    );
    let (status, body) = send_request(&mut app, &bad_pow_req);
    assert_eq!(status, 400);
    assert!(body.contains("\"ok\":false"));
}

#[test]
fn test_idempotent_block_submission() {
    let mut app = Explorer::boot();
    let (_, body) = send_request(
        &mut app,
        "GET /api/mine/template HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
    );
    let tmpl: serde_json::Value = serde_json::from_str(&body).unwrap();

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

    let template_block = Block::new(parents.clone(), work, timestamp_ms, 0, payload_bytes);
    let mined = pow::mine(&template_block);
    let nonce = mined.nonce();
    let block_id = mined.id();

    let submit_json = format!(
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
    let post_req = format!(
        "POST /api/mine/submit HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        submit_json.len(),
        submit_json
    );

    // First submission
    let (status1, body1) = send_request(&mut app, &post_req);
    assert_eq!(status1, 200);
    assert!(body1.contains(&block_id.to_hex()));

    // Second submission of the same block (idempotency)
    let (status2, body2) = send_request(&mut app, &post_req);
    assert_eq!(status2, 200);
    assert!(body2.contains(&block_id.to_hex()));
}
