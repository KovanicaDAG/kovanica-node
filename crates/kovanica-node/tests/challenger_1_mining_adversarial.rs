//! Adversarial and Empirical Stress Test Suite for External Mining Endpoints.
//!
//! Authored by: Challenger 1 (critic / empirical specialist)
//!
//! Objectives Tested:
//! 1. Malformed JSON inputs (empty body, bad syntax, missing fields, wrong types).
//! 2. Invalid parent IDs (non-hex, odd hex, non-32-byte, nonexistent parents, non-string elements).
//! 3. Corrupted binary payloads and bad hex strings (truncated bincode, bad hex, non-string, garbage).
//! 4. Invalid work values, nonce types, and timestamp drift boundaries (past, future >2h, u64::MAX).
//! 5. Robust error handling (HTTP 400 with descriptive error messages, HTTP 200 on valid inputs without server panic/crash).
//! 6. Template query parameter edge cases (valid/invalid nodes, valid/invalid custom miner addresses).
//! 7. Randomized fuzz burst robustness and state isolation.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::{SystemTime, UNIX_EPOCH};

use kovanica_dag::{pow, Block, BlockId};
use kovanica_node::explorer::{handle, Explorer};
use kovanica_state::KeyPair;

const MAX_FUTURE_DRIFT_MS: u64 = 2 * 60 * 60 * 1000; // 2 hours

/// Helper to execute an HTTP request through `Explorer::handle` over local TCP.
fn send_raw_http(app: &mut Explorer, req_bytes: &[u8]) -> (u16, String, serde_json::Value) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");
    let mut client = TcpStream::connect(addr).expect("connect client");
    let (server_stream, _) = listener.accept().expect("accept server");

    client.write_all(req_bytes).expect("write request");
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

/// Helper to fetch template and parse components
fn fetch_template(app: &mut Explorer, query: &str) -> (u16, String, serde_json::Value) {
    let req = format!("GET /api/mine/template{query} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
    send_raw_http(app, req.as_bytes())
}

/// Helper to mine a valid candidate from template json
fn mine_from_template(tmpl: &serde_json::Value) -> (Vec<BlockId>, u128, u64, u64, String, BlockId) {
    let parents: Vec<BlockId> = tmpl["parents"]
        .as_array()
        .expect("parents array")
        .iter()
        .map(|p| {
            let hex_str = p.as_str().expect("parent hex string");
            let b = hex::decode(hex_str).expect("valid hex");
            BlockId::from_bytes(b.try_into().expect("32 bytes"))
        })
        .collect();

    let work = tmpl["work"].as_u64().expect("work number") as u128;
    let timestamp_ms = tmpl["timestamp_ms"].as_u64().expect("timestamp_ms number");
    let payload_hex = tmpl["payload"].as_str().expect("payload hex").to_string();
    let payload_bytes = hex::decode(&payload_hex).expect("valid hex payload");

    let template_block = Block::new(parents.clone(), work, timestamp_ms, 0, payload_bytes);
    let mined = pow::mine(&template_block);
    (
        parents,
        work,
        timestamp_ms,
        mined.nonce(),
        payload_hex,
        mined.id(),
    )
}

// ============================================================================
// 1. MALFORMED JSON INPUTS & MISSING FIELDS
// ============================================================================

#[test]
fn test_adversarial_malformed_json_syntax_and_structures() {
    let mut app = Explorer::boot();

    let syntax_cases = [
        ("empty body with Content-Length: 0", ""),
        ("whitespace only body", "   \t\r\n   "),
        ("truncated object opening", "{\"parents\":"),
        ("truncated array in object", "{\"parents\": [\"0000000000000000000000000000000000000000000000000000000000000000\""),
        ("unquoted object keys", "{parents: [\"00\"], work: 1}"),
        ("single quoted json string", "{'parents': ['00'], 'work': 1}"),
        ("trailing comma in fields", "{\"work\": 1, \"nonce\": 0,}"),
        ("double colon in key-value", "{\"work\":: 1}"),
        ("unclosed string literal", "{\"parents\": [\"0000000000000000000000000000000000000000000000000000000000000000], \"work\": 1}"),
        ("raw javascript NaN", "{\"work\": NaN}"),
        ("raw javascript Infinity", "{\"work\": Infinity}"),
        ("json array at root", "[1, 2, 3]"),
        ("json string at root", "\"a plain string\""),
        ("json number at root", "987654321"),
        ("json boolean true at root", "true"),
        ("json boolean false at root", "false"),
        ("json null at root", "null"),
        ("deeply nested array garbage", "[[[[[[[[[[[[[[[[{\"work\": 1}]]]]]]]]]]]]]]]]"),
    ];

    for (name, body) in syntax_cases {
        let req = format!(
            "POST /api/mine/submit HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        let (status, resp_body, json) = send_raw_http(&mut app, req.as_bytes());
        assert_eq!(
            status, 400,
            "Malformed syntax case '{name}' must return HTTP 400, got {status}. Response: {resp_body}"
        );
        assert_eq!(
            json["ok"], false,
            "Malformed syntax case '{name}' must return ok: false JSON"
        );
        assert!(
            json["error"].is_string() && !json["error"].as_str().unwrap().is_empty(),
            "Malformed syntax case '{name}' must return descriptive error message in JSON: {resp_body}"
        );
    }
}

#[test]
fn test_adversarial_missing_and_null_field_permutations() {
    let mut app = Explorer::boot();

    let valid_parent = "0000000000000000000000000000000000000000000000000000000000000000";
    let valid_payload = "00";

    let missing_field_cases: Vec<(&str, String)> = vec![
        ("empty object {}", "{}".to_string()),
        ("missing parents", format!("{{\"work\":1,\"timestamp_ms\":1000,\"nonce\":0,\"payload\":\"{valid_payload}\"}}")),
        ("parents is null", format!("{{\"parents\":null,\"work\":1,\"timestamp_ms\":1000,\"nonce\":0,\"payload\":\"{valid_payload}\"}}")),
        ("missing work", format!("{{\"parents\":[\"{valid_parent}\"],\"timestamp_ms\":1000,\"nonce\":0,\"payload\":\"{valid_payload}\"}}")),
        ("work is null", format!("{{\"parents\":[\"{valid_parent}\"],\"work\":null,\"timestamp_ms\":1000,\"nonce\":0,\"payload\":\"{valid_payload}\"}}")),
        ("missing timestamp_ms", format!("{{\"parents\":[\"{valid_parent}\"],\"work\":1,\"nonce\":0,\"payload\":\"{valid_payload}\"}}")),
        ("timestamp_ms is null", format!("{{\"parents\":[\"{valid_parent}\"],\"work\":1,\"timestamp_ms\":null,\"nonce\":0,\"payload\":\"{valid_payload}\"}}")),
        ("missing nonce", format!("{{\"parents\":[\"{valid_parent}\"],\"work\":1,\"timestamp_ms\":1000,\"payload\":\"{valid_payload}\"}}")),
        ("nonce is null", format!("{{\"parents\":[\"{valid_parent}\"],\"work\":1,\"timestamp_ms\":1000,\"nonce\":null,\"payload\":\"{valid_payload}\"}}")),
        ("missing payload", format!("{{\"parents\":[\"{valid_parent}\"],\"work\":1,\"timestamp_ms\":1000,\"nonce\":0}}")),
        ("payload is null", format!("{{\"parents\":[\"{valid_parent}\"],\"work\":1,\"timestamp_ms\":1000,\"nonce\":0,\"payload\":null}}")),
    ];

    for (name, body) in missing_field_cases {
        let req = format!(
            "POST /api/mine/submit HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        let (status, resp_body, json) = send_raw_http(&mut app, req.as_bytes());
        assert_eq!(
            status, 400,
            "Missing field case '{name}' must return HTTP 400, got {status}. Body: {resp_body}"
        );
        assert_eq!(json["ok"], false);
        assert!(
            json["error"].is_string() && !json["error"].as_str().unwrap().is_empty(),
            "Missing field case '{name}' must return descriptive error message in JSON: {resp_body}"
        );
    }
}

// ============================================================================
// 2. INVALID PARENT IDS
// ============================================================================

#[test]
fn test_adversarial_invalid_parent_ids() {
    let mut app = Explorer::boot();

    let invalid_parent_cases = [
        ("empty parents array", "{\"parents\":[],\"work\":1,\"timestamp_ms\":1000,\"nonce\":0,\"payload\":\"00\"}"),
        ("parents as string", "{\"parents\":\"0000000000000000000000000000000000000000000000000000000000000000\",\"work\":1,\"timestamp_ms\":1000,\"nonce\":0,\"payload\":\"00\"}"),
        ("parents as integer", "{\"parents\":12345,\"work\":1,\"timestamp_ms\":1000,\"nonce\":0,\"payload\":\"00\"}"),
        ("parents as boolean", "{\"parents\":true,\"work\":1,\"timestamp_ms\":1000,\"nonce\":0,\"payload\":\"00\"}"),
        ("parents array containing integer", "{\"parents\":[12345],\"work\":1,\"timestamp_ms\":1000,\"nonce\":0,\"payload\":\"00\"}"),
        ("parents array containing null", "{\"parents\":[null],\"work\":1,\"timestamp_ms\":1000,\"nonce\":0,\"payload\":\"00\"}"),
        ("parents array containing object", "{\"parents\":[{\"id\":\"00\"}],\"work\":1,\"timestamp_ms\":1000,\"nonce\":0,\"payload\":\"00\"}"),
        ("parents array containing boolean", "{\"parents\":[true],\"work\":1,\"timestamp_ms\":1000,\"nonce\":0,\"payload\":\"00\"}"),
        ("non-hex characters in parent", "{\"parents\":[\"not_a_valid_hex_block_id_string_here_12345\"],\"work\":1,\"timestamp_ms\":1000,\"nonce\":0,\"payload\":\"00\"}"),
        ("parent hex with 0x prefix", "{\"parents\":[\"0x0000000000000000000000000000000000000000000000000000000000000000\"],\"work\":1,\"timestamp_ms\":1000,\"nonce\":0,\"payload\":\"00\"}"),
        ("odd length hex in parent (3 chars)", "{\"parents\":[\"abc\"],\"work\":1,\"timestamp_ms\":1000,\"nonce\":0,\"payload\":\"00\"}"),
        ("odd length hex in parent (63 chars)", "{\"parents\":[\"000000000000000000000000000000000000000000000000000000000000000\"],\"work\":1,\"timestamp_ms\":1000,\"nonce\":0,\"payload\":\"00\"}"),
        ("short parent (1 byte / 2 chars)", "{\"parents\":[\"00\"],\"work\":1,\"timestamp_ms\":1000,\"nonce\":0,\"payload\":\"00\"}"),
        ("short parent (16 bytes / 32 chars)", "{\"parents\":[\"00000000000000000000000000000000\"],\"work\":1,\"timestamp_ms\":1000,\"nonce\":0,\"payload\":\"00\"}"),
        ("long parent (33 bytes / 66 chars)", "{\"parents\":[\"000000000000000000000000000000000000000000000000000000000000000000\"],\"work\":1,\"timestamp_ms\":1000,\"nonce\":0,\"payload\":\"00\"}"),
        ("empty parent string \"\"", "{\"parents\":[\"\"],\"work\":1,\"timestamp_ms\":1000,\"nonce\":0,\"payload\":\"00\"}"),
    ];

    for (name, body) in invalid_parent_cases {
        let req = format!(
            "POST /api/mine/submit HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        let (status, resp_body, json) = send_raw_http(&mut app, req.as_bytes());
        assert_eq!(
            status, 400,
            "Invalid parent case '{name}' must return HTTP 400, got {status}. Response: {resp_body}"
        );
        assert_eq!(json["ok"], false);
        assert!(
            json["error"].is_string() && !json["error"].as_str().unwrap().is_empty(),
            "Invalid parent case '{name}' must include descriptive error message: {resp_body}"
        );
    }
}

#[test]
fn test_adversarial_nonexistent_parent_id_rejection() {
    let mut app = Explorer::boot();
    let tmpl_res = fetch_template(&mut app, "");
    assert_eq!(tmpl_res.0, 200);
    let tmpl = tmpl_res.2;
    let (_, work, ts, _, payload_hex, _) = mine_from_template(&tmpl);

    // 1. Completely fabricated 32-byte parent ID
    let nonexistent_parent = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
    let body = format!(
        "{{\"parents\":[\"{nonexistent_parent}\"],\"work\":{work},\"timestamp_ms\":{ts},\"nonce\":0,\"payload\":\"{payload_hex}\"}}"
    );
    let req = format!(
        "POST /api/mine/submit HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let (status, resp_body, json) = send_raw_http(&mut app, req.as_bytes());
    assert_eq!(
        status, 400,
        "Nonexistent parent must return HTTP 400: {resp_body}"
    );
    assert_eq!(json["ok"], false);
    assert!(
        resp_body.contains("missing parent")
            || resp_body.contains("unknown parent")
            || resp_body.contains("MissingParent")
            || resp_body.contains("parent")
    );

    // 2. Multi-parent where one parent is valid tip and another is fabricated
    let valid_tip_hex = tmpl["parents"][0].as_str().unwrap();
    let mixed_body = format!(
        "{{\"parents\":[\"{valid_tip_hex}\",\"{nonexistent_parent}\"],\"work\":{work},\"timestamp_ms\":{ts},\"nonce\":0,\"payload\":\"{payload_hex}\"}}"
    );
    let mixed_req = format!(
        "POST /api/mine/submit HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        mixed_body.len(),
        mixed_body
    );
    let (mixed_status, mixed_resp, mixed_json) = send_raw_http(&mut app, mixed_req.as_bytes());
    assert_eq!(
        mixed_status, 400,
        "Mixed valid/nonexistent parents must return HTTP 400: {mixed_resp}"
    );
    assert_eq!(mixed_json["ok"], false);
}

// ============================================================================
// 3. CORRUPTED BINARY PAYLOADS & BAD HEX STRINGS
// ============================================================================

#[test]
fn test_adversarial_corrupted_payload_and_bad_hex() {
    let mut app = Explorer::boot();
    let tmpl_res = fetch_template(&mut app, "");
    assert_eq!(tmpl_res.0, 200);
    let tmpl = tmpl_res.2;
    let parent_hex = tmpl["parents"][0].as_str().unwrap();
    let work = tmpl["work"].as_u64().unwrap();
    let ts = tmpl["timestamp_ms"].as_u64().unwrap();

    let corrupted_payload_cases = [
        // Type mismatches
        ("payload is number", format!("{{\"parents\":[\"{parent_hex}\"],\"work\":{work},\"timestamp_ms\":{ts},\"nonce\":0,\"payload\":12345}}")),
        ("payload is boolean", format!("{{\"parents\":[\"{parent_hex}\"],\"work\":{work},\"timestamp_ms\":{ts},\"nonce\":0,\"payload\":true}}")),
        ("payload is array", format!("{{\"parents\":[\"{parent_hex}\"],\"work\":{work},\"timestamp_ms\":{ts},\"nonce\":0,\"payload\":[\"00\"]}}")),
        ("payload is object", format!("{{\"parents\":[\"{parent_hex}\"],\"work\":{work},\"timestamp_ms\":{ts},\"nonce\":0,\"payload\":{{\"txs\":[]}}}}")),
        // Hex syntax errors
        ("payload non-hex chars", format!("{{\"parents\":[\"{parent_hex}\"],\"work\":{work},\"timestamp_ms\":{ts},\"nonce\":0,\"payload\":\"non_hex_payload_string\"}}")),
        ("payload odd-length hex (3 chars)", format!("{{\"parents\":[\"{parent_hex}\"],\"work\":{work},\"timestamp_ms\":{ts},\"nonce\":0,\"payload\":\"abc\"}}")),
        ("payload with 0x prefix", format!("{{\"parents\":[\"{parent_hex}\"],\"work\":{work},\"timestamp_ms\":{ts},\"nonce\":0,\"payload\":\"0x0000\"}}")),
        ("payload empty hex string", format!("{{\"parents\":[\"{parent_hex}\"],\"work\":{work},\"timestamp_ms\":{ts},\"nonce\":0,\"payload\":\"\"}}")),
        // Corrupted binary payloads (undecodable / malformed bincode)
        ("payload truncated 1 byte", format!("{{\"parents\":[\"{parent_hex}\"],\"work\":{work},\"timestamp_ms\":{ts},\"nonce\":0,\"payload\":\"00\"}}")),
        ("payload truncated 2 bytes", format!("{{\"parents\":[\"{parent_hex}\"],\"work\":{work},\"timestamp_ms\":{ts},\"nonce\":0,\"payload\":\"0000\"}}")),
        ("payload truncated 3 bytes", format!("{{\"parents\":[\"{parent_hex}\"],\"work\":{work},\"timestamp_ms\":{ts},\"nonce\":0,\"payload\":\"000000\"}}")),
        ("payload invalid tx count u32::MAX", format!("{{\"parents\":[\"{parent_hex}\"],\"work\":{work},\"timestamp_ms\":{ts},\"nonce\":0,\"payload\":\"ffffffff\"}}")),
        ("payload tx count 1 with zero body bytes", format!("{{\"parents\":[\"{parent_hex}\"],\"work\":{work},\"timestamp_ms\":{ts},\"nonce\":0,\"payload\":\"01000000\"}}")),
        ("payload random junk bytes", format!("{{\"parents\":[\"{parent_hex}\"],\"work\":{work},\"timestamp_ms\":{ts},\"nonce\":0,\"payload\":\"cafebabe0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\"}}")),
    ];

    for (name, body) in corrupted_payload_cases {
        let req = format!(
            "POST /api/mine/submit HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        let (status, resp_body, json) = send_raw_http(&mut app, req.as_bytes());
        assert_eq!(
            status, 400,
            "Corrupted payload case '{name}' must return HTTP 400, got {status}. Response: {resp_body}"
        );
        assert_eq!(json["ok"], false);
        assert!(
            json["error"].is_string() && !json["error"].as_str().unwrap().is_empty(),
            "Corrupted payload case '{name}' must include descriptive error message: {resp_body}"
        );
    }
}

// ============================================================================
// 4. INVALID WORK VALUES, NONCE TYPES, AND TIMESTAMP DRIFT
// ============================================================================

#[test]
fn test_adversarial_work_and_nonce_types() {
    let mut app = Explorer::boot();
    let tmpl_res = fetch_template(&mut app, "");
    assert_eq!(tmpl_res.0, 200);
    let tmpl = tmpl_res.2;
    let parent_hex = tmpl["parents"][0].as_str().unwrap();
    let ts = tmpl["timestamp_ms"].as_u64().unwrap();
    let payload_hex = tmpl["payload"].as_str().unwrap();

    let invalid_work_cases = [
        ("work is boolean", format!("{{\"parents\":[\"{parent_hex}\"],\"work\":true,\"timestamp_ms\":{ts},\"nonce\":0,\"payload\":\"{payload_hex}\"}}")),
        ("work is array", format!("{{\"parents\":[\"{parent_hex}\"],\"work\":[1,2],\"timestamp_ms\":{ts},\"nonce\":0,\"payload\":\"{payload_hex}\"}}")),
        ("work is object", format!("{{\"parents\":[\"{parent_hex}\"],\"work\":{{\"val\":1}},\"timestamp_ms\":{ts},\"nonce\":0,\"payload\":\"{payload_hex}\"}}")),
        ("work is non-numeric string", format!("{{\"parents\":[\"{parent_hex}\"],\"work\":\"extreme\",\"timestamp_ms\":{ts},\"nonce\":0,\"payload\":\"{payload_hex}\"}}")),
        ("work is negative string", format!("{{\"parents\":[\"{parent_hex}\"],\"work\":\"-10\",\"timestamp_ms\":{ts},\"nonce\":0,\"payload\":\"{payload_hex}\"}}")),
        ("work is float string", format!("{{\"parents\":[\"{parent_hex}\"],\"work\":\"10.5\",\"timestamp_ms\":{ts},\"nonce\":0,\"payload\":\"{payload_hex}\"}}")),
    ];

    for (name, body) in invalid_work_cases {
        let req = format!(
            "POST /api/mine/submit HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        let (status, resp_body, json) = send_raw_http(&mut app, req.as_bytes());
        assert_eq!(
            status, 400,
            "Invalid work case '{name}' must return HTTP 400, got {status}. Response: {resp_body}"
        );
        assert_eq!(json["ok"], false);
    }

    let invalid_nonce_cases = [
        ("nonce is boolean", format!("{{\"parents\":[\"{parent_hex}\"],\"work\":1,\"timestamp_ms\":{ts},\"nonce\":true,\"payload\":\"{payload_hex}\"}}")),
        ("nonce is array", format!("{{\"parents\":[\"{parent_hex}\"],\"work\":1,\"timestamp_ms\":{ts},\"nonce\":[0],\"payload\":\"{payload_hex}\"}}")),
        ("nonce is object", format!("{{\"parents\":[\"{parent_hex}\"],\"work\":1,\"timestamp_ms\":{ts},\"nonce\":{{\"n\":0}},\"payload\":\"{payload_hex}\"}}")),
        ("nonce is non-numeric string", format!("{{\"parents\":[\"{parent_hex}\"],\"work\":1,\"timestamp_ms\":{ts},\"nonce\":\"random_nonce\",\"payload\":\"{payload_hex}\"}}")),
        ("nonce is negative string", format!("{{\"parents\":[\"{parent_hex}\"],\"work\":1,\"timestamp_ms\":{ts},\"nonce\":\"-1\",\"payload\":\"{payload_hex}\"}}")),
        ("nonce is float string", format!("{{\"parents\":[\"{parent_hex}\"],\"work\":1,\"timestamp_ms\":{ts},\"nonce\":\"100.5\",\"payload\":\"{payload_hex}\"}}")),
    ];

    for (name, body) in invalid_nonce_cases {
        let req = format!(
            "POST /api/mine/submit HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        let (status, resp_body, json) = send_raw_http(&mut app, req.as_bytes());
        assert_eq!(
            status, 400,
            "Invalid nonce case '{name}' must return HTTP 400, got {status}. Response: {resp_body}"
        );
        assert_eq!(json["ok"], false);
    }
}

#[test]
fn test_adversarial_timestamp_drift_and_coercion() {
    let mut app = Explorer::boot();
    let tmpl_res = fetch_template(&mut app, "");
    assert_eq!(tmpl_res.0, 200);
    let tmpl = tmpl_res.2;
    let parent_hex = tmpl["parents"][0].as_str().unwrap();
    let parent_id = BlockId::from_bytes(hex::decode(parent_hex).unwrap().try_into().unwrap());
    let work = tmpl["work"].as_u64().unwrap() as u128;
    let payload_hex = tmpl["payload"].as_str().unwrap();
    let payload_bytes = hex::decode(payload_hex).unwrap();

    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    // 1. Invalid timestamp types
    let invalid_ts_cases = [
        ("timestamp is boolean", format!("{{\"parents\":[\"{parent_hex}\"],\"work\":1,\"timestamp_ms\":true,\"nonce\":0,\"payload\":\"{payload_hex}\"}}")),
        ("timestamp is array", format!("{{\"parents\":[\"{parent_hex}\"],\"work\":1,\"timestamp_ms\":[100],\"nonce\":0,\"payload\":\"{payload_hex}\"}}")),
        ("timestamp is object", format!("{{\"parents\":[\"{parent_hex}\"],\"work\":1,\"timestamp_ms\":{{\"t\":100}},\"nonce\":0,\"payload\":\"{payload_hex}\"}}")),
        ("timestamp is non-numeric string", format!("{{\"parents\":[\"{parent_hex}\"],\"work\":1,\"timestamp_ms\":\"invalid_time\",\"nonce\":0,\"payload\":\"{payload_hex}\"}}")),
        ("timestamp is negative string", format!("{{\"parents\":[\"{parent_hex}\"],\"work\":1,\"timestamp_ms\":\"-1000\",\"nonce\":0,\"payload\":\"{payload_hex}\"}}")),
    ];

    for (name, body) in invalid_ts_cases {
        let req = format!(
            "POST /api/mine/submit HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        let (status, resp_body, json) = send_raw_http(&mut app, req.as_bytes());
        assert_eq!(
            status, 400,
            "Invalid timestamp case '{name}' must return HTTP 400, got {status}. Response: {resp_body}"
        );
        assert_eq!(json["ok"], false);
    }

    // 2. Extreme future timestamp (> 2 hours wall-clock drift)
    let drift_too_far = now_ms + MAX_FUTURE_DRIFT_MS + 120_000; // 2 hours + 2 min
    let block_too_far = Block::new(
        vec![parent_id],
        work,
        drift_too_far,
        0,
        payload_bytes.clone(),
    );
    let mined_too_far = pow::mine(&block_too_far);
    let far_body = format!(
        "{{\"parents\":[\"{parent_hex}\"],\"work\":{work},\"timestamp_ms\":{drift_too_far},\"nonce\":{},\"payload\":\"{payload_hex}\"}}",
        mined_too_far.nonce()
    );
    let far_req = format!(
        "POST /api/mine/submit HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        far_body.len(),
        far_body
    );
    let (far_status, far_resp, far_json) = send_raw_http(&mut app, far_req.as_bytes());
    assert_eq!(
        far_status, 400,
        "Future drift > 2h must be rejected with HTTP 400: {far_resp}"
    );
    assert_eq!(far_json["ok"], false);
    assert!(
        far_resp.contains("more than 2h ahead of local clock")
            || far_resp.contains("drift")
            || far_resp.contains("clock")
            || far_json["error"].is_string()
    );

    // 3. Timestamp u64::MAX
    let max_body = format!(
        "{{\"parents\":[\"{parent_hex}\"],\"work\":{work},\"timestamp_ms\":{},\"nonce\":0,\"payload\":\"{payload_hex}\"}}",
        u64::MAX
    );
    let max_req = format!(
        "POST /api/mine/submit HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        max_body.len(),
        max_body
    );
    let (max_status, max_resp, max_json) = send_raw_http(&mut app, max_req.as_bytes());
    assert_eq!(
        max_status, 400,
        "Timestamp u64::MAX must return HTTP 400: {max_resp}"
    );
    assert_eq!(max_json["ok"], false);

    // 4. Valid future timestamp within 2h limit (now + 30 min)
    let valid_future_ts = now_ms + (30 * 60 * 1000);
    let block_valid_future = Block::new(
        vec![parent_id],
        work,
        valid_future_ts,
        0,
        payload_bytes.clone(),
    );
    let mined_valid = pow::mine(&block_valid_future);
    let valid_future_body = format!(
        "{{\"parents\":[\"{parent_hex}\"],\"work\":{work},\"timestamp_ms\":{valid_future_ts},\"nonce\":{},\"payload\":\"{payload_hex}\"}}",
        mined_valid.nonce()
    );
    let valid_future_req = format!(
        "POST /api/mine/submit HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        valid_future_body.len(),
        valid_future_body
    );
    let (vf_status, vf_resp, vf_json) = send_raw_http(&mut app, valid_future_req.as_bytes());
    assert_eq!(
        vf_status, 200,
        "Valid timestamp within 2h should succeed: {vf_resp}"
    );
    assert_eq!(vf_json["ok"], true);
    assert_eq!(vf_json["block"], mined_valid.id().to_hex());
}

// ============================================================================
// 5. GET /api/mine/template ADVERSARIAL QUERY TESTING
// ============================================================================

#[test]
fn test_adversarial_template_endpoint_queries() {
    let mut app = Explorer::boot();

    // 1. Unknown node queries
    let unknown_nodes = [
        "ghost",
        "nonexistent",
        "node_999",
        "alpha-invalid",
        "%20",
        "null",
    ];
    for node in unknown_nodes {
        let (status, resp_body, json) = fetch_template(&mut app, &format!("?node={node}"));
        assert_eq!(
            status, 400,
            "Query for unknown node '{node}' must return HTTP 400: {resp_body}"
        );
        assert_eq!(json["ok"], false);
        assert!(
            resp_body.contains("unknown node") || json["error"].is_string(),
            "Unknown node '{node}' error message expected: {resp_body}"
        );
    }

    // 2. Valid nodes (alpha, beta, gamma)
    for valid_node in ["alpha", "beta", "gamma"] {
        let (status, resp_body, json) = fetch_template(&mut app, &format!("?node={valid_node}"));
        assert_eq!(
            status, 200,
            "Valid node '{valid_node}' template failed: {resp_body}"
        );
        assert_eq!(json["ok"], true);
        assert!(json["parents"].is_array() && !json["parents"].as_array().unwrap().is_empty());
        assert!(json["work"].is_number() || json["work"].is_string());
        assert!(json["timestamp_ms"].is_number());
        assert!(json["payload"].is_string());
        assert!(json["transactions"].is_array());
    }

    // 3. Custom miner address testing
    let custom_key = KeyPair::from_u64(888);
    let custom_hex = custom_key.address().to_hex();

    // 3a. Valid custom miner address
    let (m_status, m_body, m_json) = fetch_template(&mut app, &format!("?miner={custom_hex}"));
    assert_eq!(
        m_status, 200,
        "Valid custom miner address query failed: {m_body}"
    );
    assert_eq!(m_json["ok"], true);
    assert_eq!(m_json["miner"], custom_hex);

    // 3b. Invalid / malformed custom miner addresses should fall back to default node miner without crash
    let bad_miners = ["invalid_hex", "12345", "00", "not_a_key", ""];
    for bad_m in bad_miners {
        let (b_status, b_body, b_json) = fetch_template(&mut app, &format!("?miner={bad_m}"));
        assert_eq!(
            b_status, 200,
            "Malformed miner '{bad_m}' should fall back gracefully: {b_body}"
        );
        assert_eq!(b_json["ok"], true);
    }
}

// ============================================================================
// 6. SERVER RESILIENCE, FUZZ BURSTS & STATE INTEGRITY
// ============================================================================

#[test]
fn test_fuzz_burst_and_server_stability() {
    let mut app = Explorer::boot();

    let founder = KeyPair::from_u64(1).address();
    let initial_bal = app.mesh.node("alpha").unwrap().balance(&founder).unwrap();
    let initial_tip = app.mesh.node("alpha").unwrap().selected_tip().unwrap();
    let initial_count = app.mesh.node("alpha").unwrap().block_count().unwrap();

    // 100 randomized garbage bursts against both endpoints
    let mut rng_seed = 0x12345678u64;
    for i in 0..100 {
        // Simple deterministic PRNG
        rng_seed = rng_seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let garbage_len = (rng_seed % 500) as usize + 1;
        let mut garbage_bytes = vec![0u8; garbage_len];
        for b in &mut garbage_bytes {
            rng_seed = rng_seed
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            *b = (rng_seed >> 32) as u8;
        }

        let is_post = (rng_seed % 2) == 0;
        let req_bytes = if is_post {
            let body_str = String::from_utf8_lossy(&garbage_bytes);
            format!(
                "POST /api/mine/submit HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                body_str.len(),
                body_str
            ).into_bytes()
        } else {
            let query_str = String::from_utf8_lossy(&garbage_bytes[..garbage_len.min(50)]);
            format!(
                "GET /api/mine/template?node={} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
                query_str
            )
            .into_bytes()
        };

        let (status, resp_body, _) = send_raw_http(&mut app, &req_bytes);
        // All random garbage requests must return an error code (400 or 404), never 200 or 500
        assert!(
            status == 400 || status == 404,
            "Garbage burst iteration {i} returned unexpected status {status}: {resp_body}"
        );
    }

    // Node state must be completely unperturbed
    let node_check = app.mesh.node("alpha").unwrap();
    assert_eq!(node_check.balance(&founder).unwrap(), initial_bal);
    assert_eq!(node_check.selected_tip().unwrap(), initial_tip);
    assert_eq!(node_check.block_count().unwrap(), initial_count);

    // Follow up with genuine template + mine + submit to prove the pipeline is fully functional
    let (t_status, _, tmpl) = fetch_template(&mut app, "");
    assert_eq!(t_status, 200);
    let (parents, work, ts, nonce, payload_hex, mined_id) = mine_from_template(&tmpl);

    let submit_body = format!(
        "{{\"parents\":[{}],\"work\":{work},\"timestamp_ms\":{ts},\"nonce\":{nonce},\"payload\":\"{payload_hex}\"}}",
        parents.iter().map(|p| format!("\"{}\"", p.to_hex())).collect::<Vec<_>>().join(",")
    );
    let submit_req = format!(
        "POST /api/mine/submit HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        submit_body.len(),
        submit_body
    );

    let (s_status, s_body, s_json) = send_raw_http(&mut app, submit_req.as_bytes());
    assert_eq!(s_status, 200, "Submit after fuzz bursts failed: {s_body}");
    assert_eq!(s_json["ok"], true);
    assert_eq!(s_json["block"], mined_id.to_hex());

    let node_final = app.mesh.node("alpha").unwrap();
    assert_eq!(node_final.selected_tip().unwrap(), mined_id);
    assert_eq!(node_final.block_count().unwrap(), initial_count + 1);
}
