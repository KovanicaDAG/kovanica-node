use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use kovanica_dag::{pow, Block, BlockId};
use kovanica_node::explorer::{handle, Explorer};
use kovanica_state::KeyPair;

const MAX_FUTURE_DRIFT_MS: u64 = 2 * 60 * 60 * 1000; // 2 hours

fn send_request_raw(app: &mut Explorer, req_bytes: &[u8]) -> (u16, String) {
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
    (status, body)
}

fn send_request_slow_body(
    app: &mut Explorer,
    headers: &[u8],
    body_bytes: &[u8],
    chunk_size: usize,
    delay_ms: u64,
) -> (u16, String) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");

    let server_handle = thread::spawn(move || {
        let (server_stream, _) = listener.accept().expect("accept server");
        server_stream
    });

    let mut client = TcpStream::connect(addr).expect("connect client");
    let server_stream = server_handle.join().expect("join server");

    let headers_vec = headers.to_vec();
    let body_vec = body_bytes.to_vec();

    let client_handle = thread::spawn(move || {
        // Send headers first
        let _ = client.write_all(&headers_vec);
        let _ = client.flush();

        // Send body slowly in small chunks
        for chunk in body_vec.chunks(chunk_size) {
            let _ = client.write_all(chunk);
            let _ = client.flush();
            if delay_ms > 0 {
                thread::sleep(Duration::from_millis(delay_ms));
            }
        }
        let _ = client.shutdown(std::net::Shutdown::Write);
        let mut resp = Vec::new();
        let _ = client.read_to_end(&mut resp);
        resp
    });

    let _ = handle(app, server_stream);

    let resp = client_handle.join().unwrap_or_default();
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

fn get_mining_template(app: &mut Explorer) -> serde_json::Value {
    let (status, body) = send_request_raw(
        app,
        b"GET /api/mine/template HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
    );
    assert_eq!(status, 200, "Failed to get template: {body}");
    serde_json::from_str(&body).expect("Valid JSON template")
}

fn mine_and_submit(
    app: &mut Explorer,
    parents: &[BlockId],
    work: u128,
    timestamp_ms: u64,
    payload_hex: &str,
) -> (u16, String, BlockId) {
    let payload_bytes = hex::decode(payload_hex).expect("Valid payload hex");
    let template_block = Block::new(parents.to_vec(), work, timestamp_ms, 0, payload_bytes);
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
    let (status, body) = send_request_raw(app, post_req.as_bytes());
    (status, body, block_id)
}

// =========================================================================
// 1. HTTP Request Edge Cases
// =========================================================================

#[test]
fn test_http_large_and_boundary_payloads() {
    let mut app = Explorer::boot();

    // 1.1 Huge Content-Length (10MB) where client sends only 100 bytes and disconnects
    let partial_req = "POST /api/mine/submit HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: 10485760\r\n\r\n{\"parents\":";
    let (status, body) = send_request_raw(&mut app, partial_req.as_bytes());
    assert_eq!(status, 400, "Truncated stream must return 400: {body}");
    assert!(body.contains("\"ok\":false"));

    // 1.2 Content-Length: 0 on POST
    let zero_len_req = "POST /api/mine/submit HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: 0\r\n\r\n";
    let (status, body) = send_request_raw(&mut app, zero_len_req.as_bytes());
    assert_eq!(status, 400);
    assert!(body.contains("\"ok\":false"));

    // 1.3 Missing Content-Length on POST
    let no_cl_req = "POST /api/mine/submit HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n\r\n{\"work\":1}";
    let (status, body) = send_request_raw(&mut app, no_cl_req.as_bytes());
    assert_eq!(status, 400);
    assert!(body.contains("\"ok\":false"));

    // 1.4 Non-numeric Content-Length
    let bad_cl_req = "POST /api/mine/submit HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: not_a_number\r\n\r\n{\"work\":1}";
    let (status, body) = send_request_raw(&mut app, bad_cl_req.as_bytes());
    assert_eq!(status, 400);
    assert!(body.contains("\"ok\":false"));

    // 1.5 Content-Length smaller than actual payload (e.g. Content-Length: 10 with 100 bytes sent)
    let small_cl_req = "POST /api/mine/submit HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: 10\r\n\r\n{\"parents\":[\"0000000000000000000000000000000000000000000000000000000000000000\"],\"work\":1}";
    let (status, body) = send_request_raw(&mut app, small_cl_req.as_bytes());
    assert_eq!(status, 400);
    assert!(body.contains("\"ok\":false"));

    // 1.6 Oversized payload > 2MB max body size (e.g. 2.2MB of whitespace padding in JSON)
    let padding = " ".repeat(2_200_000);
    let oversized_json = format!("{{\"parents\":[],\"pad\":\"{}\"}}", padding);
    let oversized_req = format!(
        "POST /api/mine/submit HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        oversized_json.len(),
        oversized_json
    );
    let (status, body) = send_request_raw(&mut app, oversized_req.as_bytes());
    assert_eq!(
        status, 400,
        "Oversized body should be rejected with 400: {body}"
    );
    assert!(body.contains("\"ok\":false"));
}

#[test]
fn test_http_slow_and_chunked_body_streaming() {
    let mut app = Explorer::boot();
    let tmpl = get_mining_template(&mut app);
    let parents_arr = tmpl["parents"].as_array().unwrap();
    let parent_hex = parents_arr[0].as_str().unwrap();
    let parent_id = BlockId::from_bytes(hex::decode(parent_hex).unwrap().try_into().unwrap());
    let work = tmpl["work"].as_u64().unwrap() as u128;
    let ts = tmpl["timestamp_ms"].as_u64().unwrap();
    let payload_hex = tmpl["payload"].as_str().unwrap();

    let block = Block::new(
        vec![parent_id],
        work,
        ts,
        0,
        hex::decode(payload_hex).unwrap(),
    );
    let mined = pow::mine(&block);

    let submit_json = format!(
        "{{\"parents\":[\"{}\"],\"work\":{},\"timestamp_ms\":{},\"nonce\":{},\"payload\":\"{}\"}}",
        parent_hex,
        work,
        ts,
        mined.nonce(),
        payload_hex
    );
    let headers = format!(
        "POST /api/mine/submit HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
        submit_json.len()
    );

    // Send body in tiny 7-byte chunks with 2ms delay between chunks
    let (status, body) =
        send_request_slow_body(&mut app, headers.as_bytes(), submit_json.as_bytes(), 7, 2);
    assert_eq!(status, 200, "Slow-chunked body request failed: {body}");
    let resp: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(resp["ok"], true);
    assert_eq!(resp["block"], mined.id().to_hex());
}

#[test]
fn test_http_malformed_json_matrix() {
    let mut app = Explorer::boot();

    let malformed_cases = [
        ("unterminated object", "{\"parents\": [\"0000000000000000000000000000000000000000000000000000000000000000\"]"),
        ("unterminated string", "{\"parents\": [\"0000000000000000000000000000000000000000000000000000000000000000}"),
        ("trailing comma in array", "{\"parents\": [\"0000000000000000000000000000000000000000000000000000000000000000\",], \"work\": 1}"),
        ("double comma", "{\"parents\": [\"0000000000000000000000000000000000000000000000000000000000000000\"],, \"work\": 1}"),
        ("json array root", "[\"parents\", 1, 2, 3]"),
        ("json string root", "\"just a string\""),
        ("json number root", "123456789"),
        ("json boolean root", "true"),
        ("json null root", "null"),
        ("empty body", ""),
        ("all null fields", "{\"parents\": null, \"work\": null, \"timestamp_ms\": null, \"nonce\": null, \"payload\": null}"),
        ("unquoted keys and values", "{parents: [00], work: 1}"),
        ("single quoted json", "{'parents': ['00'], 'work': 1}"),
    ];

    for (name, json_body) in malformed_cases {
        let req = format!(
            "POST /api/mine/submit HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            json_body.len(),
            json_body
        );
        let (status, body) = send_request_raw(&mut app, req.as_bytes());
        assert_eq!(
            status, 400,
            "Case '{name}' should return 400, got {status}: {body}"
        );
        assert!(
            body.contains("\"ok\":false"),
            "Case '{name}' response should contain ok:false"
        );
    }

    // Extraneous unknown fields alongside valid block fields should be tolerated
    let tmpl = get_mining_template(&mut app);
    let parent_hex = tmpl["parents"][0].as_str().unwrap();
    let parent_id = BlockId::from_bytes(hex::decode(parent_hex).unwrap().try_into().unwrap());
    let work = tmpl["work"].as_u64().unwrap() as u128;
    let ts = tmpl["timestamp_ms"].as_u64().unwrap();
    let payload_hex = tmpl["payload"].as_str().unwrap();

    let block = Block::new(
        vec![parent_id],
        work,
        ts,
        0,
        hex::decode(payload_hex).unwrap(),
    );
    let mined = pow::mine(&block);

    let valid_with_extras = format!(
        "{{\"unknown_pool_tag\":\"antigravity-1.0\",\"parents\":[\"{}\"],\"work\":{},\"timestamp_ms\":{},\"nonce\":{},\"payload\":\"{}\",\"extra_stats\":{{\"hashrate\":1000000}}}}",
        parent_hex,
        work,
        ts,
        mined.nonce(),
        payload_hex
    );
    let req = format!(
        "POST /api/mine/submit HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        valid_with_extras.len(),
        valid_with_extras
    );
    let (status, body) = send_request_raw(&mut app, req.as_bytes());
    assert_eq!(
        status, 200,
        "Valid request with extra fields should succeed: {body}"
    );
    assert!(body.contains("\"ok\":true"));
}

#[test]
fn test_http_invalid_hex_and_type_coercions() {
    let mut app = Explorer::boot();
    let tmpl = get_mining_template(&mut app);
    let parent_hex = tmpl["parents"][0].as_str().unwrap();
    let parent_id = BlockId::from_bytes(hex::decode(parent_hex).unwrap().try_into().unwrap());
    let work = tmpl["work"].as_u64().unwrap() as u128;
    let ts = tmpl["timestamp_ms"].as_u64().unwrap();
    let payload_hex = tmpl["payload"].as_str().unwrap();

    let block = Block::new(
        vec![parent_id],
        work,
        ts,
        0,
        hex::decode(payload_hex).unwrap(),
    );
    let mined = pow::mine(&block);
    let nonce = mined.nonce();

    let invalid_type_cases = [
        // Parents validation
        ("empty parents array", format!("{{\"parents\":[],\"work\":{work},\"timestamp_ms\":{ts},\"nonce\":{nonce},\"payload\":\"{payload_hex}\"}}")),
        ("parents as string", format!("{{\"parents\":\"{parent_hex}\",\"work\":{work},\"timestamp_ms\":{ts},\"nonce\":{nonce},\"payload\":\"{payload_hex}\"}}")),
        ("parents as number", format!("{{\"parents\":12345,\"work\":{work},\"timestamp_ms\":{ts},\"nonce\":{nonce},\"payload\":\"{payload_hex}\"}}")),
        ("parents array with numbers", format!("{{\"parents\":[12345],\"work\":{work},\"timestamp_ms\":{ts},\"nonce\":{nonce},\"payload\":\"{payload_hex}\"}}")),
        ("parents array with null", format!("{{\"parents\":[null],\"work\":{work},\"timestamp_ms\":{ts},\"nonce\":{nonce},\"payload\":\"{payload_hex}\"}}")),
        ("odd length hex in parents", format!("{{\"parents\":[\"abc\"],\"work\":{work},\"timestamp_ms\":{ts},\"nonce\":{nonce},\"payload\":\"{payload_hex}\"}}")),
        ("non-hex characters in parents", format!("{{\"parents\":[\"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz\"],\"work\":{work},\"timestamp_ms\":{ts},\"nonce\":{nonce},\"payload\":\"{payload_hex}\"}}")),
        ("parent wrong byte length (16 bytes = 32 chars)", format!("{{\"parents\":[\"00000000000000000000000000000000\"],\"work\":{work},\"timestamp_ms\":{ts},\"nonce\":{nonce},\"payload\":\"{payload_hex}\"}}")),
        ("parent wrong byte length (33 bytes = 66 chars)", format!("{{\"parents\":[\"00000000000000000000000000000000000000000000000000000000000000000000\"],\"work\":{work},\"timestamp_ms\":{ts},\"nonce\":{nonce},\"payload\":\"{payload_hex}\"}}")),
        ("parent empty string", format!("{{\"parents\":[\"\"],\"work\":{work},\"timestamp_ms\":{ts},\"nonce\":{nonce},\"payload\":\"{payload_hex}\"}}")),

        // Work validation
        ("work as non-numeric string", format!("{{\"parents\":[\"{parent_hex}\"],\"work\":\"not_a_number\",\"timestamp_ms\":{ts},\"nonce\":{nonce},\"payload\":\"{payload_hex}\"}}")),
        ("work as negative string", format!("{{\"parents\":[\"{parent_hex}\"],\"work\":\"-10\",\"timestamp_ms\":{ts},\"nonce\":{nonce},\"payload\":\"{payload_hex}\"}}")),
        ("work as boolean", format!("{{\"parents\":[\"{parent_hex}\"],\"work\":true,\"timestamp_ms\":{ts},\"nonce\":{nonce},\"payload\":\"{payload_hex}\"}}")),
        ("work as array", format!("{{\"parents\":[\"{parent_hex}\"],\"work\":[1,2],\"timestamp_ms\":{ts},\"nonce\":{nonce},\"payload\":\"{payload_hex}\"}}")),
        ("work as object", format!("{{\"parents\":[\"{parent_hex}\"],\"work\":{{\"val\":1}},\"timestamp_ms\":{ts},\"nonce\":{nonce},\"payload\":\"{payload_hex}\"}}")),

        // Timestamp validation
        ("timestamp as non-numeric string", format!("{{\"parents\":[\"{parent_hex}\"],\"work\":{work},\"timestamp_ms\":\"not_time\",\"nonce\":{nonce},\"payload\":\"{payload_hex}\"}}")),
        ("timestamp as boolean", format!("{{\"parents\":[\"{parent_hex}\"],\"work\":{work},\"timestamp_ms\":false,\"nonce\":{nonce},\"payload\":\"{payload_hex}\"}}")),
        ("timestamp as array", format!("{{\"parents\":[\"{parent_hex}\"],\"work\":{work},\"timestamp_ms\":[100],\"nonce\":{nonce},\"payload\":\"{payload_hex}\"}}")),
        ("timestamp as object", format!("{{\"parents\":[\"{parent_hex}\"],\"work\":{work},\"timestamp_ms\":{{\"t\":100}},\"nonce\":{nonce},\"payload\":\"{payload_hex}\"}}")),

        // Nonce validation
        ("nonce as non-numeric string", format!("{{\"parents\":[\"{parent_hex}\"],\"work\":{work},\"timestamp_ms\":{ts},\"nonce\":\"invalid_nonce\",\"payload\":\"{payload_hex}\"}}")),
        ("nonce as boolean", format!("{{\"parents\":[\"{parent_hex}\"],\"work\":{work},\"timestamp_ms\":{ts},\"nonce\":true,\"payload\":\"{payload_hex}\"}}")),
        ("nonce as array", format!("{{\"parents\":[\"{parent_hex}\"],\"work\":{work},\"timestamp_ms\":{ts},\"nonce\":[42],\"payload\":\"{payload_hex}\"}}")),
        ("nonce as object", format!("{{\"parents\":[\"{parent_hex}\"],\"work\":{work},\"timestamp_ms\":{ts},\"nonce\":{{\"n\":42}},\"payload\":\"{payload_hex}\"}}")),

        // Payload validation
        ("payload as number", format!("{{\"parents\":[\"{parent_hex}\"],\"work\":{work},\"timestamp_ms\":{ts},\"nonce\":{nonce},\"payload\":12345}}")),
        ("payload as boolean", format!("{{\"parents\":[\"{parent_hex}\"],\"work\":{work},\"timestamp_ms\":{ts},\"nonce\":{nonce},\"payload\":true}}")),
        ("payload as array", format!("{{\"parents\":[\"{parent_hex}\"],\"work\":{work},\"timestamp_ms\":{ts},\"nonce\":{nonce},\"payload\":[\"00\"]}}")),
        ("payload as odd hex", format!("{{\"parents\":[\"{parent_hex}\"],\"work\":{work},\"timestamp_ms\":{ts},\"nonce\":{nonce},\"payload\":\"abc\"}}")),
        ("payload as non-hex", format!("{{\"parents\":[\"{parent_hex}\"],\"work\":{work},\"timestamp_ms\":{ts},\"nonce\":{nonce},\"payload\":\"zzzz\"}}")),
        ("payload valid hex but corrupted bincode", format!("{{\"parents\":[\"{parent_hex}\"],\"work\":{work},\"timestamp_ms\":{ts},\"nonce\":{nonce},\"payload\":\"deadbeefcafebabe0102030405060708090a0b0c0d0e0f\"}}")),
    ];

    for (name, json_str) in invalid_type_cases {
        let req = format!(
            "POST /api/mine/submit HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            json_str.len(),
            json_str
        );
        let (status, body) = send_request_raw(&mut app, req.as_bytes());
        assert_eq!(
            status, 400,
            "Case '{name}' should return 400, got {status}: {body}"
        );
        assert!(
            body.contains("\"ok\":false"),
            "Case '{name}' should contain ok:false"
        );
    }

    // String coercion test: work, timestamp_ms, nonce passed as valid numeric strings
    let coerced_valid_json = format!(
        "{{\"parents\":[\"{parent_hex}\"],\"work\":\"{work}\",\"timestamp_ms\":\"{ts}\",\"nonce\":\"{nonce}\",\"payload\":\"{payload_hex}\"}}"
    );
    let req = format!(
        "POST /api/mine/submit HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        coerced_valid_json.len(),
        coerced_valid_json
    );
    let (status, body) = send_request_raw(&mut app, req.as_bytes());
    assert_eq!(
        status, 200,
        "Numeric string fields should be coerced successfully: {body}"
    );
    assert!(body.contains("\"ok\":true"));
}

// =========================================================================
// 2. Boundary Values: Work, Timestamps, Parents, Difficulty
// =========================================================================

#[test]
fn test_boundary_work_values() {
    // 2.1 work == 0 with PoW disabled (hybrid/mock mode)
    {
        let mut app = Explorer::boot();
        let tmpl = get_mining_template(&mut app);
        let parent_hex = tmpl["parents"][0].as_str().unwrap();
        let parent_id = BlockId::from_bytes(hex::decode(parent_hex).unwrap().try_into().unwrap());
        let ts = tmpl["timestamp_ms"].as_u64().unwrap();
        let payload_hex = tmpl["payload"].as_str().unwrap();

        // Submit block with work: 0
        let (status, body, _) = mine_and_submit(&mut app, &[parent_id], 0, ts, payload_hex);
        assert_eq!(
            status, 200,
            "work:0 block should be accepted when PoW is off: {body}"
        );
        assert!(body.contains("\"ok\":true"));
    }

    // 2.2 work == 0 with PoW enabled
    {
        let mut app = Explorer::boot();
        let node = app.mesh.node_mut("alpha").unwrap();
        node.set_proof_of_work(true).unwrap();

        let tmpl = get_mining_template(&mut app);
        let parent_hex = tmpl["parents"][0].as_str().unwrap();
        let parent_id = BlockId::from_bytes(hex::decode(parent_hex).unwrap().try_into().unwrap());
        let ts = tmpl["timestamp_ms"].as_u64().unwrap();
        let payload_hex = tmpl["payload"].as_str().unwrap();

        // meets_target treats work 0 as work 1 (accepts all hashes)
        let (status, body, _) = mine_and_submit(&mut app, &[parent_id], 0, ts, payload_hex);
        assert_eq!(
            status, 200,
            "work:0 block with PoW enabled should succeed: {body}"
        );
        assert!(body.contains("\"ok\":true"));
    }

    // 2.3 work == 1 with PoW enabled
    {
        let mut app = Explorer::boot();
        let node = app.mesh.node_mut("alpha").unwrap();
        node.set_proof_of_work(true).unwrap();

        let tmpl = get_mining_template(&mut app);
        let parent_hex = tmpl["parents"][0].as_str().unwrap();
        let parent_id = BlockId::from_bytes(hex::decode(parent_hex).unwrap().try_into().unwrap());
        let ts = tmpl["timestamp_ms"].as_u64().unwrap();
        let payload_hex = tmpl["payload"].as_str().unwrap();

        let (status, body, _) = mine_and_submit(&mut app, &[parent_id], 1, ts, payload_hex);
        assert_eq!(
            status, 200,
            "work:1 block with PoW enabled should succeed: {body}"
        );
        assert!(body.contains("\"ok\":true"));
    }

    // 2.4 Extremely high work target with PoW enabled
    {
        let mut app = Explorer::boot();
        let node = app.mesh.node_mut("alpha").unwrap();
        node.set_proof_of_work(true).unwrap();

        let tmpl = get_mining_template(&mut app);
        let parent_hex = tmpl["parents"][0].as_str().unwrap();
        let _parent_id = BlockId::from_bytes(hex::decode(parent_hex).unwrap().try_into().unwrap());
        let ts = tmpl["timestamp_ms"].as_u64().unwrap();
        let payload_hex = tmpl["payload"].as_str().unwrap();

        // Attempt submission with high work and nonce 0 (astronomically unlikely to pass)
        let high_work = 1_000_000_000_000_000u128;
        let submit_json = format!(
            "{{\"parents\":[\"{parent_hex}\"],\"work\":{high_work},\"timestamp_ms\":{ts},\"nonce\":0,\"payload\":\"{payload_hex}\"}}"
        );
        let req = format!(
            "POST /api/mine/submit HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            submit_json.len(),
            submit_json
        );
        let (status, body) = send_request_raw(&mut app, req.as_bytes());
        assert_eq!(
            status, 400,
            "Invalid nonce for high work should fail: {body}"
        );
        assert!(body.contains("proof of work target not met") || body.contains("\"ok\":false"));
    }
}

#[test]
fn test_boundary_timestamps() {
    let mut app = Explorer::boot();
    let tmpl = get_mining_template(&mut app);
    let parent_hex = tmpl["parents"][0].as_str().unwrap();
    let parent_id = BlockId::from_bytes(hex::decode(parent_hex).unwrap().try_into().unwrap());
    let work = tmpl["work"].as_u64().unwrap() as u128;
    let parent_ts = tmpl["timestamp_ms"].as_u64().unwrap();
    let payload_hex = tmpl["payload"].as_str().unwrap();

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    // 2.5 Timestamp at parent_ts (monotone non-decreasing)
    let (status, body, _) = mine_and_submit(&mut app, &[parent_id], work, parent_ts, payload_hex);
    assert_eq!(status, 200, "Timestamp equal to parent is allowed: {body}");
    assert!(body.contains("\"ok\":true"));

    // 2.6 Future timestamp within 2 hours: now + 1 hour (<= 2h limit)
    let tmpl2 = get_mining_template(&mut app);
    let tip2 = BlockId::from_bytes(
        hex::decode(tmpl2["parents"][0].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap(),
    );
    let payload2_hex = tmpl2["payload"].as_str().unwrap();
    let valid_future_ts = now_ms.saturating_add(60 * 60 * 1000); // +1h
    let (status, body, _) = mine_and_submit(&mut app, &[tip2], work, valid_future_ts, payload2_hex);
    assert_eq!(
        status, 200,
        "Future timestamp within 2h should succeed: {body}"
    );
    assert!(body.contains("\"ok\":true"));

    // 2.7 Future timestamp beyond 2 hours: now + 2 hours + 60 seconds (> 2h limit)
    let tmpl3 = get_mining_template(&mut app);
    let tip3 = BlockId::from_bytes(
        hex::decode(tmpl3["parents"][0].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap(),
    );
    let payload3_hex = tmpl3["payload"].as_str().unwrap();
    let invalid_future_ts = now_ms.saturating_add(MAX_FUTURE_DRIFT_MS + 60_000); // +2h 1min
    let (status, body, _) =
        mine_and_submit(&mut app, &[tip3], work, invalid_future_ts, payload3_hex);
    assert_eq!(status, 400, "Timestamp > 2h in future must fail: {body}");
    assert!(body.contains("more than 2h ahead of local clock") || body.contains("\"ok\":false"));

    // 2.8 Timestamp u64::MAX
    let (status, body, _) = mine_and_submit(&mut app, &[tip3], work, u64::MAX, payload3_hex);
    assert_eq!(status, 400, "Timestamp u64::MAX must fail: {body}");
    assert!(body.contains("\"ok\":false"));
}

#[test]
fn test_boundary_parents_and_dag_topology() {
    let mut app = Explorer::boot();

    // 2.9 Non-existent / unknown parent
    let fake_parent = BlockId::from_bytes([0xef; 32]);
    let tmpl = get_mining_template(&mut app);
    let work = tmpl["work"].as_u64().unwrap() as u128;
    let ts = tmpl["timestamp_ms"].as_u64().unwrap();
    let payload_hex = tmpl["payload"].as_str().unwrap();

    let (status, body, _) = mine_and_submit(&mut app, &[fake_parent], work, ts, payload_hex);
    assert_eq!(status, 400, "Unknown parent must fail: {body}");
    assert!(body.contains("\"ok\":false"));

    // 2.10 Multiple DAG tips with out-of-order parent listing
    // Create a DAG fork by producing 2 parallel blocks on genesis
    let genesis_id = {
        let node = app.mesh.node("alpha").unwrap();
        node.selected_tip().unwrap()
    };

    // First child of genesis
    let (status1, body1, child1_id) =
        mine_and_submit(&mut app, &[genesis_id], work, ts + 10, payload_hex);
    assert_eq!(status1, 200, "Child 1 creation failed: {body1}");

    // Second parallel child of genesis (fork)
    // Custom coinbase so hash/id is distinct
    let custom_miner = KeyPair::from_u64(99).address();
    let custom_tmpl = {
        let node = app.mesh.node("alpha").unwrap();
        node.mining_template_for(Some(custom_miner)).unwrap()
    };
    let (status2, body2, child2_id) =
        mine_and_submit(&mut app, &[genesis_id], work, ts + 20, &custom_tmpl.payload);
    assert_eq!(status2, 200, "Child 2 creation failed: {body2}");

    // Merge both children in reverse/out-of-order: [child2_id, child1_id]
    let merge_payload = {
        let node = app.mesh.node("alpha").unwrap();
        node.mining_template().unwrap().payload
    };
    let (merge_status, merge_body, merge_id) = mine_and_submit(
        &mut app,
        &[child2_id, child1_id],
        work,
        ts + 30,
        &merge_payload,
    );
    assert_eq!(
        merge_status, 200,
        "Merging out-of-order tips should succeed: {merge_body}"
    );
    assert!(merge_body.contains("\"ok\":true"));

    let node_after = app.mesh.node("alpha").unwrap();
    assert!(node_after.has_block(&merge_id));
    assert_eq!(node_after.selected_tip().unwrap(), merge_id);
}

// =========================================================================
// 3. DAG Consistency, State Isolation & Server Resilience
// =========================================================================

#[test]
fn test_dag_consistency_after_corrupted_bursts() {
    let mut app = Explorer::boot();

    let node_initial = app.mesh.node("alpha").unwrap();
    let initial_tip = node_initial.selected_tip().unwrap();
    let initial_count = node_initial.block_count().unwrap();
    let founder_addr = KeyPair::from_u64(1).address();
    let initial_balance = node_initial.balance(&founder_addr).unwrap();

    // Fire 50 malformed / corrupted requests
    for i in 0..50 {
        let bad_payload = match i % 5 {
            0 => "POST /api/mine/submit HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: 15\r\n\r\n{\"corrupted\":true}",
            1 => "POST /api/mine/submit HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: 40\r\n\r\n{\"parents\":[\"zzzz\"],\"work\":1,\"nonce\":0}",
            2 => "POST /api/mine/submit HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: 50\r\n\r\n{\"parents\":[\"00\"],\"work\":\"invalid\",\"nonce\":0}",
            3 => "POST /api/mine/submit HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: 8\r\n\r\nnot_json",
            _ => "POST /api/mine/submit HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: 60\r\n\r\n{\"parents\":[\"0000000000000000000000000000000000000000000000000000000000000000\"],\"work\":1,\"timestamp_ms\":10,\"nonce\":0,\"payload\":\"00\"}",
        };
        let (status, body) = send_request_raw(&mut app, bad_payload.as_bytes());
        assert_eq!(
            status, 400,
            "Corrupted request {i} returned {status}: {body}"
        );
    }

    // Verify node state is completely untouched
    let node_check = app.mesh.node("alpha").unwrap();
    assert_eq!(node_check.selected_tip().unwrap(), initial_tip);
    assert_eq!(node_check.block_count().unwrap(), initial_count);
    assert_eq!(node_check.balance(&founder_addr).unwrap(), initial_balance);

    // Verify valid block mining immediately succeeds
    let tmpl = get_mining_template(&mut app);
    let parent_hex = tmpl["parents"][0].as_str().unwrap();
    let parent_id = BlockId::from_bytes(hex::decode(parent_hex).unwrap().try_into().unwrap());
    let work = tmpl["work"].as_u64().unwrap() as u128;
    let ts = tmpl["timestamp_ms"].as_u64().unwrap();
    let payload_hex = tmpl["payload"].as_str().unwrap();

    let (status, body, valid_id) = mine_and_submit(&mut app, &[parent_id], work, ts, payload_hex);
    assert_eq!(
        status, 200,
        "Valid submission after corrupted burst failed: {body}"
    );
    assert!(body.contains("\"ok\":true"));

    let node_final = app.mesh.node("alpha").unwrap();
    assert_eq!(node_final.selected_tip().unwrap(), valid_id);
    assert_eq!(node_final.block_count().unwrap(), initial_count + 1);
}

#[test]
fn test_mining_template_and_continuous_block_pipeline() {
    let mut app = Explorer::boot();

    // Mine 10 consecutive blocks in a tight loop via HTTP endpoints
    for h in 1..=10 {
        let tmpl = get_mining_template(&mut app);
        let parents: Vec<BlockId> = tmpl["parents"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| {
                BlockId::from_bytes(
                    hex::decode(p.as_str().unwrap())
                        .unwrap()
                        .try_into()
                        .unwrap(),
                )
            })
            .collect();
        let work = tmpl["work"].as_u64().unwrap() as u128;
        let ts = tmpl["timestamp_ms"].as_u64().unwrap();
        let payload_hex = tmpl["payload"].as_str().unwrap();

        let (status, body, mined_id) = mine_and_submit(&mut app, &parents, work, ts, payload_hex);
        assert_eq!(status, 200, "Block at height {h} failed: {body}");
        assert!(body.contains(&mined_id.to_hex()));

        // Check node tip after each block
        let node = app.mesh.node("alpha").unwrap();
        assert_eq!(node.selected_tip().unwrap(), mined_id);
    }

    let node = app.mesh.node("alpha").unwrap();
    // Genesis (1) + 10 mined blocks = 11 total
    assert_eq!(node.block_count().unwrap(), 11);
}

#[test]
fn test_mempool_drain_and_reorg_consistency() {
    let mut app = Explorer::boot();
    let recipient = KeyPair::from_u64(2).address();

    // Pool transfer of 100 KVNC
    app.mesh.pool("alpha", 1, 100 * 100_000_000, 2).unwrap();

    let node_before = app.mesh.node("alpha").unwrap();
    assert_eq!(node_before.pending_count(), 1);
    assert_eq!(node_before.balance(&recipient).unwrap(), 0);

    // Fetch template — should contain coinbase + the transfer
    let tmpl = get_mining_template(&mut app);
    assert_eq!(tmpl["transactions"].as_array().unwrap().len(), 2);
    let parents: Vec<BlockId> = tmpl["parents"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| {
            BlockId::from_bytes(
                hex::decode(p.as_str().unwrap())
                    .unwrap()
                    .try_into()
                    .unwrap(),
            )
        })
        .collect();
    let work = tmpl["work"].as_u64().unwrap() as u128;
    let ts = tmpl["timestamp_ms"].as_u64().unwrap();
    let payload_hex = tmpl["payload"].as_str().unwrap();

    // Mine and submit
    let (status, body, mined_id) = mine_and_submit(&mut app, &parents, work, ts, payload_hex);
    assert_eq!(status, 200, "Mining block with tx failed: {body}");

    let node_after = app.mesh.node("alpha").unwrap();
    assert_eq!(node_after.selected_tip().unwrap(), mined_id);
    assert_eq!(node_after.pending_count(), 0, "Mempool should be drained");
    assert_eq!(
        node_after.balance(&recipient).unwrap(),
        100u128 * 100_000_000u128
    );

    // Resubmitting same block should be idempotent and not double-spend or change balance
    let (idempotent_status, idempotent_body, _) =
        mine_and_submit(&mut app, &parents, work, ts, payload_hex);
    assert_eq!(idempotent_status, 200);
    assert!(idempotent_body.contains(&mined_id.to_hex()));
    let node_recheck = app.mesh.node("alpha").unwrap();
    assert_eq!(
        node_recheck.balance(&recipient).unwrap(),
        100u128 * 100_000_000u128
    );
}
