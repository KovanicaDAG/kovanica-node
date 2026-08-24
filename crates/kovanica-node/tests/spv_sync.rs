//! Integration tests for SPV (Simplified Payment Verification) Wire Protocol
//! and Light Client Sync over TCP streams.

use std::net::TcpListener;
use std::thread;
use std::time::Duration;

use kovanica_dag::{BlockId, Retarget};
use kovanica_node::{
    handle_relay_query, request_merkle_block, sync_headers_via_relay,
    sync_headers_via_relay_with_clock, verify_merkle_block, Node, RelayMsg, RelaySession,
};
use kovanica_state::spv::{BlockHeader as SpvHeader, SpvClient, SpvError};
use kovanica_state::{KeyPair, OutPoint, Transaction, TxId, TxOutput};

fn genesis_node() -> Node {
    let mut node = Node::new();
    node.set_now_ms(1_000);
    node.genesis(3, 1000, 1000, 1).unwrap();
    node
}

fn get_genesis_header() -> SpvHeader {
    let node = genesis_node();
    let gen_id = node.genesis_id().unwrap();
    node.spv_header(&gen_id).unwrap()
}

#[test]
fn test_e2e_spv_header_sync_over_tcp() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let genesis_hdr = get_genesis_header();

    // Run full node query handler on background thread
    let handle = thread::spawn(move || {
        let mut node = genesis_node();
        let mut sent_blocks = Vec::new();
        for i in 0..5 {
            node.set_now_ms(1_000 + (i as u64 + 1) * 1_000);
            let sent = node.send(1, 10 + i as u64, 2).unwrap();
            sent_blocks.push(sent.block);
        }

        let mut server = RelaySession::accept(&listener).unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();

        // Handle incoming GetHeaders query
        let req = server.recv().unwrap();
        let resp = handle_relay_query(&node, &req).expect("query handled");
        server.send(&resp).unwrap();
        *sent_blocks.last().unwrap()
    });

    // Light client connects and syncs headers
    let mut client_session = RelaySession::connect(addr).unwrap();
    client_session
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();

    let mut spv_client = SpvClient::new(genesis_hdr, false, None);
    let count = sync_headers_via_relay(&mut client_session, &mut spv_client, None).unwrap();
    assert_eq!(count, 5);

    let expected_tip_id = handle.join().unwrap();

    // Verify SPV client state
    let tip = spv_client.tip().unwrap();
    assert_eq!(tip.height, 5);
    assert_eq!(tip.id, expected_tip_id);
}

#[test]
fn test_e2e_spv_merkle_proof_verification_over_tcp() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let genesis_hdr = get_genesis_header();

    let handle = thread::spawn(move || {
        let mut node = genesis_node();
        // Alice (actor 1) transfers 250 KVNC to Bob (actor 2)
        node.set_now_ms(2_000);
        let sent = node.send(1, 250, 2).unwrap();

        let mut server = RelaySession::accept(&listener).unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();

        // Serve GetHeaders then GetMerkleProof on the same persistent TCP session
        for _ in 0..2 {
            let req = server.recv().unwrap();
            let resp = handle_relay_query(&node, &req).expect("query handled");
            server.send(&resp).unwrap();
        }
        (sent.block, sent.tx)
    });

    let mut client_session = RelaySession::connect(addr).unwrap();
    client_session
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();

    let mut spv_client = SpvClient::new(genesis_hdr, false, None);

    // 1. Sync headers
    let count = sync_headers_via_relay(&mut client_session, &mut spv_client, None).unwrap();
    assert_eq!(count, 1);

    // 2. Request and verify Merkle proof for Bob's transaction
    let (sent_block, sent_tx) = {
        // We know the query will ask for sent_block and sent_tx
        let mut temp_node = genesis_node();
        temp_node.set_now_ms(2_000);
        let s = temp_node.send(1, 250, 2).unwrap();
        (s.block, s.tx)
    };

    let mb = request_merkle_block(&mut client_session, sent_block, sent_tx).unwrap();
    assert_eq!(mb.block_id, sent_block);
    assert!(mb.proof.is_some());
    assert!(mb.matched_tx.is_some());

    let is_valid = verify_merkle_block(&spv_client, &mb).unwrap();
    assert!(is_valid);

    let matched = mb.matched_tx.as_ref().unwrap();
    assert_eq!(matched.outputs()[0].value, 250);
    assert_eq!(matched.outputs()[0].owner, Node::address(2));

    handle.join().unwrap();
}

#[test]
fn test_spv_difficulty_retarget_enforcement() {
    let retarget = Retarget {
        window: 2,
        target_interval_ms: 1_000,
        max_factor: 4,
        min_work: 1,
    };

    let genesis_hdr = SpvHeader {
        id: BlockId::from_bytes([1u8; 32]),
        prev_hash: BlockId::from_bytes([0u8; 32]),
        merkle_root: [0u8; 32],
        work: 1,
        timestamp_ms: 1_000,
        nonce: 0,
        blue_score: 0,
        chain_blue_work: 1,
        height: 0,
    };

    let mut client = SpvClient::new(genesis_hdr.clone(), false, Some(retarget));

    // Valid next header at height 1
    let h1 = SpvHeader {
        id: BlockId::from_bytes([2u8; 32]),
        prev_hash: genesis_hdr.id,
        merkle_root: [0u8; 32],
        work: 1,
        timestamp_ms: 2_000,
        nonce: 0,
        blue_score: 1,
        chain_blue_work: 2,
        height: 1,
    };
    assert!(client.add_header(h1.clone()).is_ok());

    // Valid next header at height 2
    let h2 = SpvHeader {
        id: BlockId::from_bytes([3u8; 32]),
        prev_hash: h1.id,
        merkle_root: [0u8; 32],
        work: 1,
        timestamp_ms: 3_000,
        nonce: 0,
        blue_score: 2,
        chain_blue_work: 3,
        height: 2,
    };
    assert!(client.add_header(h2.clone()).is_ok());

    // Header with invalid difficulty should be rejected
    let h3_bad_work = SpvHeader {
        id: BlockId::from_bytes([4u8; 32]),
        prev_hash: h2.id,
        merkle_root: [0u8; 32],
        work: 999, // Mismatched difficulty target
        timestamp_ms: 4_000,
        nonce: 0,
        blue_score: 3,
        chain_blue_work: 1002,
        height: 3,
    };
    let res = client.add_header(h3_bad_work);
    assert_eq!(res, Err(SpvError::DifficultyMismatch));
}

#[test]
fn test_spv_wall_clock_drift_boundary() {
    let now_ms = 1_000_000u64;
    const MAX_FUTURE_DRIFT_MS: u64 = 2 * 60 * 60 * 1000; // 7,200,000 ms

    let genesis_hdr = SpvHeader {
        id: BlockId::from_bytes([1u8; 32]),
        prev_hash: BlockId::from_bytes([0u8; 32]),
        merkle_root: [0u8; 32],
        work: 1,
        timestamp_ms: now_ms,
        nonce: 0,
        blue_score: 0,
        chain_blue_work: 1,
        height: 0,
    };

    // Header at exact drift boundary (now + 2h)
    let h_boundary = SpvHeader {
        id: BlockId::from_bytes([2u8; 32]),
        prev_hash: genesis_hdr.id,
        merkle_root: [0u8; 32],
        work: 1,
        timestamp_ms: now_ms + MAX_FUTURE_DRIFT_MS,
        nonce: 0,
        blue_score: 1,
        chain_blue_work: 2,
        height: 1,
    };

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let h_boundary_clone = h_boundary.clone();
    let handle = thread::spawn(move || {
        let mut server = RelaySession::accept(&listener).unwrap();
        let _ = server.recv().unwrap();
        server
            .send(&RelayMsg::Headers {
                headers: vec![h_boundary_clone],
            })
            .unwrap();
    });

    let mut client_session = RelaySession::connect(addr).unwrap();
    let mut spv_client = SpvClient::new(genesis_hdr.clone(), false, None);

    // Accept header at exact boundary
    let res =
        sync_headers_via_relay_with_clock(&mut client_session, &mut spv_client, None, Some(now_ms));
    assert_eq!(res.unwrap(), 1);
    handle.join().unwrap();

    // Now test header exceeding drift boundary by 1ms (now + 2h + 1ms)
    let h_exceed = SpvHeader {
        id: BlockId::from_bytes([3u8; 32]),
        prev_hash: h_boundary.id,
        merkle_root: [0u8; 32],
        work: 1,
        timestamp_ms: now_ms + MAX_FUTURE_DRIFT_MS + 1,
        nonce: 0,
        blue_score: 2,
        chain_blue_work: 3,
        height: 2,
    };

    let listener2 = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr2 = listener2.local_addr().unwrap();

    let handle2 = thread::spawn(move || {
        let mut server = RelaySession::accept(&listener2).unwrap();
        let _ = server.recv().unwrap();
        server
            .send(&RelayMsg::Headers {
                headers: vec![h_exceed],
            })
            .unwrap();
    });

    let mut client_session2 = RelaySession::connect(addr2).unwrap();
    let res2 = sync_headers_via_relay_with_clock(
        &mut client_session2,
        &mut spv_client,
        None,
        Some(now_ms),
    );
    assert!(res2.is_err());
    handle2.join().unwrap();
}

#[test]
fn test_spv_tampered_merkle_proof_rejection() {
    let mut node = genesis_node();
    let genesis = node.genesis_id().unwrap();
    let genesis_hdr = node.spv_header(&genesis).unwrap();
    let sent = node.send(1, 100, 2).unwrap();

    let mut spv_client = SpvClient::new(genesis_hdr, false, None);
    let sent_hdr = node.spv_header(&sent.block).unwrap();
    spv_client.add_header(sent_hdr).unwrap();

    let mb = node.merkle_block(&sent.block, &sent.tx).unwrap();

    // 1. Valid MerkleBlock passes
    assert!(verify_merkle_block(&spv_client, &mb).unwrap());

    // 2. Tampered transaction payload
    let mut mb_tampered_tx = mb.clone();
    if let Some(ref mut tx) = mb_tampered_tx.matched_tx {
        // Alter output value
        let kp = KeyPair::from_u64(1);
        let op = OutPoint::new(TxId::from_bytes([1u8; 32]), 0);
        *tx = Transaction::signed(
            &[(op, &kp)],
            vec![TxOutput::new(999_999, kp.address())],
            vec![],
        );
    }
    assert!(!verify_merkle_block(&spv_client, &mb_tampered_tx).unwrap());

    // 3. Tampered sibling path
    let mut mb_tampered_path = mb.clone();
    if let Some(ref mut proof) = mb_tampered_path.proof {
        proof.path = vec![[0xfeu8; 32]];
    }
    assert!(!verify_merkle_block(&spv_client, &mb_tampered_path).unwrap());

    // 4. Tampered Merkle root
    let mut mb_tampered_root = mb;
    mb_tampered_root.merkle_root = [0x55u8; 32];
    assert!(!verify_merkle_block(&spv_client, &mb_tampered_root).unwrap());
}

#[test]
fn test_spv_mobile_wallet_payment_workflow_and_bandwidth() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let genesis_hdr = get_genesis_header();

    let handle = thread::spawn(move || {
        let mut node = genesis_node();
        let mut target_tx = None;
        let mut target_block = None;

        for i in 0..20 {
            node.set_now_ms(1_000 + (i as u64 + 1) * 1_000);
            let sent = node.send(1, 10 + i as u64, 2).unwrap();
            if i == 10 {
                target_tx = Some(sent.tx);
                target_block = Some(sent.block);
            }
        }

        let mut server = RelaySession::accept(&listener).unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();

        // 1. Serve GetHeaders
        let req1 = server.recv().unwrap();
        let resp1 = handle_relay_query(&node, &req1).unwrap();
        server.send(&resp1).unwrap();

        // 2. Serve GetMerkleProof
        let req2 = server.recv().unwrap();
        let resp2 = handle_relay_query(&node, &req2).unwrap();
        server.send(&resp2).unwrap();

        (target_block.unwrap(), target_tx.unwrap())
    });

    let mut client_session = RelaySession::connect(addr).unwrap();
    client_session
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();

    let mut spv_client = SpvClient::new(genesis_hdr, false, None);

    // Sync 20 headers
    let synced = sync_headers_via_relay(&mut client_session, &mut spv_client, None).unwrap();
    assert_eq!(synced, 20);
    assert_eq!(spv_client.tip().unwrap().height, 20);

    let (target_block_id, target_tx_id) = {
        let mut temp_node = genesis_node();
        let mut tb = None;
        let mut tt = None;
        for i in 0..20 {
            temp_node.set_now_ms(1_000 + (i as u64 + 1) * 1_000);
            let sent = temp_node.send(1, 10 + i as u64, 2).unwrap();
            if i == 10 {
                tt = Some(sent.tx);
                tb = Some(sent.block);
            }
        }
        (tb.unwrap(), tt.unwrap())
    };

    // Request and verify Merkle proof for payment
    let mb = request_merkle_block(&mut client_session, target_block_id, target_tx_id).unwrap();
    assert!(verify_merkle_block(&spv_client, &mb).unwrap());

    // Confirm payment details
    let matched = mb.matched_tx.unwrap();
    assert_eq!(matched.outputs()[0].value, 20);
    assert_eq!(matched.outputs()[0].owner, Node::address(2));

    handle.join().unwrap();
}
