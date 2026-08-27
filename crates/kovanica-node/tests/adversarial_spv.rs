//! Adversarial Stress Testing & Fuzzing for SPV Wire Protocol and Merkle Proofs.
//!
//! Evaluates:
//! 1. Wire framing fuzzing, byte-by-byte truncation, boundary violation, and corrupt tag handling.
//! 2. Adversarial Merkle proof attacks: bit-flips, path corruption, index mutations, leaf duplication, cross-block forgery.
//! 3. High-concurrency TCP stress test with 30+ simultaneous SPV light clients and Byzantine probes against a live full node.

use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Sender};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use kovanica_dag::BlockId;
use kovanica_node::relay::{
    decode_msg, encode_msg, handle_relay_query, RelayMsg, RelaySession, MAX_FRAME, MAX_HEADERS,
    MAX_LOCATOR_IDS, MAX_MERKLE_PATH, TAG_GETHEADERS, TAG_HEADERS, TAG_MERKLEBLOCK,
};
use kovanica_node::{sync_headers_via_relay, verify_merkle_block, BlockRecord, Node};
use kovanica_state::spv::{
    generate_merkle_proof, merkle_root, BlockHeader as SpvHeader, MerkleProof, SpvClient,
};
use kovanica_state::{KeyPair, OutPoint, Transaction, TxId, TxOutput};

fn dummy_tx(seed: u64, amount: u64) -> Transaction {
    let kp = KeyPair::from_u64(seed);
    let op = OutPoint::new(TxId::from_bytes([seed as u8; 32]), 0);
    Transaction::signed(
        &[(op, &kp)],
        vec![TxOutput::new(amount, KeyPair::from_u64(seed + 1).address())],
        vec![],
    )
}

fn sample_messages() -> Vec<RelayMsg> {
    let genesis_hdr = SpvHeader {
        id: BlockId::from_bytes([1u8; 32]),
        prev_hash: BlockId::from_bytes([0u8; 32]),
        merkle_root: [2u8; 32],
        work: 10,
        timestamp_ms: 1000,
        nonce: 42,
        blue_score: 1,
        chain_blue_work: 10,
        height: 0,
    };

    let sample_tx = dummy_tx(1, 100);

    vec![
        RelayMsg::Hello {
            from: "node-alpha".into(),
            advertised: vec!["node-beta".into(), "node-gamma".into()],
        },
        RelayMsg::Block(BlockRecord {
            parents: vec![BlockId::from_bytes([0xBB; 32])],
            work: 5,
            timestamp_ms: 2000,
            nonce: 12345,
            vrf: None,
            txs: vec![sample_tx.clone()],
        }),
        RelayMsg::Tx(sample_tx.clone()),
        RelayMsg::GetHeaders {
            locator: vec![
                BlockId::from_bytes([3u8; 32]),
                BlockId::from_bytes([4u8; 32]),
            ],
            stop_hash: Some(BlockId::from_bytes([5u8; 32])),
            max_count: 500,
        },
        RelayMsg::GetHeaders {
            locator: vec![BlockId::from_bytes([6u8; 32])],
            stop_hash: None,
            max_count: 0,
        },
        RelayMsg::Headers {
            headers: vec![genesis_hdr.clone()],
        },
        RelayMsg::GetBlocks {
            locator: vec![BlockId::from_bytes([7u8; 32])],
            stop_hash: Some(BlockId::from_bytes([8u8; 32])),
        },
        RelayMsg::GetMerkleProof {
            block_id: BlockId::from_bytes([9u8; 32]),
            tx_id: sample_tx.id(),
        },
        RelayMsg::MerkleBlock {
            block_id: BlockId::from_bytes([10u8; 32]),
            merkle_root: [0xCC; 32],
            tx_count: 1,
            proof: Some(MerkleProof {
                tx_id: *sample_tx.id().as_bytes(),
                merkle_root: [0xCC; 32],
                path: vec![[0xDD; 32], [0xEE; 32]],
                index: 0,
                tx_count: 1,
            }),
            matched_tx: Some(sample_tx),
        },
        RelayMsg::MerkleBlock {
            block_id: BlockId::from_bytes([11u8; 32]),
            merkle_root: [0; 32],
            tx_count: 0,
            proof: None,
            matched_tx: None,
        },
    ]
}

#[test]
fn test_wire_framing_fuzzing_and_truncation() {
    let samples = sample_messages();

    // 1. Basic round-trip for all sample variants
    for msg in &samples {
        let encoded = encode_msg(msg);
        let decoded = decode_msg(&encoded).expect("valid message must decode");
        assert_eq!(msg, &decoded);
    }

    // 2. Empty slice check
    assert!(decode_msg(&[]).is_err());

    // 3. Byte-by-byte truncation on every sample message
    for (idx, msg) in samples.iter().enumerate() {
        let encoded = encode_msg(msg);
        for len in 0..encoded.len() {
            let truncated = &encoded[..len];
            let res = decode_msg(truncated);
            assert!(
                res.is_err(),
                "Truncated message #{} at len {}/{} unexpectedly succeeded: {:?}",
                idx,
                len,
                encoded.len(),
                res
            );
        }
    }

    // 4. Trailing garbage on every sample message
    for (idx, msg) in samples.iter().enumerate() {
        let encoded = encode_msg(msg);
        for garbage_len in [1, 2, 5, 32, 100] {
            let mut corrupted = encoded.clone();
            corrupted.extend(vec![0xAA; garbage_len]);
            let res = decode_msg(&corrupted);
            assert!(
                res.is_err(),
                "Message #{} with {} trailing garbage bytes unexpectedly succeeded: {:?}",
                idx,
                garbage_len,
                res
            );
        }
    }

    // 5. Unknown / corrupt tags
    for tag in [0x03, 0x04, 0x10, 0x14, 0x17, 0x7F, 0xFF] {
        let buf = vec![tag, 0x00, 0x00, 0x00];
        assert!(decode_msg(&buf).is_err());
    }

    // 6. Framing bounds violations
    // A. locator count > MAX_LOCATOR_IDS (1000)
    {
        let mut buf = vec![TAG_GETHEADERS];
        let oversized_count = (MAX_LOCATOR_IDS + 1) as u64;
        buf.extend_from_slice(&oversized_count.to_le_bytes());
        for _ in 0..oversized_count {
            buf.extend_from_slice(&[0u8; 32]);
        }
        buf.push(0u8); // no stop
        buf.extend_from_slice(&100u32.to_le_bytes());
        let res = decode_msg(&buf);
        assert!(res.is_err());
    }

    // B. headers count > MAX_HEADERS (10000)
    {
        let mut buf = vec![TAG_HEADERS];
        let oversized_count = (MAX_HEADERS + 1) as u64;
        buf.extend_from_slice(&oversized_count.to_le_bytes());
        for _ in 0..oversized_count {
            buf.extend_from_slice(&[0u8; 160]);
        }
        let res = decode_msg(&buf);
        assert!(res.is_err());
    }

    // C. merkle path count > MAX_MERKLE_PATH (64)
    {
        let mut buf = vec![TAG_MERKLEBLOCK];
        buf.extend_from_slice(&[1u8; 32]); // block_id
        buf.extend_from_slice(&[2u8; 32]); // merkle_root
        buf.extend_from_slice(&1u32.to_le_bytes()); // tx_count
        buf.push(1u8); // has_proof = true
        buf.extend_from_slice(&[3u8; 32]); // tx_id
        buf.extend_from_slice(&[2u8; 32]); // proof_merkle_root
        let oversized_path_len = (MAX_MERKLE_PATH + 1) as u64;
        buf.extend_from_slice(&oversized_path_len.to_le_bytes());
        for _ in 0..oversized_path_len {
            buf.extend_from_slice(&[4u8; 32]);
        }
        buf.extend_from_slice(&0u64.to_le_bytes()); // index
        buf.extend_from_slice(&1u64.to_le_bytes()); // proof_tx_count
        buf.push(0u8); // has_matched_tx = false
        let res = decode_msg(&buf);
        assert!(res.is_err());
    }

    // D. Invalid boolean / flag values
    {
        // GetHeaders has_stop = 2
        let mut buf = vec![TAG_GETHEADERS];
        buf.extend_from_slice(&0u64.to_le_bytes());
        buf.push(2u8);
        buf.extend_from_slice(&0u32.to_le_bytes());
        assert!(decode_msg(&buf).is_err());

        // MerkleBlock has_proof = 2
        let mut buf = vec![TAG_MERKLEBLOCK];
        buf.extend_from_slice(&[0u8; 32]);
        buf.extend_from_slice(&[0u8; 32]);
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.push(2u8);
        assert!(decode_msg(&buf).is_err());

        // MerkleBlock has_matched_tx = 2
        let mut buf = vec![TAG_MERKLEBLOCK];
        buf.extend_from_slice(&[0u8; 32]);
        buf.extend_from_slice(&[0u8; 32]);
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.push(0u8); // has_proof = false
        buf.push(2u8); // has_matched_tx = 2 (invalid)
        assert!(decode_msg(&buf).is_err());
    }

    // 7. Pseudo-random payload fuzzing (20,000 iterations without panicking)
    let mut rng_state = 0x123456789ABCDEF0u64;
    let mut next_u64 = || {
        rng_state = rng_state.wrapping_mul(6364136223846793005).wrapping_add(1);
        rng_state
    };

    for _ in 0..20_000 {
        let len = (next_u64() % 512) as usize;
        let mut fuzz_bytes = Vec::with_capacity(len);
        for _ in 0..len {
            fuzz_bytes.push((next_u64() & 0xFF) as u8);
        }
        // decode_msg must never panic
        let _ = decode_msg(&fuzz_bytes);
    }
}

#[test]
fn test_adversarial_merkle_proof_verification() {
    let leaf_counts = [1, 2, 4, 8, 16, 32, 64];

    for &count in &leaf_counts {
        let txs: Vec<Transaction> = (0..count)
            .map(|i| dummy_tx(i as u64 + 100, (i + 1) as u64 * 10))
            .collect();
        let root = merkle_root(&txs);

        for index in 0..count {
            let proof = generate_merkle_proof(&txs, index)
                .expect("proof generation must succeed for valid index");

            assert_eq!(proof.merkle_root, root);
            assert_eq!(proof.index, index);
            assert_eq!(proof.tx_count, count);
            assert!(proof.verify(), "Valid proof must verify");

            // Attack 1: Mutate tx_id (single bit flip across all 32 bytes)
            for byte_idx in 0..32 {
                for bit in 0..8 {
                    let mut bad_proof = proof.clone();
                    bad_proof.tx_id[byte_idx] ^= 1 << bit;
                    assert!(
                        !bad_proof.verify(),
                        "Proof with bit flip at tx_id byte {} bit {} must fail",
                        byte_idx,
                        bit
                    );
                }
            }

            // Attack 2: Mutate merkle_root (single bit flip)
            for byte_idx in 0..32 {
                let mut bad_proof = proof.clone();
                bad_proof.merkle_root[byte_idx] ^= 0x01;
                assert!(
                    !bad_proof.verify(),
                    "Proof with altered merkle_root must fail"
                );
            }

            // Attack 3: Mutate sibling path elements
            for (sibling_idx, _) in proof.path.iter().enumerate() {
                let mut bad_proof = proof.clone();
                bad_proof.path[sibling_idx][0] ^= 0xFF;
                assert!(
                    !bad_proof.verify(),
                    "Proof with corrupted sibling at depth {} must fail",
                    sibling_idx
                );
            }

            // Attack 4: Mutate leaf index bits (flip least-significant bit for even counts)
            if count > 1 {
                let mut bad_proof = proof.clone();
                bad_proof.index = index ^ 1;
                assert!(
                    !bad_proof.verify(),
                    "Proof with flipped index {} -> {} must fail",
                    index,
                    bad_proof.index
                );
            }

            // Attack 5: Truncate or extend sibling path
            if !proof.path.is_empty() {
                let mut truncated = proof.clone();
                truncated.path.pop();
                assert!(!truncated.verify(), "Proof with truncated path must fail");

                let mut extended = proof.clone();
                extended.path.push([0x42; 32]);
                assert!(
                    !extended.verify(),
                    "Proof with extra sibling in path must fail"
                );
            }
        }

        // Out-of-bounds proof generation returns None
        assert!(generate_merkle_proof(&txs, count).is_none());
        assert!(generate_merkle_proof(&txs, count + 10).is_none());
    }
}

#[test]
fn test_merkle_odd_leaf_count_and_index_bounds_analysis() {
    // Test odd leaf count (e.g. 3 leaves, where leaf 2 is duplicated)
    let txs: Vec<Transaction> = (0..3)
        .map(|i| dummy_tx(i as u64 + 500, (i + 1) as u64 * 100))
        .collect();
    let root = merkle_root(&txs);

    let proof0 = generate_merkle_proof(&txs, 0).unwrap();
    let proof1 = generate_merkle_proof(&txs, 1).unwrap();
    let proof2 = generate_merkle_proof(&txs, 2).unwrap();

    assert_eq!(proof0.merkle_root, root);
    assert_eq!(proof1.merkle_root, root);
    assert_eq!(proof2.merkle_root, root);
    assert!(proof0.verify());
    assert!(proof1.verify());
    assert!(proof2.verify());

    // In a 3-leaf tree, index 2 has duplicate sibling at level 0 (T2, T2).
    // An adversarial proof with index = 3 evaluates H(T2, T2) identically.
    let mut forged_idx3 = proof2.clone();
    forged_idx3.index = 3;
    // Without upper-bound index validation in MerkleProof::verify, forged_idx3.verify() returns true
    // This empirically proves that MerkleProof::verify only validates path arithmetic,
    // and higher-level verifiers must enforce proof.index < proof.tx_count.
    assert!(forged_idx3.verify());
}

#[test]
fn test_cross_block_merkle_forgery_and_tampered_payloads() {
    let mut node = Node::new();
    node.set_now_ms(1000);
    node.genesis(3, 1000, 1000, 1).unwrap();

    let gen_id = node.genesis_id().unwrap();
    let gen_hdr = node.spv_header(&gen_id).unwrap();
    let mut spv_client = SpvClient::new(gen_hdr, false, None);

    // Block 1 with TX 1
    node.set_now_ms(2000);
    let sent1 = node.send(1, 100, 2).unwrap();
    let hdr1 = node.spv_header(&sent1.block).unwrap();
    spv_client.add_header(hdr1.clone()).unwrap();

    // Block 2 with TX 2
    node.set_now_ms(3000);
    let sent2 = node.send(2, 50, 3).unwrap();
    let hdr2 = node.spv_header(&sent2.block).unwrap();
    spv_client.add_header(hdr2.clone()).unwrap();

    let mb1 = node.merkle_block(&sent1.block, &sent1.tx).unwrap();
    let mb2 = node.merkle_block(&sent2.block, &sent2.tx).unwrap();

    assert!(verify_merkle_block(&spv_client, &mb1).unwrap());
    assert!(verify_merkle_block(&spv_client, &mb2).unwrap());

    // 1. Cross-block attack: TX 1's proof claiming to belong to Block 2
    let mut cross_block_mb = mb1.clone();
    cross_block_mb.block_id = sent2.block;
    // Header for Block 2 has different merkle root, so verification must fail
    assert!(!verify_merkle_block(&spv_client, &cross_block_mb).unwrap());

    // 2. Mismatched matched_tx: TX 2 payload paired with TX 1's proof
    let mut mismatched_tx_mb = mb1.clone();
    mismatched_tx_mb.matched_tx = mb2.matched_tx.clone();
    assert!(!verify_merkle_block(&spv_client, &mismatched_tx_mb).unwrap());

    // 3. Querying non-existent transaction from node returns MerkleBlock with proof=None
    let bogus_tx = TxId::from_bytes([0xEE; 32]);
    let mb_bogus = node.merkle_block(&sent1.block, &bogus_tx).unwrap();
    assert!(mb_bogus.proof.is_none());
    assert!(mb_bogus.matched_tx.is_none());
    // verify_merkle_block on missing proof safely returns Ok(false)
    assert!(!verify_merkle_block(&spv_client, &mb_bogus).unwrap());

    // 4. Querying non-existent block from node returns error
    let bogus_block = BlockId::from_bytes([0xFF; 32]);
    assert!(node.merkle_block(&bogus_block, &sent1.tx).is_err());
}

#[allow(clippy::large_enum_variant)]
enum NodeCmd {
    Query(RelayMsg, Sender<Option<RelayMsg>>),
    Produce(Sender<()>),
    GetGenesisHeader(Sender<SpvHeader>),
}

#[test]
fn test_concurrent_tcp_light_clients_and_high_throughput_load() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let server_addr = listener.local_addr().unwrap();

    let (cmd_tx, cmd_rx) = channel::<NodeCmd>();
    let running = Arc::new(AtomicBool::new(true));

    // 1. Single Node Actor thread owning the Node
    let node_handle = thread::spawn(move || {
        let mut node = Node::new();
        node.set_now_ms(1_000);
        node.genesis(3, 1000, 1000, 1).unwrap();
        let mut block_idx = 0u64;

        while let Ok(cmd) = cmd_rx.recv() {
            match cmd {
                NodeCmd::Query(msg, resp_tx) => {
                    let resp = handle_relay_query(&node, &msg);
                    let _ = resp_tx.send(resp);
                }
                NodeCmd::Produce(ack_tx) => {
                    block_idx += 1;
                    node.set_now_ms(1_000 + block_idx * 1_000);
                    let _ = node.send(1, 10 + block_idx, 2);
                    let _ = ack_tx.send(());
                }
                NodeCmd::GetGenesisHeader(resp_tx) => {
                    let gen_id = node.genesis_id().unwrap();
                    let hdr = node.spv_header(&gen_id).unwrap();
                    let _ = resp_tx.send(hdr);
                }
            }
        }
    });

    // Obtain genesis header from node
    let genesis_hdr = {
        let (tx, rx) = channel();
        cmd_tx.send(NodeCmd::GetGenesisHeader(tx)).unwrap();
        rx.recv().unwrap()
    };

    // 2. Server Acceptor Loop
    let server_running = Arc::clone(&running);
    let server_cmd_tx = cmd_tx.clone();
    let server_listener = listener.try_clone().unwrap();

    let server_handle = thread::spawn(move || {
        while server_running.load(Ordering::Relaxed) {
            if let Ok(mut session) = RelaySession::accept(&server_listener) {
                let session_cmd_tx = server_cmd_tx.clone();
                thread::spawn(move || {
                    let _ = session.set_read_timeout(Some(Duration::from_millis(500)));
                    for _ in 0..10 {
                        match session.recv() {
                            Ok(req) => {
                                let (resp_tx, resp_rx) = channel();
                                if session_cmd_tx.send(NodeCmd::Query(req, resp_tx)).is_err() {
                                    break;
                                }
                                if let Ok(Some(resp)) = resp_rx.recv_timeout(Duration::from_secs(1))
                                {
                                    if session.send(&resp).is_err() {
                                        break;
                                    }
                                }
                            }
                            Err(_) => break,
                        }
                    }
                });
            }
        }
    });

    // 3. Live block producer thread
    let producer_running = Arc::clone(&running);
    let producer_cmd_tx = cmd_tx.clone();
    let producer_handle = thread::spawn(move || {
        for _ in 0..15 {
            if !producer_running.load(Ordering::Relaxed) {
                break;
            }
            let (ack_tx, ack_rx) = channel();
            if producer_cmd_tx.send(NodeCmd::Produce(ack_tx)).is_ok() {
                let _ = ack_rx.recv_timeout(Duration::from_secs(1));
            }
            thread::sleep(Duration::from_millis(20));
        }
    });

    // 4. Spawn 30 concurrent SPV light clients
    let mut client_handles = Vec::new();
    for client_id in 0..30 {
        let g_hdr = genesis_hdr.clone();
        let handle = thread::spawn(move || {
            // Jitter on connect to simulate dynamic bursty traffic
            thread::sleep(Duration::from_millis((client_id % 7) * 15));

            let mut session = match RelaySession::connect(server_addr) {
                Ok(s) => s,
                Err(_) => return,
            };
            let _ = session.set_read_timeout(Some(Duration::from_secs(3)));

            let mut client = SpvClient::new(g_hdr, false, None);

            // Sync headers over TCP
            let _ = sync_headers_via_relay(&mut session, &mut client, None);

            // If headers were synced, query Merkle proof
            if let Some(tip) = client.tip() {
                let req = RelayMsg::GetMerkleProof {
                    block_id: tip.id,
                    tx_id: TxId::from_bytes([0; 32]), // query non-existent tx
                };
                let _ = session.send(&req);
            }
        });
        client_handles.push(handle);
    }

    // 5. Spawn 5 Byzantine / Fuzzing clients sending malformed TCP payloads
    let mut byzantine_handles = Vec::new();
    for _ in 0..5 {
        let handle = thread::spawn(move || {
            if let Ok(mut stream) = std::net::TcpStream::connect(server_addr) {
                use std::io::Write;
                let bogus_len = (MAX_FRAME as u32 + 100).to_le_bytes();
                let _ = stream.write_all(&bogus_len);
                let _ = stream.write_all(&[0xFF; 20]);
                let _ = stream.flush();
            }
        });
        byzantine_handles.push(handle);
    }

    // Wait for all client and Byzantine threads to finish
    for h in client_handles {
        let _ = h.join();
    }
    for h in byzantine_handles {
        let _ = h.join();
    }

    // Stop background producer and server
    running.store(false, Ordering::Relaxed);
    // Connect one dummy client to wake server accept loop
    let _ = std::net::TcpStream::connect(server_addr);
    let _ = producer_handle.join();
    let _ = server_handle.join();
    drop(cmd_tx);
    let _ = node_handle.join();
}
