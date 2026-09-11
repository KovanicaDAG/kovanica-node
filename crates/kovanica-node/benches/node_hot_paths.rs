//! Criterion benchmarks for the node's hot paths.
//!
//! Coverage:
//!   * `mempool_add_*` / `mempool_ordered_pending_*` — `MempoolV2` ingestion
//!     and deterministic assembly ordering (fee-rate computation + id sort).
//!   * `node_produce_block_*` — block assembly over a contested mempool: every
//!     pooled tx spends the same genesis coinbase, so `produce_block` tries the
//!     whole ordered candidate list against the working UTXO set and keeps the
//!     one valid spend (the doublespend-detection hot path a full node runs).
//!   * `net_encode_*` / `net_decode_*` — the gossip wire format
//!     (`encode_records` / `decode_records`) over a synthetic chain of
//!     [`BlockRecord`]s carrying signed single-input transactions.
//!
//! The wire codec is public and pure: `MempoolV2::add`, `encode_records` and
//! `decode_records` are exercised directly rather than through sockets, so the
//! benches measure the codec itself (the TCP framing adds only read/write
//! syscalls on top).

use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use kovanica_dag::Block;
use kovanica_node::net::{decode_records, encode_records};
use kovanica_node::node::{BlockRecord, Node};
use kovanica_node::{MempoolConfig, MempoolV2};
use kovanica_state::{KeyPair, OutPoint, Transaction, TxId, TxOutput, UtxoSet};

/// Value locked into every synthetic funding output; a spend pays out a little
/// less so `fee_with_utxo` / `fee_rate_with_utxo` succeed.
const FUNDING_VALUE: u64 = 1_000_000;

/// Build `n` distinct signed single-input transactions: tx `i` spends outpoint
/// (`txid_i`, 0) and pays `FUNDING_VALUE - 100` back to the same key.
fn make_txs(n: usize) -> Vec<Transaction> {
    let kp = KeyPair::from_u64(1);
    (0..n)
        .map(|i| {
            let mut txid_bytes = [0u8; 32];
            txid_bytes[..8].copy_from_slice(&(i as u64).to_le_bytes());
            let outpoint = OutPoint::new(TxId::from_bytes(txid_bytes), 0);
            Transaction::signed(
                &[(outpoint, &kp)],
                vec![TxOutput::native(FUNDING_VALUE - 100, kp.address())],
                vec![],
            )
        })
        .collect()
}

/// A `UtxoSet` funding every input of `txs`, so [`MempoolV2::add`] can compute
/// fees and accept them as pending.
fn utxo_for(txs: &[Transaction]) -> UtxoSet {
    let kp = KeyPair::from_u64(1);
    let mut utxo = UtxoSet::new();
    for tx in txs {
        utxo.insert(
            tx.inputs()[0].outpoint,
            TxOutput::native(FUNDING_VALUE, kp.address()),
        );
    }
    utxo
}

fn bench_mempool(c: &mut Criterion) {
    for n in [1_000usize, 10_000] {
        // Ingestion: add `n` distinct single-input txs (fee computed against
        // the funding UTXO set). Transactions are rebuilt in setup so signing
        // never lands in the timed loop.
        c.bench_function(&format!("mempool_add_{n}"), |b| {
            b.iter_batched(
                || {
                    let txs = make_txs(n);
                    let utxo = utxo_for(&txs);
                    (MempoolV2::new(MempoolConfig::default()), utxo, txs)
                },
                |(mut pool, utxo, txs)| {
                    for tx in txs {
                        pool.add(tx, &utxo).expect("funded tx enters pending");
                    }
                    black_box(pool.len_pending());
                },
                BatchSize::LargeInput,
            )
        });

        // Assembly ordering: clone + sort the pending pool by id.
        c.bench_function(&format!("mempool_ordered_pending_{n}"), |b| {
            b.iter_batched(
                || {
                    let txs = make_txs(n);
                    let utxo = utxo_for(&txs);
                    let mut pool = MempoolV2::new(MempoolConfig::default());
                    for tx in txs {
                        pool.add(tx, &utxo).expect("funded tx enters pending");
                    }
                    pool
                },
                |pool| black_box(pool.ordered_pending().len()),
                BatchSize::LargeInput,
            )
        });
    }
}

/// A node in the default (PoW, non-hybrid) configuration with genesis minting a
/// small founder coinbase to actor 1, and `n` contested transfers pooled into
/// the mempool: every tx spends the same genesis coinbase, so `produce_block`
/// keeps exactly one (doublespend detection). Recipient seeds are distinct so
/// every tx id is unique while the spends stay mutually conflicting.
fn node_with_contested_pool(n: usize) -> Node {
    let mut node = Node::new();
    node.genesis(3, 1000, 1000, 1).expect("genesis");
    for i in 0..n {
        node.pool(1, 400, 1000 + i as u64).expect("pooled transfer");
    }
    node
}

fn bench_produce_block(c: &mut Criterion) {
    for n in [1_000usize, 10_000] {
        // Block assembly: `produce_block` orders the pooled candidates, applies
        // each against a working UTXO set (only the first double-spend wins),
        // inserts the block, and evicts the losers.
        c.bench_function(&format!("node_produce_block_contested_{n}"), |b| {
            b.iter_batched(
                || node_with_contested_pool(n),
                |mut node| black_box(node.produce_block().expect("produces a block").is_some()),
                BatchSize::LargeInput,
            );
        });
    }
}

/// A synthetic gossip dump: `num_records` blocks in a chain, each carrying
/// `txs_per_record` signed single-input transactions (shared from [`make_txs`]).
fn make_records(num_records: usize, txs_per_record: usize) -> Vec<BlockRecord> {
    let all_txs = make_txs(num_records * txs_per_record);
    let genesis = Block::genesis(1, 0, 0, b"genesis".to_vec());
    let mut parent = genesis.id();
    let mut records = Vec::with_capacity(num_records);
    for i in 0..num_records {
        let txs = all_txs[i * txs_per_record..(i + 1) * txs_per_record].to_vec();
        records.push(BlockRecord {
            parents: vec![parent],
            work: 1,
            timestamp_ms: i as u64 + 1,
            nonce: 0,
            vrf: None,
            txs,
        });
        parent = Block::new(
            vec![parent],
            1,
            i as u64 + 1,
            0,
            format!("b{i}").into_bytes(),
        )
        .id();
    }
    records
}

fn bench_wire_codec(c: &mut Criterion) {
    for (num_records, txs_per_record, label) in [(20usize, 5usize, "20x5"), (100, 10, "100x10")] {
        let records = make_records(num_records, txs_per_record);
        let bytes = encode_records(&records);

        c.bench_function(&format!("net_encode_blocks_{label}"), |b| {
            b.iter(|| black_box(encode_records(&records)))
        });
        c.bench_function(&format!("net_decode_blocks_{label}"), |b| {
            b.iter(|| black_box(decode_records(&bytes).expect("round-trips")))
        });
        // The id of a record is recomputed by peers to match headers.
        c.bench_function(&format!("net_record_ids_{label}"), |b| {
            b.iter(|| {
                for record in &records {
                    black_box(record.id());
                }
            })
        });
    }
}

criterion_group!(
    benches,
    bench_mempool,
    bench_produce_block,
    bench_wire_codec
);
criterion_main!(benches);
