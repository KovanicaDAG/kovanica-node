//! Criterion benchmarks for the consensus hot paths: `Dag::insert` under
//! multi-parent fan-out (which exercises the reachability oracle, mergeset
//! computation and GHOSTDAG k-cluster colouring on every insert), the
//! selected-parent + mergeset preview path, and whole-DAG linearization.
//!
//! Note on coverage: `compute_ghostdag` and `mergeset_ordered` are
//! `pub(crate)` — there is intentionally no public entry point that runs the
//! k-cluster colouring in isolation. The closest public surfaces are:
//!   * `Dag::insert` — measures the *full* GHOSTDAG path (selected parent,
//!     mergeset, blue/red colouring) *plus* the incremental reachability
//!     oracle update, end to end;
//!   * `Dag::preview` — measures the selected-parent + mergeset half of
//!     `compute_ghostdag` against a prepared DAG, without inserting;
//!   * `Dag::linearize` — the deterministic total order, which recomputes
//!     every block's mergeset via the oracle.
//!
//! `Dag::insert` benches here use a deterministic sliding-window topology:
//! every block references the previous `FANOUT` blocks, so the DAG stays
//! dense (each block's mergeset is non-trivial) and the wide merge pattern
//! also reindexes the reachability oracle's tree intervals.

use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use kovanica_dag::{Block, BlockId, Dag};

/// GHOSTDAG `k` used for all benches (matches the default testnet shape).
const K: u16 = 3;

/// Number of parent references each non-genesis block carries.
const FANOUT: usize = 4;

/// Build `n` blocks (genesis excluded) where block `i` references the previous
/// `FANOUT` blocks (all prior blocks, plus genesis for the very first one).
/// Block ids are content-addressed, so the whole sequence can be pre-built and
/// handed to the benchmark with the DAG only containing genesis.
fn build_blocks(n: usize) -> (Dag, Vec<Block>) {
    let genesis = Block::genesis(1, 0, 0, b"kovanica-genesis".to_vec());
    let genesis_id = genesis.id();
    let dag = Dag::new(K, genesis);
    let mut blocks = Vec::with_capacity(n);
    for i in 0..n {
        let mut parents: Vec<BlockId> = blocks.iter().rev().take(FANOUT).map(Block::id).collect();
        if parents.is_empty() {
            parents.push(genesis_id);
        }
        blocks.push(Block::new(
            parents,
            1,
            i as u64 + 1,
            0,
            format!("b{i}").into_bytes(),
        ));
    }
    (dag, blocks)
}

/// Insert all `blocks` into `dag` (which already holds genesis).
fn insert_all(dag: &mut Dag, blocks: Vec<Block>) {
    for block in blocks {
        black_box(dag.insert(block).expect("bench block is valid"));
    }
}

/// A fully inserted DAG of `n` non-genesis blocks, ready for read-only benches.
fn prepared_dag(n: usize) -> Dag {
    let (mut dag, blocks) = build_blocks(n);
    insert_all(&mut dag, blocks);
    dag
}

fn bench_insert(c: &mut Criterion) {
    for n in [1_000usize, 4_000] {
        c.bench_function(&format!("dag_insert_fanout{FANOUT}_{n}"), |b| {
            b.iter_batched(
                || build_blocks(n),
                |(mut dag, blocks)| insert_all(&mut dag, blocks),
                BatchSize::LargeInput,
            )
        });
    }
}

fn bench_preview_and_linearize(c: &mut Criterion) {
    for n in [1_000usize, 4_000] {
        let dag = prepared_dag(n);

        // `Dag::preview` = selected parent + mergeset (the pre-colouring half
        // of `compute_ghostdag`); it only needs the parents to be present, so
        // the merged block is built over the most recent FANOUT blocks (which
        // is also the largest realistic merge this DAG shape admits).
        let last_blocks: Vec<BlockId> = dag
            .linearize()
            .into_iter()
            .rev()
            .filter(|id| *id != dag.genesis())
            .take(FANOUT)
            .collect();
        let merger = Block::new(last_blocks, 1, n as u64 + 1, 0, b"preview".to_vec());
        c.bench_function(&format!("dag_preview_mergeset_{n}"), |b| {
            b.iter(|| black_box(dag.preview(&merger).expect("tips are present")))
        });

        // Whole-DAG linearization: selected chain walk + per-block mergeset
        // recomputation + tail sort.
        c.bench_function(&format!("dag_linearize_{n}"), |b| {
            b.iter(|| black_box(dag.linearize()))
        });
    }
}

criterion_group!(benches, bench_insert, bench_preview_and_linearize);
criterion_main!(benches);
