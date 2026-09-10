use criterion::{black_box, criterion_group, criterion_main, Criterion};
use kovanica_dag::{Block, Dag};

fn build_chain(n: usize) -> (Dag, Vec<Block>) {
    let genesis = Block::genesis(1, 0, 0, Vec::new());
    let dag = Dag::new(3, genesis);
    let mut blocks = Vec::with_capacity(n);
    let mut parent = dag.genesis();
    for i in 0..n {
        let block = Block::new(vec![parent], 1, i as u64 + 1, 0, Vec::new());
        parent = block.id();
        blocks.push(block);
    }
    (dag, blocks)
}

fn bench_dag_insert(c: &mut Criterion) {
    c.bench_function("dag_insert_100", |b| {
        b.iter_batched(
            || build_chain(100),
            |(mut dag, blocks)| {
                for block in blocks {
                    let _ = black_box(dag.insert(block));
                }
            },
            criterion::BatchSize::SmallInput,
        )
    });

    c.bench_function("dag_insert_1000", |b| {
        b.iter_batched(
            || build_chain(1000),
            |(mut dag, blocks)| {
                for block in blocks {
                    let _ = black_box(dag.insert(block));
                }
            },
            criterion::BatchSize::SmallInput,
        )
    });
}

criterion_group!(benches, bench_dag_insert);
criterion_main!(benches);
