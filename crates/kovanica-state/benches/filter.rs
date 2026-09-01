use criterion::{black_box, criterion_group, criterion_main, Criterion};
use kovanica_state::spv::BlockFilter;

fn random_addresses(seed: u64, n: usize) -> Vec<[u8; 32]> {
    let mut out = Vec::with_capacity(n);
    let mut s = seed;
    for _ in 0..n {
        let mut addr = [0u8; 32];
        for b in &mut addr {
            s = s.wrapping_mul(6364136223846793005).wrapping_add(1);
            *b = s as u8;
        }
        out.push(addr);
    }
    out
}

fn bench_filter(c: &mut Criterion) {
    let addrs_100 = random_addresses(1, 100);
    let addrs_1000 = random_addresses(2, 1000);
    let target = addrs_100[50];

    c.bench_function("filter_encode_100", |b| {
        b.iter_batched(
            || addrs_100.clone(),
            |addrs| {
                let f = BlockFilter::from_addresses(&addrs, 8);
                black_box(f);
            },
            criterion::BatchSize::SmallInput,
        )
    });

    c.bench_function("filter_encode_1000", |b| {
        b.iter_batched(
            || addrs_1000.clone(),
            |addrs| {
                let f = BlockFilter::from_addresses(&addrs, 8);
                black_box(f);
            },
            criterion::BatchSize::SmallInput,
        )
    });

    let filter_100 = BlockFilter::from_addresses(&addrs_100, 8);
    c.bench_function("filter_contains_hit_100", |b| {
        b.iter(|| black_box(filter_100.contains(black_box(&target))))
    });

    let filter_1000 = BlockFilter::from_addresses(&addrs_1000, 8);
    let target_1000 = addrs_1000[500];
    c.bench_function("filter_contains_hit_1000", |b| {
        b.iter(|| black_box(filter_1000.contains(black_box(&target_1000))))
    });
}

criterion_group!(benches, bench_filter);
criterion_main!(benches);
