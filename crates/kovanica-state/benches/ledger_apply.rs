//! Criterion benchmark: ledger apply_block and apply_dag throughput.

use criterion::{criterion_group, criterion_main, Criterion};
use kovanica_dag::{Block, Dag};
use kovanica_state::{
    apply_block, apply_dag, HalvingSchedule, KeyPair, Ledger, Transaction, TxOutput,
};

fn bench_ledger_apply(c: &mut Criterion) {
    let founder = KeyPair::from_u64(1);
    let coinbase = Transaction::coinbase(
        vec![TxOutput::new(1_000_000, founder.address())],
        b"genesis".to_vec(),
    );
    let schedule = HalvingSchedule::new(1_000, 1);
    let ledger = Ledger::new(3, schedule, &[coinbase]).expect("genesis ledger");

    c.bench_function("ledger_apply_block", |bencher| {
        let mut utxo = ledger.ledger_state().clone();
        let mut counter = 0u64;
        bencher.iter(|| {
            let recipient = KeyPair::from_u64(counter + 2);
            let tx = {
                let inputs = utxo
                    .iter()
                    .find(|(_, o)| o.owner == founder.address())
                    .map(|(op, _)| *op)
                    .into_iter()
                    .collect::<Vec<_>>();
                let mut t = Transaction::unsigned(
                    &inputs,
                    vec![TxOutput::new(100, recipient.address())],
                    vec![],
                );
                let sighash = t.sighash();
                for i in 0..t.inputs().len() {
                    t.attach_signature(i, kovanica_state::Sig::from_bytes(founder.sign(&sighash)));
                }
                t
            };
            apply_block(&mut utxo, &[tx], 1_000).expect("apply");
            counter += 1;
        });
    });

    // apply_dag over a pre-built DAG of simple blocks.
    let genesis = Block::genesis(1, 0, 0, b"genesis".to_vec());
    let mut dag = Dag::new(3, genesis);
    let g = dag.genesis();
    let mut tip = g;
    for i in 1..=50 {
        let b = Block::new(vec![tip], 1, i, 0, vec![i as u8]);
        tip = dag.insert(b).expect("insert");
    }

    c.bench_function("ledger_apply_dag_50", |bencher| {
        bencher.iter(|| {
            let _ = apply_dag(&dag, 1_000);
        });
    });
}

criterion_group!(benches, bench_ledger_apply);
criterion_main!(benches);
