//! Consensus enforcement of difficulty (`Dag::set_difficulty`).
//!
//! These tests exercise the *enforcement* wired into `Dag::insert` — that a
//! non-genesis block must carry exactly the `work` the target its past implies
//! and a timestamp not preceding any parent's. The retargeting *math* itself is
//! unit-tested in `src/difficulty.rs`; here we check the consensus rules built
//! on top of it, including adversarial attempts to understate or overstate work
//! and to backdate a block, and that the target is a deterministic pure function
//! of the DAG (identical on every node).

use kovanica_dag::{Block, BlockId, Dag, DagError, Retarget};

/// A small, hand-computable policy: target 1s, a 2-interval window, ±4× clamp,
/// floor 1. The tiny window keeps the sampled history short enough to trace by
/// hand in the assertions below.
fn small_retarget() -> Retarget {
    Retarget {
        target_interval_ms: 1_000,
        window: 2,
        max_factor: 4,
        min_work: 1,
    }
}

/// A difficulty-enforcing DAG seeded with a genesis at `work = 1`, `ts = 0`.
/// Genesis itself is exempt from the difficulty rules (it has no past).
fn enforcing_dag() -> (Dag, BlockId) {
    let genesis = Block::genesis(1, 0, 0, b"genesis".to_vec());
    let g = genesis.id();
    let mut dag = Dag::new(3, genesis);
    dag.set_difficulty(small_retarget());
    (dag, g)
}

#[test]
fn genesis_work_and_timestamp_are_unconstrained() {
    // Genesis carries arbitrary work/timestamp and is never difficulty-checked;
    // enabling difficulty on the DAG does not reject it.
    let genesis = Block::genesis(999, 12_345, 0, b"genesis".to_vec());
    let g = genesis.id();
    let mut dag = Dag::new(3, genesis);
    dag.set_difficulty(small_retarget());
    assert!(dag.contains(&g));
    assert_eq!(dag.len(), 1);
}

#[test]
fn first_block_must_carry_min_work() {
    let (mut dag, g) = enforcing_dag();

    // With only genesis in history there is no interval to measure, so the
    // target is the floor `min_work` (= 1). Any other work is rejected.
    let wrong = Block::new(vec![g], 5, 500, 0, b"b1".to_vec());
    let id = wrong.id();
    assert_eq!(
        dag.insert(wrong),
        Err(DagError::DifficultyMismatch {
            id,
            expected: 1,
            actual: 5,
        })
    );
    assert_eq!(dag.len(), 1, "the rejected block was not added");

    // The honest target (1) is accepted.
    assert!(dag
        .insert(Block::new(vec![g], 1, 500, 0, b"b1".to_vec()))
        .is_ok());
}

#[test]
fn fast_cadence_raises_the_required_work_and_off_target_is_rejected() {
    let (mut dag, g) = enforcing_dag();
    // b1 arrives 500ms after genesis (twice as fast as the 1s target), at the
    // required work 1.
    let b1 = dag
        .insert(Block::new(vec![g], 1, 500, 0, b"b1".to_vec()))
        .unwrap();

    // For b2 the sampled window is [genesis@0/w1, b1@500/w1]: one 500ms interval
    // against a 1000ms target → work must roughly double, clamped: expected = 2.
    // A miner understating the work (1) is rejected …
    let understated = Block::new(vec![b1], 1, 1_000, 0, b"b2".to_vec());
    let id = understated.id();
    assert_eq!(
        dag.insert(understated),
        Err(DagError::DifficultyMismatch {
            id,
            expected: 2,
            actual: 1,
        })
    );

    // … and so is one overstating it (100).
    let overstated = Block::new(vec![b1], 100, 1_000, 0, b"b2".to_vec());
    let id = overstated.id();
    assert_eq!(
        dag.insert(overstated),
        Err(DagError::DifficultyMismatch {
            id,
            expected: 2,
            actual: 100,
        })
    );

    // Only the exact target (2) is admitted.
    assert!(dag
        .insert(Block::new(vec![b1], 2, 1_000, 0, b"b2".to_vec()))
        .is_ok());
}

#[test]
fn on_target_cadence_holds_work_steady() {
    let (mut dag, g) = enforcing_dag();
    // Blocks exactly one target-interval apart, at the floor work: the measured
    // rate matches the target, so the required work never moves off `min_work`.
    let mut parent = g;
    for i in 1..=6u64 {
        let ts = i * 1_000;
        parent = dag
            .insert(Block::new(
                vec![parent],
                1,
                ts,
                0,
                format!("b{i}").into_bytes(),
            ))
            .unwrap_or_else(|e| panic!("block {i} at steady cadence should be accepted: {e:?}"));
    }
    assert_eq!(dag.len(), 7); // genesis + 6
}

#[test]
fn a_block_may_not_precede_its_parent_in_time() {
    let (mut dag, g) = enforcing_dag();
    let b1 = dag
        .insert(Block::new(vec![g], 1, 500, 0, b"b1".to_vec()))
        .unwrap();

    // b2 carries the correct work (2) but a timestamp earlier than b1's (500).
    // The timestamp rule rejects it regardless of the work being right.
    let backdated = Block::new(vec![b1], 2, 400, 0, b"b2".to_vec());
    let id = backdated.id();
    assert_eq!(
        dag.insert(backdated),
        Err(DagError::NonMonotonicTimestamp {
            id,
            timestamp_ms: 400,
            parent_timestamp_ms: 500,
        })
    );
}

#[test]
fn timestamp_must_not_precede_any_parent_of_a_merge() {
    let (mut dag, g) = enforcing_dag();
    // Two parallel blocks off genesis with different timestamps (both need the
    // first-block target, min_work = 1).
    let a = dag
        .insert(Block::new(vec![g], 1, 500, 0, b"a".to_vec()))
        .unwrap();
    let b = dag
        .insert(Block::new(vec![g], 1, 1_000, 0, b"b".to_vec()))
        .unwrap();

    // A merge timestamped 700ms is >= a (500) but precedes b (1000): rejected,
    // and the reported parent is the one it is older than.
    let merge = Block::new(vec![a, b], 1, 700, 0, b"m".to_vec());
    let id = merge.id();
    assert_eq!(
        dag.insert(merge),
        Err(DagError::NonMonotonicTimestamp {
            id,
            timestamp_ms: 700,
            parent_timestamp_ms: 1_000,
        })
    );
}

#[test]
fn the_target_is_a_deterministic_function_of_the_dag() {
    // Two independently-built DAGs holding the same blocks must compute the same
    // difficulty target — the enforcement is a pure function of the DAG, so every
    // node agrees. We read the target out of the rejection's `expected` field.
    fn build_to_b1() -> (Dag, BlockId) {
        let (mut dag, g) = enforcing_dag();
        let b1 = dag
            .insert(Block::new(vec![g], 1, 500, 0, b"b1".to_vec()))
            .unwrap();
        (dag, b1)
    }

    let expected_from = |dag: &mut Dag, b1: BlockId| -> u128 {
        // Insert a deliberately-wrong-work block and read the target back.
        match dag.insert(Block::new(vec![b1], 999, 1_000, 0, b"probe".to_vec())) {
            Err(DagError::DifficultyMismatch { expected, .. }) => expected,
            other => panic!("expected a DifficultyMismatch, got {other:?}"),
        }
    };

    let (mut d1, b1a) = build_to_b1();
    let (mut d2, b1b) = build_to_b1();
    assert_eq!(b1a, b1b, "same blocks → same ids");
    assert_eq!(expected_from(&mut d1, b1a), expected_from(&mut d2, b1b));
}

#[test]
fn difficulty_off_by_default_accepts_any_work() {
    // Without set_difficulty, work and timestamps are unchecked, exactly as
    // before this feature — a block with arbitrary work and a backdated
    // timestamp is still admitted.
    let genesis = Block::genesis(1, 100, 0, b"genesis".to_vec());
    let g = genesis.id();
    let mut dag = Dag::new(3, genesis);
    assert!(dag.difficulty().is_none());
    assert!(dag
        .insert(Block::new(vec![g], 987_654, 0, 0, b"anything".to_vec()))
        .is_ok());
}
