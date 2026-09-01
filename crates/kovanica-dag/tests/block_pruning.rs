//! Tests for DAG-level block pruning (full block eviction).
//!
//! Block pruning evicts entire blocks (payloads *and* consensus metadata) once
//! they are deep enough below the selected tip. The evicted set is
//! `past(P) \ {genesis}` where `P` is the pruning point — the lowest
//! selected-chain block with `blue_score >= selected_tip.blue_score - depth`.

use std::collections::{HashMap, HashSet};

use kovanica_dag::{Block, BlockId, Dag, DagError};

/// Build a DAG with the given `k` and a fixed genesis.
fn new_dag(k: u16) -> (Dag, BlockId) {
    let genesis = Block::genesis(1, 0, 0, b"kovanica-genesis".to_vec());
    let id = genesis.id();
    (Dag::new(k, genesis), id)
}

/// Insert a unit-work block with the given parents and label.
fn add(dag: &mut Dag, parents: &[BlockId], label: &str) -> BlockId {
    dag.insert(Block::new(
        parents.to_vec(),
        1,
        0,
        0,
        label.as_bytes().to_vec(),
    ))
    .expect("insert should succeed")
}

/// Build a pure chain g -> c1 -> ... -> c5.
fn chain5() -> (Dag, BlockId, Vec<BlockId>) {
    let (mut dag, genesis) = new_dag(3);
    let mut chain = Vec::new();
    let mut prev = genesis;
    for i in 1..=5 {
        let id = add(&mut dag, &[prev], &format!("c{i}"));
        chain.push(id);
        prev = id;
    }
    (dag, genesis, chain)
}

/// Record every `is_ancestor` answer among `blocks` (distinct pairs), in a
/// deterministic order.
fn record_ancestry(dag: &Dag, blocks: &[BlockId]) -> Vec<(BlockId, BlockId, bool)> {
    let mut answers = Vec::new();
    for a in blocks {
        for b in blocks {
            if a != b {
                answers.push((*a, *b, dag.is_ancestor(a, b)));
            }
        }
    }
    answers
}

#[test]
fn block_pruning_depth_disabled_by_default() {
    let (dag, genesis) = new_dag(3);
    assert_eq!(dag.block_pruning_depth(), u64::MAX);
    assert_eq!(dag.block_pruning_score(), 0);
    assert_eq!(dag.pruning_point(), genesis);
}

#[test]
fn set_block_pruning_depth() {
    let (mut dag, _) = new_dag(3);
    dag.set_block_pruning_depth(5);
    assert_eq!(dag.block_pruning_depth(), 5);
    // With no blocks beyond genesis, score is 0 and the pruning point is genesis.
    assert_eq!(dag.block_pruning_score(), 0);
    assert_eq!(dag.pruning_point(), dag.genesis());
}

#[test]
fn shallow_dag_prunes_nothing() {
    let (mut dag, genesis) = new_dag(3);
    dag.set_block_pruning_depth(2);
    let a = add(&mut dag, &[genesis], "a");
    let b = add(&mut dag, &[a], "b");
    // threshold = 2 - 2 = 0: nothing is evictable yet.
    assert!(dag.contains(&genesis));
    assert!(dag.contains(&a));
    assert!(dag.contains(&b));
    assert_eq!(dag.pruning_point(), genesis);
}

#[test]
fn prune_old_blocks_evicts_finalized_blocks() {
    let (mut dag, genesis, chain) = chain5();
    let (c1, c2, c3, c4, c5) = (chain[0], chain[1], chain[2], chain[3], chain[4]);

    dag.set_block_pruning_depth(2); // threshold = 5 - 2 = 3, P = c3
    dag.prune_old_blocks();

    // past(c3) \ {genesis} = {c1, c2} evicted.
    assert!(!dag.contains(&c1), "c1 should be evicted");
    assert!(!dag.contains(&c2), "c2 should be evicted");
    assert!(dag.contains(&genesis), "genesis is never evicted");
    assert!(dag.contains(&c3), "the pruning point itself stays");
    assert!(dag.contains(&c4));
    assert!(dag.contains(&c5));
    assert_eq!(dag.len(), 4);

    assert_eq!(dag.pruning_point(), c3);
    assert_eq!(dag.tips(), vec![c5]);
}

#[test]
fn genesis_never_evicted() {
    let (mut dag, genesis, chain) = chain5();
    let (c1, c2, c3, c4, c5) = (chain[0], chain[1], chain[2], chain[3], chain[4]);

    // Depth 0: threshold = tip.blue_score, P = the tip itself. Everything in
    // past(tip) except genesis is evicted.
    dag.set_block_pruning_depth(0);
    dag.prune_old_blocks();

    assert!(dag.contains(&genesis), "genesis must never be evicted");
    assert!(!dag.contains(&c1));
    assert!(!dag.contains(&c2));
    assert!(!dag.contains(&c3));
    assert!(!dag.contains(&c4));
    assert!(dag.contains(&c5), "the tip is not in its own past");
    assert_eq!(dag.len(), 2);
}

#[test]
fn pruning_point_moves_forward() {
    let (mut dag, _, chain) = chain5();
    let (c3, c4, c5) = (chain[2], chain[3], chain[4]);

    dag.set_block_pruning_depth(2);
    dag.prune_old_blocks();
    assert_eq!(dag.pruning_point(), c3);

    // Extend the chain: threshold = 6 - 2 = 4, P moves to c4, and c3 (the old
    // pruning point) is now evicted too.
    let c6 = add(&mut dag, &[c5], "c6");
    assert_eq!(dag.pruning_point(), c4);
    assert!(!dag.contains(&c3), "the old pruning point is now evicted");
    assert!(dag.contains(&c4));
    assert!(dag.contains(&c5));
    assert!(dag.contains(&c6));
}

#[test]
fn insert_with_block_pruning_automatically_prunes() {
    let (mut dag, genesis) = new_dag(3);
    dag.set_block_pruning_depth(2);

    let c1 = add(&mut dag, &[genesis], "c1");
    let c2 = add(&mut dag, &[c1], "c2");
    let c3 = add(&mut dag, &[c2], "c3");
    let c4 = add(&mut dag, &[c3], "c4");
    let c5 = add(&mut dag, &[c4], "c5");

    // After inserting c5, threshold = 3, P = c3: c1 and c2 are evicted
    // automatically at the end of the insert.
    assert!(!dag.contains(&c1), "c1 should be auto-evicted");
    assert!(!dag.contains(&c2), "c2 should be auto-evicted");
    assert!(dag.contains(&c3));
    assert!(dag.contains(&c4));
    assert!(dag.contains(&c5));
}

#[test]
fn prune_old_blocks_is_idempotent() {
    let (mut dag, _, _) = chain5();
    dag.set_block_pruning_depth(2);
    dag.prune_old_blocks();
    let len_after_first = dag.len();
    let order_after_first = dag.linearize();

    dag.prune_old_blocks();
    assert_eq!(dag.len(), len_after_first);
    assert_eq!(dag.linearize(), order_after_first);
}

#[test]
fn oracle_consistency_after_eviction() {
    let (mut dag, genesis, chain) = chain5();
    let (c3, c4, c5) = (chain[2], chain[3], chain[4]);

    // Record answers among the blocks that will remain present.
    let present = [genesis, c3, c4, c5];
    let before = record_ancestry(&dag, &present);

    dag.set_block_pruning_depth(2);
    dag.prune_old_blocks();

    let after = record_ancestry(&dag, &present);
    assert_eq!(
        before, after,
        "reachability answers must be unchanged by eviction"
    );

    // Sanity: the recorded answers are the expected ones.
    assert!(dag.is_ancestor(&genesis, &c3));
    assert!(dag.is_ancestor(&c3, &c4));
    assert!(dag.is_ancestor(&c4, &c5));
    assert!(!dag.is_ancestor(&c5, &c3));
}

#[test]
fn linearization_is_valid_topological_order_after_eviction() {
    let (mut dag, genesis, chain) = chain5();
    let (c1, c2, c3, c4, c5) = (chain[0], chain[1], chain[2], chain[3], chain[4]);

    dag.set_block_pruning_depth(2);
    dag.prune_old_blocks();

    let order = dag.linearize();
    // Exactly the present blocks, no duplicates.
    assert_eq!(order.len(), dag.len());
    let present: HashSet<BlockId> = order.iter().copied().collect();
    assert_eq!(present.len(), order.len(), "no duplicates in the order");
    assert!(present.contains(&genesis));
    assert!(present.contains(&c3));
    assert!(present.contains(&c4));
    assert!(present.contains(&c5));
    assert!(!present.contains(&c1));
    assert!(!present.contains(&c2));

    // Every block appears after all its present parents (evicted parents are
    // absent from the order and skipped).
    let pos: HashMap<BlockId, usize> = order.iter().enumerate().map(|(i, id)| (*id, i)).collect();
    for id in &order {
        let block = dag.block(id).unwrap();
        for parent in block.parents() {
            if let Some(&p) = pos.get(parent) {
                assert!(
                    p < pos[id],
                    "parent {parent} must precede child {id} in the order"
                );
            }
        }
    }

    // The chain scenario's exact order: genesis, then the present chain.
    assert_eq!(order, vec![genesis, c3, c4, c5]);
}

#[test]
fn insert_rejects_builds_on_pruned_history() {
    let (mut dag, genesis, chain) = chain5();
    let (c1, c3, c5) = (chain[0], chain[2], chain[4]);

    dag.set_block_pruning_depth(2);
    dag.prune_old_blocks();

    // Referencing an evicted parent is a missing-parent error.
    let err = dag
        .insert(Block::new(vec![c1], 1, 0, 0, b"x".to_vec()))
        .unwrap_err();
    assert!(
        matches!(err, DagError::MissingParent(id) if id == c1),
        "expected MissingParent(c1), got {err}"
    );

    // Building on genesis (which is in past(P)) is rejected: the selected
    // parent must be in future(P) ∪ {P}.
    let block = Block::new(vec![genesis], 1, 0, 0, b"y".to_vec());
    let id = block.id();
    let err = dag.insert(block).unwrap_err();
    assert!(
        matches!(err, DagError::BuildsOnPrunedHistory { id: got } if got == id),
        "expected BuildsOnPrunedHistory, got {err}"
    );

    // Building on the pruning point itself is accepted (sp == P).
    assert!(dag
        .insert(Block::new(vec![c3], 1, 0, 0, b"z".to_vec()))
        .is_ok());

    // Building on a block in future(P) is accepted (P is an ancestor of sp).
    assert!(dag
        .insert(Block::new(vec![c5], 1, 0, 0, b"w".to_vec()))
        .is_ok());
}

#[test]
fn snapshot_roundtrip_with_pruned_blocks() {
    let (mut dag, genesis, chain) = chain5();
    let (c1, c2, c3, c4, c5) = (chain[0], chain[1], chain[2], chain[3], chain[4]);

    dag.set_block_pruning_depth(2);
    dag.prune_old_blocks();
    assert!(!dag.contains(&c1));
    assert!(!dag.contains(&c2));

    let bytes = dag.write_snapshot();
    let mut restored = Dag::read_snapshot(&bytes).unwrap();

    // The present set is preserved exactly.
    assert_eq!(restored.len(), dag.len());
    assert_eq!(restored.len(), 4);
    assert!(restored.contains(&genesis));
    assert!(restored.contains(&c3));
    assert!(restored.contains(&c4));
    assert!(restored.contains(&c5));
    assert!(!restored.contains(&c1));
    assert!(!restored.contains(&c2));

    // Linearization and tips match (the chain scenario round-trips exactly).
    assert_eq!(restored.linearize(), dag.linearize());
    assert_eq!(restored.tips(), dag.tips());

    // Re-enabling the same pruning depth reproduces the same pruning point.
    restored.set_block_pruning_depth(2);
    assert_eq!(restored.pruning_point(), dag.pruning_point());
    assert_eq!(restored.pruning_point(), c3);

    // The restored DAG accepts the same future blocks.
    assert!(restored
        .insert(Block::new(vec![c5], 1, 0, 0, b"c6".to_vec()))
        .is_ok());
}

#[test]
fn adversarial_wide_fork_pruning() {
    // A DAG with parallel side chains and merges, so eviction crosses mergesets
    // and leaves present blocks with evicted parents.
    let (mut dag, genesis) = new_dag(3);
    let a1 = add(&mut dag, &[genesis], "a1");
    let b1 = add(&mut dag, &[genesis], "b1");
    let a2 = add(&mut dag, &[a1], "a2");
    let m2 = add(&mut dag, &[a2, b1], "m2");
    let a3 = add(&mut dag, &[m2], "a3");
    let b2 = add(&mut dag, &[b1], "b2");
    let a4 = add(&mut dag, &[a3], "a4");
    let m4 = add(&mut dag, &[a4, b2], "m4");
    let a5 = add(&mut dag, &[m4], "a5");

    let all = [genesis, a1, b1, a2, m2, a3, b2, a4, m4, a5];
    let before = record_ancestry(&dag, &all);

    dag.set_block_pruning_depth(2);
    dag.prune_old_blocks();

    // Evicted: past(a4) \ {genesis} = {a1, b1, a2, m2, a3}. b2 is in
    // anticone(a4), so it stays present even though its parent b1 is evicted.
    assert!(!dag.contains(&a1));
    assert!(!dag.contains(&b1));
    assert!(!dag.contains(&a2));
    assert!(!dag.contains(&m2));
    assert!(!dag.contains(&a3));
    assert!(
        dag.contains(&b2),
        "b2 is in anticone(a4): present with an evicted parent"
    );
    assert!(dag.contains(&a4));
    assert!(dag.contains(&m4));
    assert!(dag.contains(&a5));

    // Oracle consistency on the present set: answers are unchanged by eviction.
    let present = [genesis, b2, a4, m4, a5];
    let present_set: HashSet<BlockId> = present.iter().copied().collect();
    let before_present: Vec<(BlockId, BlockId, bool)> = before
        .into_iter()
        .filter(|(a, b, _)| present_set.contains(a) && present_set.contains(b))
        .collect();
    let after = record_ancestry(&dag, &present);
    assert_eq!(
        before_present, after,
        "reachability answers must be unchanged by eviction"
    );

    // A present block with an evicted parent still answers correctly.
    assert!(dag.is_ancestor(&genesis, &b2));
    assert!(dag.is_ancestor(&b2, &m4), "b2 is a parent of m4");
    assert!(dag.is_ancestor(&m4, &a5));
    assert!(!dag.is_ancestor(&b2, &a4), "b2 is in anticone(a4)");
    assert!(!dag.is_ancestor(&a4, &b2));

    // k-cluster invariant: every stored blue anticone size is <= k.
    for id in dag.linearize() {
        let gd = dag.ghostdag(&id).unwrap();
        for size in gd.blue_anticone_sizes.values() {
            assert!(*size <= 3, "blue anticone size {size} exceeds k=3");
        }
    }

    // Linearization is a valid topological order of exactly the present blocks.
    let order = dag.linearize();
    assert_eq!(order.len(), dag.len());
    let pos: HashMap<BlockId, usize> = order.iter().enumerate().map(|(i, id)| (*id, i)).collect();
    for id in &order {
        let block = dag.block(id).unwrap();
        for parent in block.parents() {
            if let Some(&p) = pos.get(parent) {
                assert!(p < pos[id], "parent {parent} must precede child {id}");
            }
        }
    }
}
