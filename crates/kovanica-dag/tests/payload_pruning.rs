//! Tests for DAG-level payload pruning.

use kovanica_dag::{Block, BlockId, Dag};

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

#[test]
fn payload_pruning_depth_disabled_by_default() {
    let (dag, _) = new_dag(3);
    assert_eq!(dag.payload_pruning_depth(), u64::MAX);
    assert_eq!(dag.payload_pruning_score(), 0);
}

#[test]
fn set_payload_pruning_depth() {
    let (mut dag, _) = new_dag(3);
    dag.set_payload_pruning_depth(5);
    assert_eq!(dag.payload_pruning_depth(), 5);
    // With no blocks beyond genesis, score is 0
    assert_eq!(dag.payload_pruning_score(), 0);
}

#[test]
fn prune_old_payloads_evicts_old_blocks() {
    let (mut dag, genesis) = new_dag(3);
    dag.set_payload_pruning_depth(1); // prune blocks 1+ blue score below tip

    let a = add(&mut dag, &[genesis], "a"); // blue_score 1
    let b = add(&mut dag, &[a], "b"); // blue_score 2, selected tip

    // a should be pruned (blue_score 1 < tip(2) - 1 = 1? No, 1 < 1 is false)
    // Actually threshold = tip.blue_score - depth = 2 - 1 = 1
    // Blocks with blue_score < 1 are pruned. a has blue_score 1, so not pruned.
    // Let's use depth 0 to prune everything below tip.
    dag.set_payload_pruning_depth(0);
    dag.prune_old_payloads();

    // With depth 0, threshold = tip.blue_score - 0 = 2
    // Blocks with blue_score < 2 should be pruned: genesis(0) and a(1)
    // But genesis is never pruned
    assert!(
        !dag.block(&genesis).unwrap().is_pruned(),
        "genesis never pruned"
    );
    assert!(dag.block(&a).unwrap().is_pruned(), "a should be pruned");
    assert!(
        !dag.block(&b).unwrap().is_pruned(),
        "tip should not be pruned"
    );
}

#[test]
fn prune_old_payloads_idempotent() {
    let (mut dag, genesis) = new_dag(3);
    dag.set_payload_pruning_depth(0);

    let a = add(&mut dag, &[genesis], "a");
    let _b = add(&mut dag, &[a], "b");

    dag.prune_old_payloads();
    let a_ptr_before = dag.block(&a).unwrap().payload() as *const [u8];

    // Call again - should be idempotent
    dag.prune_old_payloads();
    let a_ptr_after = dag.block(&a).unwrap().payload() as *const [u8];

    assert_eq!(a_ptr_before, a_ptr_after);
}

#[test]
fn pruned_payloads_do_not_affect_reachability() {
    let (mut dag, genesis) = new_dag(3);
    dag.set_payload_pruning_depth(0);

    let a = add(&mut dag, &[genesis], "a");
    let b = add(&mut dag, &[genesis], "b");
    let _m = add(&mut dag, &[a, b], "m");

    dag.prune_old_payloads();

    // All reachability queries should still work correctly
    assert!(dag.is_ancestor(&genesis, &a));
    assert!(dag.is_ancestor(&genesis, &_m));
    assert!(dag.is_ancestor(&a, &_m));
    assert!(dag.is_ancestor(&b, &_m));
    assert!(!dag.is_ancestor(&a, &b));
    assert!(!dag.is_ancestor(&b, &a));

    // Anticone
    assert!(dag.in_anticone(&a, &b));
    assert!(!dag.in_anticone(&a, &_m));
    assert!(!dag.in_anticone(&b, &_m));
}

#[test]
fn pruned_payloads_do_not_affect_ghostdag_colouring() {
    let (mut dag, genesis) = new_dag(3);
    dag.set_payload_pruning_depth(0);

    let a = add(&mut dag, &[genesis], "a");
    let b = add(&mut dag, &[genesis], "b");
    let m = add(&mut dag, &[a, b], "m");

    dag.prune_old_payloads();

    // GHOSTDAG colouring should be unchanged
    let gd = dag.ghostdag(&m).unwrap();
    assert_eq!(gd.blue_score, 3); // genesis + a + b
    assert!(gd.mergeset_reds.is_empty());
    // mergeset = past(m) \ (past(sp) ∪ {sp}); sp is a or b, so mergeset has 1 element
    assert_eq!(gd.mergeset_blues.len(), 1);
}

#[test]
fn pruned_payloads_do_not_affect_linearization() {
    let (mut dag, genesis) = new_dag(3);
    dag.set_payload_pruning_depth(0);

    let a = add(&mut dag, &[genesis], "a");
    let b = add(&mut dag, &[genesis], "b");
    let _m = add(&mut dag, &[a, b], "m");

    let order_before = dag.linearize();

    dag.prune_old_payloads();

    let order_after = dag.linearize();
    assert_eq!(order_before, order_after);
}

#[test]
fn pruned_blocks_can_still_be_selected_parents() {
    let (mut dag, genesis) = new_dag(3);
    dag.set_payload_pruning_depth(0);

    let a = add(&mut dag, &[genesis], "a"); // pruned
    let b = add(&mut dag, &[genesis], "b"); // pruned
    let m = add(&mut dag, &[a, b], "m"); // tip

    dag.prune_old_payloads();

    // a and b are pruned but their ghostdag data is intact
    assert!(dag.block(&a).unwrap().is_pruned());
    assert!(dag.block(&b).unwrap().is_pruned());

    // The selected parent of m should be one of a or b
    let sp = dag.ghostdag(&m).unwrap().selected_parent.unwrap();
    assert!(sp == a || sp == b);

    // The selected tip should be m
    assert_eq!(dag.selected_tip(), m);
}

#[test]
fn snapshot_preserves_pruned_state() {
    let (mut dag, genesis) = new_dag(3);
    dag.set_payload_pruning_depth(0);

    let a = add(&mut dag, &[genesis], "a");
    let b = add(&mut dag, &[genesis], "b");
    let m = add(&mut dag, &[a, b], "m");

    dag.prune_old_payloads();

    // Verify pruned before snapshot
    assert!(dag.block(&a).unwrap().is_pruned());
    assert!(dag.block(&b).unwrap().is_pruned());
    assert!(!dag.block(&m).unwrap().is_pruned());

    // Snapshot and restore
    let bytes = dag.write_snapshot();
    let restored = Dag::read_snapshot(&bytes).unwrap();

    // Restored DAG should have pruned payloads
    assert!(restored.block(&a).unwrap().is_pruned());
    assert!(restored.block(&b).unwrap().is_pruned());
    assert!(!restored.block(&m).unwrap().is_pruned());

    // All consensus data should match
    assert_eq!(restored.linearize(), dag.linearize());
    assert_eq!(restored.tips(), dag.tips());
    assert_eq!(restored.selected_tip(), dag.selected_tip());

    for id in dag.linearize() {
        let orig = dag.ghostdag(&id).unwrap();
        let rest = restored.ghostdag(&id).unwrap();
        assert_eq!(orig.blue_score, rest.blue_score);
        assert_eq!(orig.blue_work, rest.blue_work);
        assert_eq!(orig.selected_parent, rest.selected_parent);
    }
}

#[test]
fn pruning_depth_changes_dynamically() {
    let (mut dag, genesis) = new_dag(3);

    let a = add(&mut dag, &[genesis], "a");
    let b = add(&mut dag, &[a], "b");
    let c = add(&mut dag, &[b], "c");

    // Initially no pruning
    assert_eq!(dag.payload_pruning_depth(), u64::MAX);
    assert!(!dag.block(&a).unwrap().is_pruned());
    assert!(!dag.block(&b).unwrap().is_pruned());

    // Set depth to 1, prune
    dag.set_payload_pruning_depth(1);
    dag.prune_old_payloads();

    // Tip c has blue_score 3, threshold = 3 - 1 = 2
    // Blocks with blue_score < 2: genesis(0), a(1)
    assert!(!dag.block(&genesis).unwrap().is_pruned());
    assert!(dag.block(&a).unwrap().is_pruned());
    assert!(!dag.block(&b).unwrap().is_pruned()); // blue_score 2, not < 2
    assert!(!dag.block(&c).unwrap().is_pruned());

    // Increase depth to 2 - a is ALREADY pruned (irreversible)
    dag.set_payload_pruning_depth(2);
    dag.prune_old_payloads();

    // a remains pruned (irreversible), threshold = 3 - 2 = 1
    // Blocks with blue_score < 1: only genesis(0), never pruned
    assert!(!dag.block(&genesis).unwrap().is_pruned());
    assert!(dag.block(&a).unwrap().is_pruned()); // already pruned, stays pruned
    assert!(!dag.block(&b).unwrap().is_pruned());
    assert!(!dag.block(&c).unwrap().is_pruned());

    // Decrease depth back to 0
    dag.set_payload_pruning_depth(0);
    dag.prune_old_payloads();

    // Threshold = 3 - 0 = 3
    // b has blue_score 2, now gets pruned too
    assert!(!dag.block(&genesis).unwrap().is_pruned());
    assert!(dag.block(&a).unwrap().is_pruned());
    assert!(dag.block(&b).unwrap().is_pruned());
    assert!(!dag.block(&c).unwrap().is_pruned());
}

#[test]
fn insert_with_pruning_automatically_prunes() {
    let (mut dag, genesis) = new_dag(3);
    dag.set_payload_pruning_depth(0);

    let a = add(&mut dag, &[genesis], "a");
    let b = add(&mut dag, &[a], "b"); // tip

    // After inserting b, a should be automatically pruned
    // (insert calls prune_old_payloads when depth is finite)
    assert!(
        dag.block(&a).unwrap().is_pruned(),
        "a should be pruned after insert of b"
    );
    assert!(
        !dag.block(&b).unwrap().is_pruned(),
        "tip b should not be pruned"
    );
}

#[test]
fn genesis_never_pruned() {
    let (mut dag, genesis) = new_dag(3);
    dag.set_payload_pruning_depth(0);

    let a = add(&mut dag, &[genesis], "a");
    let _b = add(&mut dag, &[a], "b");

    dag.prune_old_payloads();

    assert!(
        !dag.block(&genesis).unwrap().is_pruned(),
        "genesis must never be pruned"
    );
}

#[test]
fn payload_pruning_does_not_affect_block_ids() {
    let (mut dag, genesis) = new_dag(3);
    dag.set_payload_pruning_depth(0);

    let a = add(&mut dag, &[genesis], "a");
    let a_id = a;
    let a_block_before = dag.block(&a).unwrap().clone();
    let id_before = a_block_before.id();

    dag.prune_old_payloads();

    let a_block_after = dag.block(&a).unwrap();
    let id_after = a_block_after.id();

    // Block id should be the same (computed at insert time over original payload)
    assert_eq!(id_before, id_after);
    assert_eq!(a_id, id_after);
}

#[test]
fn pruned_block_payload_returns_empty_slice() {
    let (mut dag, genesis) = new_dag(3);
    dag.set_payload_pruning_depth(0);

    let a = add(&mut dag, &[genesis], "a");
    let _b = add(&mut dag, &[a], "b");

    dag.prune_old_payloads();

    let a_block = dag.block(&a).unwrap();
    assert_eq!(a_block.payload(), &[]);
    assert_eq!(a_block.payload().len(), 0);
    assert!(a_block.is_pruned());
}
