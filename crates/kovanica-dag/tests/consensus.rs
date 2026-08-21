//! Integration tests for the GHOSTDAG consensus core: colouring under the
//! k-cluster rule (including an adversarial wide fork), the k-cluster
//! invariant, determinism across insertion order, and topological validity of
//! the linearization.

use std::collections::HashSet;

use kovanica_dag::{Block, BlockId, Dag, DagError};

/// Build a DAG with the given `k` and a fixed genesis.
fn new_dag(k: u16) -> (Dag, BlockId) {
    let genesis = Block::genesis(1, 0, 0, b"kovanica-genesis".to_vec());
    let id = genesis.id();
    (Dag::new(k, genesis), id)
}

/// Insert a unit-work block with the given parents and label.
fn add(dag: &mut Dag, parents: &[BlockId], label: &str) -> BlockId {
    add_w(dag, parents, 1, label)
}

/// Insert a block with an explicit `work` weight.
fn add_w(dag: &mut Dag, parents: &[BlockId], work: u128, label: &str) -> BlockId {
    dag.insert(Block::new(
        parents.to_vec(),
        work,
        0,
        0,
        label.as_bytes().to_vec(),
    ))
    .expect("insert should succeed")
}

/// Assert `order` is a valid topological order of `dag`: every block appears
/// after all of its parents.
fn assert_topological(dag: &Dag, order: &[BlockId]) {
    let mut seen: HashSet<BlockId> = HashSet::new();
    for id in order {
        for parent in dag.block(id).unwrap().parents() {
            assert!(
                seen.contains(parent),
                "block {id} emitted before its parent {parent}"
            );
        }
        seen.insert(*id);
    }
    assert_eq!(
        seen.len(),
        dag.len(),
        "order must cover every block exactly once"
    );
}

/// The k-cluster invariant: for every block, every entry in its blue anticone
/// map is `<= k`, and the map covers exactly `blue_score` blocks.
fn assert_k_cluster_invariant(dag: &Dag, order: &[BlockId]) {
    let k = dag.k();
    for id in order {
        let gd = dag.ghostdag(id).unwrap();
        assert_eq!(
            gd.blue_anticone_sizes.len() as u64,
            gd.blue_score,
            "blue map size must equal blue score for {id}"
        );
        for (&blue, &size) in &gd.blue_anticone_sizes {
            assert!(
                size <= k,
                "blue block {blue} has blue anticone {size} > k={k} in the view of {id}"
            );
        }
    }
}

#[test]
fn genesis_only() {
    let (dag, genesis) = new_dag(3);
    assert_eq!(dag.len(), 1);
    assert_eq!(dag.tips(), vec![genesis]);
    assert_eq!(dag.selected_tip(), genesis);
    assert_eq!(dag.linearize(), vec![genesis]);
    assert_eq!(dag.ghostdag(&genesis).unwrap().blue_score, 0);
}

#[test]
fn linear_chain_increments_blue_score() {
    let (mut dag, genesis) = new_dag(3);
    let a = add(&mut dag, &[genesis], "a");
    let b = add(&mut dag, &[a], "b");
    let c = add(&mut dag, &[b], "c");

    assert_eq!(dag.ghostdag(&a).unwrap().blue_score, 1); // {genesis}
    assert_eq!(dag.ghostdag(&b).unwrap().blue_score, 2); // {genesis, a}
    assert_eq!(dag.ghostdag(&c).unwrap().blue_score, 3); // {genesis, a, b}

    assert_eq!(dag.selected_tip(), c);
    assert_eq!(dag.selected_chain(), vec![genesis, a, b, c]);
    assert_eq!(dag.linearize(), vec![genesis, a, b, c]);
}

#[test]
fn parallel_blocks_merge_all_blue_when_k_large() {
    let (mut dag, genesis) = new_dag(3);
    let a = add(&mut dag, &[genesis], "a");
    let b = add(&mut dag, &[genesis], "b");
    assert!(dag.in_anticone(&a, &b), "a and b are parallel");
    let m = add(&mut dag, &[a, b], "m");

    let gd = dag.ghostdag(&m).unwrap();
    assert_eq!(gd.blue_score, 3, "genesis + a + b are all blue");
    assert!(
        gd.mergeset_reds.is_empty(),
        "nothing is red when k is generous"
    );

    let order = dag.linearize();
    assert_topological(&dag, &order);
    assert_eq!(order[0], genesis);
    assert_eq!(*order.last().unwrap(), m);
}

#[test]
fn k_zero_reds_the_second_parallel_block() {
    // With k = 0 no two blues may be parallel, so a merge of two parallel
    // blocks keeps only its selected parent blue and reds the other.
    let (mut dag, genesis) = new_dag(0);
    let a = add(&mut dag, &[genesis], "a");
    let b = add(&mut dag, &[genesis], "b");
    let m = add(&mut dag, &[a, b], "m");

    let gd = dag.ghostdag(&m).unwrap();
    assert_eq!(
        gd.mergeset_blues.len(),
        0,
        "the non-selected parallel block is red"
    );
    assert_eq!(gd.mergeset_reds.len(), 1);
    assert_eq!(gd.blue_score, 2, "only genesis + selected parent are blue");

    // The selected parent is the heavier-keyed of the two parallel tips.
    let sp = gd.selected_parent.unwrap();
    assert!(sp == a || sp == b);
    assert_eq!(gd.mergeset_reds[0], if sp == a { b } else { a });
}

#[test]
fn adversarial_wide_fork_bounds_blue_set_by_k() {
    // A "wide attacker" mines many blocks in parallel directly off genesis,
    // then a block merges them all. Under the k-cluster rule the blue set can
    // absorb only k of the parallel blocks beyond the selected parent; the rest
    // must be red no matter the insertion order.
    let k = 2u16;
    let (mut dag, genesis) = new_dag(k);

    let parallel: Vec<BlockId> = (0..5)
        .map(|i| add(&mut dag, &[genesis], &format!("w{i}")))
        .collect();
    // All five are mutually parallel.
    for i in 0..parallel.len() {
        for j in (i + 1)..parallel.len() {
            assert!(dag.in_anticone(&parallel[i], &parallel[j]));
        }
    }

    let m = add(&mut dag, &parallel, "merge");
    let gd = dag.ghostdag(&m).unwrap();

    // Blue set = genesis + selected parent + exactly k of the remaining
    // parallel blocks = k + 2 blues; the other (5 - 1 - k) are red.
    assert_eq!(gd.blue_score, u64::from(k) + 2);
    assert_eq!(gd.mergeset_blues.len(), usize::from(k));
    assert_eq!(gd.mergeset_reds.len(), 5 - 1 - usize::from(k));

    let order = dag.linearize();
    assert_topological(&dag, &order);
    assert_k_cluster_invariant(&dag, &order);
}

#[test]
fn linearization_is_deterministic_across_insertion_order() {
    // Build the same logical DAG two ways, inserting the two parallel blocks in
    // opposite order. The resulting consensus data and total order must match.
    let build = |swap: bool| {
        let (mut dag, genesis) = new_dag(3);
        let (a, b) = if swap {
            let b = add(&mut dag, &[genesis], "b");
            let a = add(&mut dag, &[genesis], "a");
            (a, b)
        } else {
            let a = add(&mut dag, &[genesis], "a");
            let b = add(&mut dag, &[genesis], "b");
            (a, b)
        };
        let _m = add(&mut dag, &[a, b], "m");
        dag
    };

    let dag1 = build(false);
    let dag2 = build(true);

    assert_eq!(dag1.selected_tip(), dag2.selected_tip());
    assert_eq!(dag1.linearize(), dag2.linearize());
    // linearize is itself a pure function of the DAG.
    assert_eq!(dag1.linearize(), dag1.linearize());
}

#[test]
fn heavier_branch_wins_selected_chain() {
    // genesis -> a -> a2 (length-2 branch) vs genesis -> b (length-1 branch).
    // The longer/heavier branch's tip is selected.
    let (mut dag, genesis) = new_dag(3);
    let a = add(&mut dag, &[genesis], "a");
    let a2 = add(&mut dag, &[a], "a2");
    let _b = add(&mut dag, &[genesis], "b");

    assert_eq!(dag.selected_tip(), a2);
    assert_eq!(dag.selected_chain(), vec![genesis, a, a2]);
}

#[test]
fn insert_validations() {
    let (mut dag, genesis) = new_dag(3);
    // Duplicate.
    let a_block = Block::new(vec![genesis], 1, 0, 0, b"a".to_vec());
    let a = dag.insert(a_block.clone()).unwrap();
    assert!(dag.insert(a_block).is_err());
    // Missing parent.
    let phantom = Block::genesis(1, 0, 0, b"not-in-dag".to_vec()).id();
    assert!(dag
        .insert(Block::new(vec![phantom], 1, 0, 0, b"x".to_vec()))
        .is_err());
    // Non-genesis with no parents.
    assert!(dag
        .insert(Block::new(vec![], 1, 0, 0, b"y".to_vec()))
        .is_err());
    // Sanity: the one good block is a tip.
    assert_eq!(dag.tips(), vec![a]);
}

#[test]
fn heavier_work_chain_wins_over_longer_light_chain() {
    // blue_work (not blue_score) is the primary chain-selection key. A short,
    // heavy branch must beat a longer branch that has more blocks but less work.
    // With unit work everywhere the two keys move together, so this is the test
    // that actually pins blue_work — and that the fold includes work(sp).
    let (mut dag, genesis) = new_dag(3); // genesis work = 1
    let x1 = add_w(&mut dag, &[genesis], 100, "x1");
    let x2 = add_w(&mut dag, &[x1], 1, "x2");
    let y1 = add_w(&mut dag, &[genesis], 1, "y1");
    let y2 = add_w(&mut dag, &[y1], 1, "y2");
    let y3 = add_w(&mut dag, &[y2], 1, "y3");

    // x2: fewer blue blocks but heavier blue work (genesis 1 + x1 100).
    assert_eq!(dag.ghostdag(&x2).unwrap().blue_score, 2);
    assert_eq!(dag.ghostdag(&x2).unwrap().blue_work, 101);
    // y3: more blue blocks (genesis + y1 + y2) but lighter total work.
    assert_eq!(dag.ghostdag(&y3).unwrap().blue_score, 3);
    assert_eq!(dag.ghostdag(&y3).unwrap().blue_work, 3);

    // Heavier blue work wins even though its chain is shorter.
    assert_eq!(dag.selected_tip(), x2);
    assert_eq!(dag.selected_chain(), vec![genesis, x1, x2]);
}

#[test]
fn blue_anticone_sizes_are_exact() {
    // Two parallel blocks merged: each is in the other's anticone, so within the
    // merge's blue set each records a blue anticone size of exactly 1, and
    // genesis (an ancestor of both) records 0. Pins the seed + increment logic
    // beyond the "<= k" invariant.
    let (mut dag, genesis) = new_dag(3);
    let p = add(&mut dag, &[genesis], "p");
    let q = add(&mut dag, &[genesis], "q");
    let m = add(&mut dag, &[p, q], "m");

    let sizes = &dag.ghostdag(&m).unwrap().blue_anticone_sizes;
    assert_eq!(sizes.len(), 3);
    assert_eq!(sizes[&genesis], 0);
    assert_eq!(sizes[&p], 1);
    assert_eq!(sizes[&q], 1);
}

#[test]
fn selected_parent_tiebreak_is_by_id() {
    // Two parallel blocks with equal blue work and score: the larger id wins
    // the selected-parent tiebreak. Pins the deterministic tiebreak direction.
    let (mut dag, genesis) = new_dag(3);
    let a = add(&mut dag, &[genesis], "a");
    let b = add(&mut dag, &[genesis], "b");
    let m = add(&mut dag, &[a, b], "m");

    let expected = a.max(b);
    assert_eq!(dag.ghostdag(&m).unwrap().selected_parent.unwrap(), expected);
}

#[test]
fn colouring_check_b_reds_candidate_against_saturated_blue() {
    // Isolates GHOSTDAG colouring check (b): a candidate is reddened because an
    // *already-blue* block in its anticone is saturated at k, even though the
    // candidate's own anticone-blue count is within k (so check (a) passes).
    //
    // Build three mutually-parallel blocks off genesis and merge them under
    // k = 2, so each of the three records a blue anticone size of exactly 2 = k.
    let k = 2u16;
    let (mut dag, genesis) = new_dag(k);
    let x = add(&mut dag, &[genesis], "x");
    let y = add(&mut dag, &[genesis], "y");
    let z = add(&mut dag, &[genesis], "z");
    let u = add(&mut dag, &[x, y, z], "u");

    let u_sizes = &dag.ghostdag(&u).unwrap().blue_anticone_sizes;
    for id in [x, y, z] {
        assert_eq!(u_sizes[&id], k, "each parallel block is saturated at k");
    }

    // C merges y and z (so x stays in C's anticone, saturated), then B merges u
    // and C. When B colours C, C's anticone within B's blue set is {x, u}:
    // count 2 = k, so check (a) passes — yet x is saturated, so check (b) reds C.
    let c = add(&mut dag, &[y, z], "c");
    let b = add(&mut dag, &[u, c], "b");
    let gd_b = dag.ghostdag(&b).unwrap();

    let anticone_blues = gd_b
        .blue_anticone_sizes
        .keys()
        .filter(|blue| dag.in_anticone(blue, &c))
        .count();
    assert_eq!(
        anticone_blues,
        usize::from(k),
        "check (a) would have passed"
    );
    assert!(gd_b.mergeset_reds.contains(&c), "check (b) must red C");
    assert!(!gd_b.mergeset_blues.contains(&c));
}

/// Index of `id` within `order` (panics if absent).
fn position(order: &[BlockId], id: BlockId) -> usize {
    order.iter().position(|b| *b == id).expect("block in order")
}

/// Assert the selected chain appears as a subsequence of the linearization:
/// its blocks occur in chain order (they need not be contiguous).
fn assert_selected_chain_is_subsequence(dag: &Dag) {
    let order = dag.linearize();
    let positions: Vec<usize> = dag
        .selected_chain()
        .iter()
        .map(|b| position(&order, *b))
        .collect();
    assert!(
        positions.windows(2).all(|w| w[0] < w[1]),
        "selected chain must appear in order within the linearization: {positions:?}"
    );
}

#[test]
fn recursive_order_lays_selected_chain_before_side_blocks() {
    // genesis → a → p is the heavier (blue_score 2) chain; b hangs off genesis
    // as a side block (blue_score 1). The selected tip is p, so the recursive
    // order emits the whole selected chain [genesis, a, p] first and only then
    // the side block b — unlike a global priority sort, which would place b
    // right after genesis. Pins order(B) = order(sp) ++ mergeset ++ [B].
    let (mut dag, genesis) = new_dag(3);
    let a = add(&mut dag, &[genesis], "a");
    let p = add(&mut dag, &[a], "p");
    let b = add(&mut dag, &[genesis], "b");

    assert_eq!(dag.selected_tip(), p);
    assert_eq!(dag.linearize(), vec![genesis, a, p, b]);
    assert_topological(&dag, &dag.linearize());
}

#[test]
fn recursive_order_places_mergeset_directly_before_its_merger() {
    // A diamond: a and b are parallel off genesis, m merges both. m's selected
    // parent is one of {a, b}; the other is m's mergeset and must be emitted
    // immediately before m (after the selected parent), i.e. order is
    // [genesis, selected_parent, merged, m].
    let (mut dag, genesis) = new_dag(3);
    let a = add(&mut dag, &[genesis], "a");
    let b = add(&mut dag, &[genesis], "b");
    let m = add(&mut dag, &[a, b], "m");

    let sp = dag.ghostdag(&m).unwrap().selected_parent.unwrap();
    let merged = if sp == a { b } else { a };
    assert_eq!(dag.linearize(), vec![genesis, sp, merged, m]);
}

#[test]
fn selected_chain_is_a_subsequence_on_a_wide_fork() {
    // On an adversarial wide fork (many parallel blocks then a merge), the
    // selected chain must still be a subsequence of the linearization.
    let (mut dag, genesis) = new_dag(2);
    let parallel: Vec<BlockId> = (0..6)
        .map(|i| add(&mut dag, &[genesis], &format!("w{i}")))
        .collect();
    let _m = add(&mut dag, &parallel, "merge");

    assert_selected_chain_is_subsequence(&dag);
    assert_topological(&dag, &dag.linearize());
}

#[test]
fn preview_matches_the_block_after_insert() {
    // preview(block) must return the same selected parent and mergeset the block
    // actually gets once inserted — that equivalence is what lets a caller
    // validate a block against its view before committing it.
    let (mut dag, genesis) = new_dag(3);
    let a = add(&mut dag, &[genesis], "a");
    let b = add(&mut dag, &[genesis], "b");

    // A merge of a and b, previewed before it is inserted.
    let m_block = Block::new(vec![a, b], 1, 0, 0, b"m".to_vec());
    let preview = dag.preview(&m_block).unwrap();

    let m = dag.insert(m_block).unwrap();
    let gd = dag.ghostdag(&m).unwrap();
    assert_eq!(preview.selected_parent, gd.selected_parent.unwrap());
    // The previewed mergeset equals the actual mergeset (blues ∪ reds).
    let mut actual: Vec<BlockId> = gd
        .mergeset_blues
        .iter()
        .chain(&gd.mergeset_reds)
        .copied()
        .collect();
    let mut previewed = preview.mergeset.clone();
    actual.sort();
    previewed.sort();
    assert_eq!(previewed, actual);

    // preview mirrors insert's structural checks.
    assert!(matches!(
        dag.preview(&Block::new(vec![], 1, 0, 0, b"x".to_vec())),
        Err(DagError::NoParents(_))
    ));
    let phantom = Block::genesis(1, 0, 0, b"phantom".to_vec()).id();
    assert!(matches!(
        dag.preview(&Block::new(vec![phantom], 1, 0, 0, b"y".to_vec())),
        Err(DagError::MissingParent(_))
    ));
}

#[test]
fn installed_validator_rejects_blocks_at_insert() {
    // A validator that rejects any block whose payload does not start with b'k'.
    // It must run only after the structural DAG checks (parents present), and a
    // rejected block must not be added to the DAG.
    let genesis = Block::genesis(1, 0, 0, b"kovanica-genesis".to_vec());
    let genesis_id = genesis.id();
    let mut dag = Dag::with_validator(
        3,
        genesis,
        Box::new(|block: &Block, _dag: &Dag| {
            if block.payload().first() == Some(&b'k') {
                Ok(())
            } else {
                Err("payload must start with 'k'".to_string())
            }
        }),
    );

    // Accepted: payload starts with 'k'.
    let good = dag
        .insert(Block::new(vec![genesis_id], 1, 0, 0, b"keep".to_vec()))
        .expect("valid block accepted");

    // Rejected by the validator: surfaced as DagError, and not added.
    let before = dag.len();
    let err = dag
        .insert(Block::new(vec![good], 1, 0, 0, b"drop".to_vec()))
        .unwrap_err();
    assert!(
        matches!(err, DagError::InvalidBlock { .. }),
        "validator rejection is an InvalidBlock error, got {err:?}"
    );
    assert_eq!(dag.len(), before, "rejected block was not added");
    assert_eq!(dag.tips(), vec![good], "good block is still the only tip");

    // Structural DAG checks run before the validator: a missing-parent block
    // fails as MissingParent, not InvalidBlock, even though its payload is bad.
    let phantom_id = Block::genesis(1, 0, 0, b"phantom".to_vec()).id();
    let err = dag
        .insert(Block::new(vec![phantom_id], 1, 0, 0, b"drop".to_vec()))
        .unwrap_err();
    assert!(matches!(err, DagError::MissingParent(_)));
}
