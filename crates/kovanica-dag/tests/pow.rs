//! Consensus enforcement of proof-of-work (`Dag::set_proof_of_work`).
//!
//! The hash-target math is unit-tested in `src/pow.rs`; here we check the
//! *consensus rule* wired into `Dag::insert` — that with PoW enabled a
//! non-genesis block is admitted only if its id meets its `work` target — plus
//! the adversarial cases (an unmined block is rejected), genesis exemption,
//! off-by-default behaviour, and that PoW composes with enforced difficulty.

use kovanica_dag::{meets_target, mine, Block, BlockId, Dag, DagError, Retarget};

/// A work weight high enough that a random nonce almost never meets the target
/// (so an unmined block is easy to construct) yet low enough that mining is
/// cheap (~`WORK` hashes expected).
const WORK: u128 = 256;

/// A PoW-enforcing DAG seeded with a trivially-mined genesis (genesis is exempt).
fn pow_dag() -> (Dag, BlockId) {
    let genesis = Block::genesis(1, 0, 0, b"genesis".to_vec());
    let g = genesis.id();
    let mut dag = Dag::new(3, genesis);
    dag.set_proof_of_work(true);
    (dag, g)
}

/// The first nonce for which `template` does **not** meet its target — an
/// "unmined" block. Exists with overwhelming probability for `WORK` well above 1.
fn unmined_nonce(template: &Block) -> u64 {
    (0u64..)
        .find(|&n| !meets_target(&template.with_nonce(n).id(), template.work()))
        .expect("some nonce fails the target")
}

#[test]
fn a_mined_block_is_accepted_and_an_unmined_one_is_rejected() {
    let (mut dag, g) = pow_dag();
    let template = Block::new(vec![g], WORK, 1, 0, b"b1".to_vec());

    // An unmined block (a nonce whose id does not meet the target) is rejected,
    // and the DAG is left unchanged.
    let bad = template.with_nonce(unmined_nonce(&template));
    let bad_id = bad.id();
    assert_eq!(
        dag.insert(bad),
        Err(DagError::InsufficientProofOfWork {
            id: bad_id,
            work: WORK,
        })
    );
    assert_eq!(dag.len(), 1, "the unmined block was not added");

    // The mined block (same template, winning nonce) is admitted.
    let mined = mine(&template);
    assert!(meets_target(&mined.id(), WORK));
    assert!(dag.insert(mined).is_ok());
    assert_eq!(dag.len(), 2);
}

#[test]
fn genesis_is_exempt_from_proof_of_work() {
    // Genesis carries an unmined nonce and a huge work, yet a PoW-enforcing DAG
    // accepts it: it is the trusted seed, never inserted through `insert`.
    let genesis = Block::genesis(u128::MAX, 0, 0, b"genesis".to_vec());
    let g = genesis.id();
    assert!(!meets_target(&g, u128::MAX), "genesis is not mined");
    let mut dag = Dag::new(3, genesis);
    dag.set_proof_of_work(true);
    assert!(dag.contains(&g));
    assert_eq!(dag.len(), 1);
}

#[test]
fn proof_of_work_is_off_by_default() {
    // Without set_proof_of_work, an unmined block with heavy work is still
    // admitted — exactly as before this feature.
    let genesis = Block::genesis(1, 0, 0, b"genesis".to_vec());
    let g = genesis.id();
    let mut dag = Dag::new(3, genesis);
    assert!(!dag.proof_of_work_enabled());

    let template = Block::new(vec![g], u128::MAX, 1, 0, b"b1".to_vec());
    let unmined = template.with_nonce(unmined_nonce(&template));
    assert!(dag.insert(unmined).is_ok());
}

#[test]
fn verification_and_mining_are_deterministic_across_nodes() {
    // Mining the same template is reproducible (same winning nonce/id), and the
    // resulting block is accepted identically on two independently-built DAGs —
    // PoW is a pure function of the block, so every node agrees.
    let template = Block::new(vec![], WORK, 0, 0, b"probe".to_vec());
    let mined1 = mine(&template);
    let mined2 = mine(&template);
    assert_eq!(mined1.nonce(), mined2.nonce(), "mining is deterministic");
    assert_eq!(mined1.id(), mined2.id());

    let accept_on_fresh_dag = || {
        let genesis = Block::genesis(1, 0, 0, b"genesis".to_vec());
        let g = genesis.id();
        let mut dag = Dag::new(3, genesis);
        dag.set_proof_of_work(true);
        let b = mine(&Block::new(vec![g], WORK, 1, 0, b"b1".to_vec()));
        dag.insert(b).is_ok()
    };
    assert!(accept_on_fresh_dag());
    assert!(accept_on_fresh_dag());
}

#[test]
fn proof_of_work_composes_with_enforced_difficulty() {
    // Enable both: difficulty pins `work` to the target the DAG implies, and PoW
    // requires the block to actually be mined to that work.
    let retarget = Retarget {
        target_interval_ms: 1_000,
        window: 4,
        max_factor: 4,
        min_work: WORK, // first-block target is min_work
    };
    let genesis = Block::genesis(1, 0, 0, b"genesis".to_vec());
    let g = genesis.id();
    let mut dag = Dag::new(3, genesis);
    dag.set_difficulty(retarget);
    dag.set_proof_of_work(true);

    // Correct work (min_work) but unmined → rejected on the PoW rule.
    let template = Block::new(vec![g], WORK, 1_000, 0, b"b1".to_vec());
    let unmined = template.with_nonce(unmined_nonce(&template));
    assert!(matches!(
        dag.insert(unmined),
        Err(DagError::InsufficientProofOfWork { .. })
    ));

    // Correct work AND mined → accepted.
    let mined = mine(&template);
    assert!(dag.insert(mined).is_ok());

    // Wrong work (not the difficulty target) → rejected on the difficulty rule,
    // even if we bothered to mine it.
    let wrong = mine(&Block::new(vec![g], WORK + 1, 1_000, 0, b"b2".to_vec()));
    assert!(matches!(
        dag.insert(wrong),
        Err(DagError::DifficultyMismatch { .. })
    ));
}
