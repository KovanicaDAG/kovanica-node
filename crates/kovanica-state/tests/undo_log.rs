//! Integration tests for the undo-log state design.
//!
//! The `Ledger` no longer stores a full UTXO set per block. Instead it keeps a
//! single materialised state at the selected tip plus compact per-block undo
//! deltas, reconstructing any non-final block's view state on demand. These
//! tests prove **consensus neutrality**: every block's reconstructed view state
//! is identical to a from-scratch reference computation over the raw DAG, in
//! particular across the finality boundary where deltas are folded into their
//! children and dropped.

use kovanica_dag::BlockId;
use kovanica_state::{
    apply_block, decode_block_payload, Address, HalvingSchedule, KeyPair, Ledger, OutPoint,
    Transaction, TxOutput, UtxoSet, DEFAULT_HALVING_ERA,
};

const K: u16 = 3;
const SUBSIDY: u64 = 1_000;
const SCHEDULE: HalvingSchedule = HalvingSchedule::new(SUBSIDY, DEFAULT_HALVING_ERA);

/// A ledger with a genesis coinbase minting `funding` to actor 1; returns the
/// ledger and the coinbase outpoint.
fn funded(finality_depth: u64, funding: u64) -> (Ledger, OutPoint) {
    let coinbase = Transaction::coinbase(
        vec![TxOutput::new(funding, KeyPair::from_u64(1).address())],
        b"genesis".to_vec(),
    );
    let coin = OutPoint::new(coinbase.id(), 0);
    let ledger = Ledger::with_finality(K, SCHEDULE, &[coinbase], finality_depth).unwrap();
    (ledger, coin)
}

/// A signed transfer of `value` from `from` (spending `coin`) to `to`, with the
/// remainder returned to `from` as change so no value is burned as fees.
fn transfer(coin: OutPoint, from: &KeyPair, to: &Address, value: u64, funding: u64) -> Transaction {
    let mut outputs = vec![TxOutput::new(value, *to)];
    if funding > value {
        outputs.push(TxOutput::new(funding - value, from.address()));
    }
    Transaction::signed(&[(coin, from)], outputs, Vec::new())
}

/// Reference per-block view state, computed **independently of the undo-log
/// machinery**: walk the selected-parent chain from genesis and apply each
/// block's mergeset transactions (conflicts rejected, as in the ledger) and
/// then its own transactions to a fresh UTXO set.
fn reference_state(ledger: &Ledger, block: &BlockId) -> UtxoSet {
    let dag = ledger.dag();
    let mut chain = vec![*block];
    let mut cur = *block;
    while let Some(sp) = dag.ghostdag(&cur).and_then(|g| g.selected_parent) {
        chain.push(sp);
        cur = sp;
    }
    chain.reverse();

    let mut state = UtxoSet::new();
    for id in &chain {
        let block = dag.block(id).expect("block present");
        // The stored ghostdag carries the same deterministic mergeset order the
        // ledger applied at insert time (blues then reds).
        let gd = dag.ghostdag(id).expect("block has ghostdag data");
        let mergeset = gd.mergeset_blues.iter().chain(&gd.mergeset_reds);
        for merged in mergeset {
            let payload = dag.block(merged).expect("mergeset block present").payload();
            if let Ok(txs) = decode_block_payload(payload) {
                // A merged block that conflicts in this view simply does not
                // apply — mirrors the ledger's per-block reject.
                let _ = apply_block(&mut state, &txs, SUBSIDY);
            }
        }
        let payload = block.payload();
        let txs = decode_block_payload(payload).expect("valid payload");
        apply_block(&mut state, &txs, SUBSIDY).expect("valid in its own view");
    }
    state
}

/// Order-independent snapshot of a UTXO set for equality checks.
fn snapshot(utxo: &UtxoSet) -> Vec<(OutPoint, u64, Address)> {
    let mut rows: Vec<(OutPoint, u64, Address)> =
        utxo.iter().map(|(op, o)| (*op, o.value, o.owner)).collect();
    rows.sort_by_key(|row| row.0);
    rows
}

#[test]
fn per_block_states_match_reference_with_finality() {
    // A chain with real transfers, pruned by finality depth 3. Every non-final
    // block's reconstructed state must equal the reference; final blocks are
    // gone (their deltas were folded and dropped).
    let alice = KeyPair::from_u64(1);
    let bob = KeyPair::from_u64(2);
    let carol = KeyPair::from_u64(3);
    let (mut ledger, coin) = funded(3, 500);
    let genesis = ledger.genesis();

    let mut ids = vec![genesis];
    let mut coin = coin;
    let mut owner = alice;
    for i in 0..10 {
        let parent = *ids.last().unwrap();
        let txs = if i == 3 {
            // alice -> bob
            let tx = transfer(coin, &owner, &bob.address(), 200, 500);
            coin = OutPoint::new(tx.id(), 1); // change output back to alice
            vec![tx]
        } else if i == 6 {
            // bob -> carol
            let tx = transfer(coin, &owner, &carol.address(), 100, 300);
            coin = OutPoint::new(tx.id(), 1);
            owner = KeyPair::from_u64(2);
            vec![tx]
        } else {
            vec![]
        };
        ids.push(ledger.insert(vec![parent], 1, 0, 0, &txs).unwrap());
    }

    let threshold = ledger.finality_score();
    assert!(threshold > 0, "finality has kicked in");
    for id in &ids {
        let score = ledger.dag().ghostdag(id).unwrap().blue_score;
        if score < threshold {
            assert!(ledger.state(id).is_none(), "final block {id} pruned");
        } else {
            let got = ledger.state(id).expect("non-final block reconstructs");
            assert_eq!(
                snapshot(&got),
                snapshot(&reference_state(&ledger, id)),
                "state mismatch for block {id} at score {score}"
            );
        }
    }
    // The tip's materialised state agrees with the reference too.
    let tip = ledger.dag().selected_tip();
    assert_eq!(
        snapshot(&ledger.state(&tip).unwrap()),
        snapshot(&reference_state(&ledger, &tip))
    );
}

#[test]
fn folding_preserves_fork_states_across_finality_boundary() {
    // The folding edge case: a side branch forks from a block that is non-final
    // at fork time but becomes final later. The final block's delta is folded
    // into the fork's first block (making it relative to the empty set), so the
    // fork must still reconstruct exactly.
    let alice = KeyPair::from_u64(1);
    let bob = KeyPair::from_u64(2);
    let carol = KeyPair::from_u64(3);
    let (mut ledger, coin) = funded(3, 500);
    let genesis = ledger.genesis();

    // Main chain b1..b10.
    let mut main = vec![genesis];
    for _ in 0..10 {
        let parent = *main.last().unwrap();
        main.push(ledger.insert(vec![parent], 1, 0, 0, &[]).unwrap());
    }
    // Fork from b7 (non-final now: threshold is 7, b7's score is 7).
    let fork_base = main[7];
    let threshold = ledger.finality_score();
    let base_score = ledger.dag().ghostdag(&fork_base).unwrap().blue_score;
    assert!(
        base_score >= threshold,
        "fork base is non-final at fork time"
    );
    let f1 = ledger
        .insert(
            vec![fork_base],
            1,
            0,
            0,
            &[transfer(coin, &alice, &bob.address(), 500, 500)],
        )
        .unwrap();
    let bob_coin = *ledger
        .state(&f1)
        .unwrap()
        .iter()
        .find(|(_, o)| o.owner == bob.address())
        .unwrap()
        .0;
    let f2 = ledger
        .insert(
            vec![f1],
            1,
            0,
            0,
            &[transfer(bob_coin, &bob, &carol.address(), 500, 500)],
        )
        .unwrap();
    let f3 = ledger.insert(vec![f2], 1, 0, 0, &[]).unwrap();

    // Extend the main chain so b7 (the fork's base) becomes final — and with
    // it f1 (score 8) and f2 (score 9). Their deltas are folded up the fork:
    // b7 into f1, f1 into f2, f2 into f3, so f3's delta ends up relative to the
    // empty set.
    let mut tip = *main.last().unwrap();
    for _ in 0..3 {
        tip = ledger.insert(vec![tip], 1, 0, 0, &[]).unwrap();
    }
    let threshold = ledger.finality_score();
    let base_score = ledger.dag().ghostdag(&fork_base).unwrap().blue_score;
    assert!(base_score < threshold, "fork base is final after extension");
    for id in [f1, f2] {
        let score = ledger.dag().ghostdag(&id).unwrap().blue_score;
        assert!(score < threshold, "fork block {id} is final too");
        assert!(ledger.state(&id).is_none(), "final fork block {id} pruned");
    }

    // f3 (score 10) is non-final: its delta accumulated the folded deltas of
    // b7, f1 and f2, so it must reconstruct exactly.
    let f3_score = ledger.dag().ghostdag(&f3).unwrap().blue_score;
    assert!(f3_score >= threshold, "f3 survives the finality boundary");
    let got = ledger.state(&f3).expect("fork block reconstructs");
    assert_eq!(
        snapshot(&got),
        snapshot(&reference_state(&ledger, &f3)),
        "fork block {f3} state mismatch after folding"
    );
    // The main chain above the boundary is unaffected.
    for id in &main {
        if ledger.state(id).is_some() {
            assert_eq!(
                snapshot(&ledger.state(id).unwrap()),
                snapshot(&reference_state(&ledger, id))
            );
        }
    }
}

#[test]
fn mergeset_blocks_reconstruct_correctly() {
    // A block merging two parallel branches: its view state must reflect the
    // mergeset application (the losing branch's conflicting spend is rejected),
    // and the parallel blocks' own states must be unaffected.
    let alice = KeyPair::from_u64(1);
    let bob = KeyPair::from_u64(2);
    let carol = KeyPair::from_u64(3);
    let (mut ledger, coin) = funded(u64::MAX, 500);
    let genesis = ledger.genesis();

    let a = ledger
        .insert(
            vec![genesis],
            1,
            0,
            0,
            &[transfer(coin, &alice, &bob.address(), 500, 500)],
        )
        .unwrap();
    let b = ledger
        .insert(
            vec![genesis],
            1,
            0,
            0,
            &[transfer(coin, &alice, &carol.address(), 500, 500)],
        )
        .unwrap();
    let m = ledger.insert(vec![a, b], 1, 0, 0, &[]).unwrap();

    // The merge's mergeset is non-empty (one of the parallel branches).
    let m_gd = ledger.dag().ghostdag(&m).unwrap();
    assert!(
        !m_gd.mergeset_blues.is_empty() || !m_gd.mergeset_reds.is_empty(),
        "merge block has a non-empty mergeset"
    );

    for id in [a, b, m] {
        let got = ledger.state(&id).expect("block reconstructs");
        assert_eq!(
            snapshot(&got),
            snapshot(&reference_state(&ledger, &id)),
            "state mismatch for block {id}"
        );
    }
    // Exactly one of the parallel spends survives in the merge's view.
    let merged = ledger.state(&m).unwrap();
    assert_eq!(
        merged.balance(&bob.address()) + merged.balance(&carol.address()),
        500
    );
}

#[test]
fn checkpoint_roundtrip_preserves_per_block_states() {
    // A checkpoint restore seeds the ledger with the checkpoint state as a
    // delta relative to the empty set; the restored ledger must reconstruct the
    // same per-block states as the original.
    let alice = KeyPair::from_u64(1);
    let bob = KeyPair::from_u64(2);
    let (mut ledger, coin) = funded(3, 500);
    let genesis = ledger.genesis();
    let mut tip = genesis;
    for i in 0..8 {
        let txs = if i == 4 {
            vec![transfer(coin, &alice, &bob.address(), 500, 500)]
        } else {
            vec![]
        };
        tip = ledger.insert(vec![tip], 1, 0, 0, &txs).unwrap();
    }

    let bytes = ledger.write_checkpoint().expect("checkpoint writes");
    let mut restored = Ledger::read_checkpoint(&bytes).expect("checkpoint restores");

    // The restored ledger holds exactly the tip segment (checkpoint block plus
    // the blocks above the finality boundary), with the same ids. Every one of
    // them must reconstruct identically to the original ledger.
    let restored_ids: Vec<BlockId> = restored.dag().linearize();
    assert!(
        restored_ids.len() >= 2,
        "tip segment has the checkpoint + tail"
    );
    for id in &restored_ids {
        let original = ledger.state(id).expect("original reconstructs");
        let restored_state = restored.state(id).expect("restored reconstructs");
        assert_eq!(
            snapshot(&original),
            snapshot(&restored_state),
            "checkpoint round-trip changed block {id}"
        );
    }
    // And the restored ledger keeps accepting blocks with identical results.
    let next = restored.insert(vec![tip], 1, 0, 0, &[]).unwrap();
    let next_orig = ledger.insert(vec![tip], 1, 0, 0, &[]).unwrap();
    assert_eq!(next, next_orig, "same block id after restore");
    assert_eq!(
        snapshot(&restored.state(&next).unwrap()),
        snapshot(&ledger.state(&next_orig).unwrap())
    );
}
