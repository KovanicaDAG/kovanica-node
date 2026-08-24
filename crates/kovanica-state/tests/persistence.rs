//! Integration tests for ledger persistence: a [`Ledger`] round-trips through a
//! snapshot by replaying its blocks, so the restored ledger — its DAG, its full
//! state, and every block's view state — is identical to the original.

use kovanica_state::{
    Address, HalvingSchedule, KeyPair, Ledger, LedgerCheckpointError, LedgerSnapshotError,
    OutPoint, Transaction, TxOutput, UtxoSet, DEFAULT_HALVING_ERA,
};

const K: u16 = 3;
const SUBSIDY: u64 = 1_000;
const SCHEDULE: HalvingSchedule = HalvingSchedule::new(SUBSIDY, DEFAULT_HALVING_ERA);

fn snapshot(utxo: &UtxoSet) -> Vec<(OutPoint, u64, Address)> {
    let mut rows: Vec<(OutPoint, u64, Address)> =
        utxo.iter().map(|(op, o)| (*op, o.value, o.owner)).collect();
    rows.sort_by_key(|row| row.0);
    rows
}

/// Build a non-trivial ledger: a chain, a parallel side block, and a merge.
fn build_ledger() -> Ledger {
    let alice = KeyPair::from_u64(1);
    let bob = KeyPair::from_u64(2);
    let carol = KeyPair::from_u64(3);

    let coinbase = Transaction::coinbase(
        vec![TxOutput::new(500, alice.address())],
        b"genesis".to_vec(),
    );
    let coin = OutPoint::new(coinbase.id(), 0);
    let mut ledger = Ledger::new(K, SCHEDULE, &[coinbase]).unwrap();
    let genesis = ledger.genesis();

    // alice → bob (300) with 200 change back to alice.
    let a_to_b = Transaction::signed(
        &[(coin, &alice)],
        vec![
            TxOutput::new(300, bob.address()),
            TxOutput::new(200, alice.address()),
        ],
        Vec::new(),
    );
    let bob_coin = OutPoint::new(a_to_b.id(), 0);
    let alice_change = OutPoint::new(a_to_b.id(), 1);
    let b1 = ledger.insert(vec![genesis], 1, 0, 0, &[a_to_b]).unwrap();

    // bob → carol (300) on b1.
    let b_to_c = Transaction::signed(
        &[(bob_coin, &bob)],
        vec![TxOutput::new(300, carol.address())],
        Vec::new(),
    );
    let b2 = ledger.insert(vec![b1], 1, 0, 0, &[b_to_c]).unwrap();

    // Parallel side block off b1: alice spends her change to carol.
    let side = Transaction::signed(
        &[(alice_change, &alice)],
        vec![TxOutput::new(200, carol.address())],
        b"side".to_vec(),
    );
    let side_block = ledger.insert(vec![b1], 1, 0, 0, &[side]).unwrap();

    // Merge the two tips (heavier work to make the merge the selected tip).
    ledger.insert(vec![b2, side_block], 5, 0, 0, &[]).unwrap();
    ledger
}

#[test]
fn ledger_roundtrips_through_a_snapshot() {
    let ledger = build_ledger();
    let bytes = ledger.write_snapshot();
    let restored = Ledger::read_snapshot(&bytes).expect("snapshot decodes");

    // Same DAG shape and order.
    assert_eq!(restored.dag().linearize(), ledger.dag().linearize());
    assert_eq!(restored.dag().tips(), ledger.dag().tips());
    assert_eq!(restored.genesis(), ledger.genesis());
    assert_eq!(restored.subsidy(), ledger.subsidy());

    // Same full ledger state.
    assert_eq!(
        snapshot(&restored.ledger_state()),
        snapshot(&ledger.ledger_state())
    );

    // Same per-block view state for every block.
    for id in ledger.dag().linearize() {
        assert_eq!(
            snapshot(restored.state(&id).unwrap()),
            snapshot(ledger.state(&id).unwrap()),
            "per-block state differs for {id}"
        );
    }
}

#[test]
fn snapshot_is_stable_across_a_second_roundtrip() {
    // Re-serialising a restored ledger yields identical bytes — the format is
    // canonical (blocks in the deterministic linearized order).
    let ledger = build_ledger();
    let bytes1 = ledger.write_snapshot();
    let restored = Ledger::read_snapshot(&bytes1).unwrap();
    let bytes2 = restored.write_snapshot();
    assert_eq!(bytes1, bytes2);
}

#[test]
fn bad_magic_is_rejected() {
    assert!(matches!(
        Ledger::read_snapshot(b"not a ledger snapshot"),
        Err(LedgerSnapshotError::BadMagic)
    ));
}

#[test]
fn truncated_snapshot_is_rejected() {
    let bytes = build_ledger().write_snapshot();
    assert!(Ledger::read_snapshot(&bytes[..bytes.len() - 1]).is_err());
}

/// Build a ledger with finality depth and enough blocks to activate finality.
fn build_ledger_with_finality(finality_depth: u64) -> Ledger {
    let alice = KeyPair::from_u64(1);
    let bob = KeyPair::from_u64(2);
    let carol = KeyPair::from_u64(3);

    let coinbase = Transaction::coinbase(
        vec![TxOutput::new(500, alice.address())],
        b"genesis".to_vec(),
    );
    let coin = OutPoint::new(coinbase.id(), 0);
    let mut ledger = Ledger::with_finality(K, SCHEDULE, &[coinbase], finality_depth).unwrap();
    let genesis = ledger.genesis();

    // Build a chain of blocks to activate finality
    let mut tip = genesis;
    for i in 0..20 {
        let tx = if i == 0 {
            // First block: alice → bob
            let a_to_b = Transaction::signed(
                &[(coin, &alice)],
                vec![
                    TxOutput::new(300, bob.address()),
                    TxOutput::new(200, alice.address()),
                ],
                Vec::new(),
            );
            let _bob_coin = OutPoint::new(a_to_b.id(), 0);
            let _alice_change = OutPoint::new(a_to_b.id(), 1);
            a_to_b
        } else {
            Transaction::coinbase(
                vec![TxOutput::new(SUBSIDY, carol.address())],
                format!("block{i}").into_bytes(),
            )
        };
        tip = ledger.insert(vec![tip], 1, i as u64, 0, &[tx]).unwrap();
    }
    ledger
}

#[test]
fn checkpoint_roundtrips() {
    // Build a ledger with finality depth 3, enough blocks to activate finality
    let ledger = build_ledger_with_finality(3);
    assert!(ledger.finality_score() > 0, "finality should be active");

    // Write checkpoint
    let bytes = ledger.write_checkpoint().expect("checkpoint writes");

    // Read checkpoint
    let restored = Ledger::read_checkpoint(&bytes).expect("checkpoint decodes");

    // The checkpoint only preserves the non-final part of the DAG (checkpoint block
    // + blocks above finality). The final blocks are not in the restored DAG.
    // Check that the restored DAG has the correct tip segment.
    let order = ledger.dag().linearize();
    let finality_score = ledger.finality_score();
    let non_final: Vec<_> = order
        .iter()
        .filter(|id| {
            let gd = ledger.dag().ghostdag(id).unwrap();
            gd.blue_score >= finality_score
        })
        .copied()
        .collect();
    assert_eq!(restored.dag().linearize(), non_final);
    assert_eq!(restored.dag().tips(), ledger.dag().tips());
    // The restored genesis is the checkpoint block, not the original genesis.
    // assert_eq!(restored.genesis(), ledger.genesis()); // Not preserved in checkpoint
    assert_eq!(restored.subsidy(), ledger.subsidy());
    assert_eq!(restored.finality_depth(), ledger.finality_depth());
    assert_eq!(
        restored.payload_pruning_depth(),
        ledger.payload_pruning_depth()
    );

    // Same full ledger state (the UTXO set at the tip)
    assert_eq!(
        snapshot(&restored.ledger_state()),
        snapshot(&ledger.ledger_state())
    );

    // Same per-block view state for every NON-FINAL block
    for id in &non_final {
        assert_eq!(
            snapshot(restored.state(id).unwrap()),
            snapshot(ledger.state(id).unwrap()),
            "per-block state differs for {id}"
        );
    }
}

#[test]
fn checkpoint_is_stable_across_second_roundtrip() {
    let ledger = build_ledger_with_finality(3);
    let bytes1 = ledger.write_checkpoint().unwrap();
    let restored = Ledger::read_checkpoint(&bytes1).unwrap();
    let bytes2 = restored.write_checkpoint().unwrap();
    assert_eq!(bytes1, bytes2);
}

#[test]
fn checkpoint_restored_ledger_accepts_new_blocks() {
    let ledger = build_ledger_with_finality(3);
    let bytes = ledger.write_checkpoint().unwrap();
    let mut restored = Ledger::read_checkpoint(&bytes).unwrap();

    let original_len = restored.dag().linearize().len();

    // The restored ledger should be able to accept new blocks on top of the tip.
    let _alice = KeyPair::from_u64(1);
    let bob = KeyPair::from_u64(2);
    let tip = restored.dag().selected_tip();
    let tx = Transaction::coinbase(
        vec![TxOutput::new(500, bob.address())],
        b"new-block".to_vec(),
    );
    let new_block = restored.insert(vec![tip], 1, 100, 0, &[tx]).unwrap();
    assert_eq!(restored.dag().selected_tip(), new_block);
    assert_eq!(restored.dag().linearize().len(), original_len + 1);
}

#[test]
fn checkpoint_rejects_unbounded_finality() {
    let ledger = build_ledger(); // no finality
    let err = ledger.write_checkpoint().unwrap_err();
    assert!(matches!(err, LedgerCheckpointError::FinalityDisabled));
}

#[test]
fn checkpoint_rejects_insufficient_depth() {
    // Finality depth 100 but only a few blocks
    let alice = KeyPair::from_u64(1);
    let coinbase = Transaction::coinbase(
        vec![TxOutput::new(500, alice.address())],
        b"genesis".to_vec(),
    );
    let mut ledger = Ledger::with_finality(K, SCHEDULE, &[coinbase], 100).unwrap();
    let genesis = ledger.genesis();
    ledger.insert(vec![genesis], 1, 1, 0, &[]).unwrap();
    ledger.insert(vec![genesis], 1, 2, 0, &[]).unwrap();

    let err = ledger.write_checkpoint().unwrap_err();
    assert!(matches!(err, LedgerCheckpointError::FinalityNotActive));
}

#[test]
fn bad_magic_checkpoint_rejected() {
    assert!(matches!(
        Ledger::read_checkpoint(b"not a checkpoint"),
        Err(LedgerCheckpointError::BadMagic)
    ));
}

#[test]
fn truncated_checkpoint_rejected() {
    let ledger = build_ledger_with_finality(3);
    let bytes = ledger.write_checkpoint().unwrap();
    assert!(Ledger::read_checkpoint(&bytes[..bytes.len() - 1]).is_err());
}
