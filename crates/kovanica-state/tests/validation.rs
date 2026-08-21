//! Integration tests for block-level structural validation at insert time.
//!
//! With a [`TxStructureValidator`] installed, a `kovanica_dag::Dag` rejects
//! structurally-invalid blocks *when they are inserted* — before they ever
//! reach state application. Stateful invalidity (e.g. a forged signature) is
//! not caught here: it is state-dependent and remains the job of `apply_dag`.

use kovanica_dag::{Block, BlockId, Dag, DagError};
use kovanica_state::{
    apply_dag, encode_block_payload, KeyPair, OutPoint, Transaction, TxOutput, TxStructureValidator,
};

const SUBSIDY: u64 = 1_000;

/// A DAG with the structural validator installed, whose genesis coinbase mints
/// `funding` to `owner`. Returns the DAG, genesis id, and the coinbase outpoint.
fn validated_dag(owner: &KeyPair, funding: u64) -> (Dag, BlockId, OutPoint) {
    let coinbase = Transaction::coinbase(
        vec![TxOutput::new(funding, owner.address())],
        b"genesis".to_vec(),
    );
    let coin = OutPoint::new(coinbase.id(), 0);
    let genesis = Block::genesis(1, 0, 0, encode_block_payload(&[coinbase]));
    let genesis_id = genesis.id();
    let dag = Dag::with_validator(3, genesis, Box::new(TxStructureValidator));
    (dag, genesis_id, coin)
}

#[test]
fn well_formed_blocks_are_accepted_and_apply() {
    let alice = KeyPair::from_u64(1);
    let bob = KeyPair::from_u64(2);
    let (mut dag, genesis, coin) = validated_dag(&alice, 500);

    let pay = Transaction::signed(
        &[(coin, &alice)],
        vec![TxOutput::new(500, bob.address())],
        vec![],
    );
    dag.insert(Block::new(
        vec![genesis],
        1,
        0,
        0,
        encode_block_payload(&[pay]),
    ))
    .expect("a well-formed block passes structural validation at insert");

    let run = apply_dag(&dag, SUBSIDY);
    assert!(run.rejected.is_empty());
    assert_eq!(run.utxo.balance(&bob.address()), 500);
}

#[test]
fn undecodable_payload_is_rejected_at_insert() {
    let alice = KeyPair::from_u64(1);
    let (mut dag, genesis, _coin) = validated_dag(&alice, 500);

    let err = dag
        .insert(Block::new(
            vec![genesis],
            1,
            0,
            0,
            b"not-transactions".to_vec(),
        ))
        .unwrap_err();
    assert!(matches!(err, DagError::InvalidBlock { .. }));
    assert_eq!(
        dag.len(),
        1,
        "only genesis remains; the bad block was not added"
    );
}

#[test]
fn structurally_invalid_transaction_is_rejected_at_insert() {
    let alice = KeyPair::from_u64(1);
    let bob = KeyPair::from_u64(2);
    let (mut dag, genesis, coin) = validated_dag(&alice, 500);

    // A spend that creates a zero-value output — structurally invalid regardless
    // of the UTXO state, so it is caught at insert without applying the DAG.
    let zero_out = Transaction::signed(
        &[(coin, &alice)],
        vec![TxOutput::new(0, bob.address())],
        vec![],
    );
    let err = dag
        .insert(Block::new(
            vec![genesis],
            1,
            0,
            0,
            encode_block_payload(&[zero_out]),
        ))
        .unwrap_err();
    match err {
        DagError::InvalidBlock { reason, .. } => {
            assert!(reason.contains("zero value"), "unexpected reason: {reason}");
        }
        other => panic!("expected InvalidBlock, got {other:?}"),
    }
    assert_eq!(dag.len(), 1);
}

#[test]
fn stateful_invalidity_still_passes_insert_but_is_caught_on_apply() {
    // A forged spend (wrong signer) is structurally well-formed — the signature
    // is the right shape — so it is accepted at insert. Only apply_dag, which
    // has the UTXO state, can see the signature is invalid and reject it.
    let alice = KeyPair::from_u64(1);
    let mallory = KeyPair::from_u64(9);
    let (mut dag, genesis, coin) = validated_dag(&alice, 500);

    let forged = Transaction::signed(
        &[(coin, &mallory)],
        vec![TxOutput::new(500, mallory.address())],
        b"forge".to_vec(),
    );
    let bad = dag
        .insert(Block::new(
            vec![genesis],
            1,
            0,
            0,
            encode_block_payload(&[forged]),
        ))
        .expect("structurally valid: it passes insert-time validation");

    let run = apply_dag(&dag, SUBSIDY);
    assert!(
        run.rejected
            .iter()
            .any(|(id, e)| *id == bad
                && matches!(e, kovanica_state::LedgerError::BadSignature { .. }))
    );
    assert_eq!(run.utxo.balance(&mallory.address()), 0);
}
