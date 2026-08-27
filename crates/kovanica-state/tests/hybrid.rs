//! Integration tests for hybrid PoW / staked-VRF block admission.
//!
//! The hybrid policy (see [`HybridConfig`]) admits a block either by
//! proof-of-work (hash meets target, work pinned to the retargeting policy's
//! implication) or by stake-weighted VRF sortition ([`StakedVrf`]). These tests
//! pin down the admission matrix, the anti-grinding pins, and the
//! identity-preserving snapshot/checkpoint replay of staked blocks.

use kovanica_dag::{
    pow, vrf_keypair_from_seed, vrf_prove, Block, BlockId, Dag, Retarget, VrfOutput, VrfProof,
};
use kovanica_state::stake::{bond_tag, StakeState};
use kovanica_state::{
    encode_block_payload, HalvingSchedule, HybridConfig, KeyPair, Ledger, LedgerInsertError,
    OutPoint, StakedVrf, Transaction, TxOutput, DEFAULT_HALVING_ERA,
};

const K: u16 = 3;
const SUBSIDY: u64 = 1_000;
const SCHEDULE: HalvingSchedule = HalvingSchedule::new(SUBSIDY, DEFAULT_HALVING_ERA);

/// A validator identity: VRF signing key plus the public-key bytes.
struct Validator {
    sk: kovanica_dag::VrfSecretKey,
    pk: [u8; 32],
}

impl Validator {
    fn from_seed(seed: u64) -> Self {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&seed.to_le_bytes());
        let (sk, vk) = vrf_keypair_from_seed(&bytes);
        Self {
            sk,
            pk: *vk.as_bytes(),
        }
    }

    /// The sortition draw over `parents`, as a [`StakedVrf`] bundle.
    fn draw(&self, parents: &[BlockId]) -> StakedVrf {
        let eval = vrf_prove(&self.sk, &Dag::vrf_input(parents));
        StakedVrf {
            vrf_pk: self.pk,
            proof: eval.proof,
            output: eval.output,
        }
    }
}

/// A ledger whose genesis coinbase mints `funding` to a single founder.
fn funded_ledger(funding: u64) -> (Ledger, KeyPair, OutPoint) {
    let founder = KeyPair::from_u64(1);
    let coinbase = Transaction::coinbase(
        vec![TxOutput::new(funding, founder.address())],
        b"genesis".to_vec(),
    );
    let coin = OutPoint::new(coinbase.id(), 0);
    let ledger = Ledger::new(K, SCHEDULE, &[coinbase]).expect("valid genesis");
    (ledger, founder, coin)
}

/// Like [`funded_ledger`] but with an explicit finality depth.
fn funded_finality_ledger(funding: u64, depth: u64) -> (Ledger, KeyPair, OutPoint) {
    let founder = KeyPair::from_u64(1);
    let coinbase = Transaction::coinbase(
        vec![TxOutput::new(funding, founder.address())],
        b"genesis".to_vec(),
    );
    let coin = OutPoint::new(coinbase.id(), 0);
    let ledger = Ledger::with_finality(K, SCHEDULE, &[coinbase], depth).expect("valid genesis");
    (ledger, founder, coin)
}

/// Bond ALL of the founder's supply to `validator`. A bond is a single-output,
/// value-conserving self-pay carrying the bond tag — so bonding everything in
/// one shot is exactly what the shape rule allows.
fn full_bond_tx(
    coin: OutPoint,
    founder: &KeyPair,
    validator: &Validator,
    funding: u64,
) -> Transaction {
    Transaction::signed(
        &[(coin, founder)],
        vec![TxOutput::new(funding, founder.address())],
        bond_tag(&validator.pk),
    )
}

/// Enable hybrid admission with no work pin on the PoW path (tests then mine
/// only against `meets_target`, which is cheap at tiny work values).
fn hybrid_no_pin() -> HybridConfig {
    HybridConfig {
        rate_num: 1,
        rate_den: 1,
        stake_nominal_work: 1,
        retarget: None,
    }
}

#[test]
fn staked_insert_requires_hybrid_mode() {
    let (mut ledger, _founder, _coin) = funded_ledger(500);
    let v = Validator::from_seed(7);
    let parents = ledger.dag().tips();
    let draw = v.draw(&parents);
    let err = ledger.insert_with_vrf(parents, 0, draw, &[]).unwrap_err();
    assert_eq!(err, LedgerInsertError::HybridDisabled);
}

#[test]
fn full_stake_validator_always_wins() {
    let (mut ledger, founder, coin) = funded_ledger(500);
    let v = Validator::from_seed(7);

    // A bond carrying the WHOLE bonded supply makes the threshold u64::MAX, so
    // every possible VRF output wins — deterministic without seed hunting.
    let b1 = ledger
        .insert(
            ledger.dag().tips(),
            1,
            0,
            0,
            &[full_bond_tx(coin, &founder, &v, 500)],
        )
        .unwrap();
    let stake = ledger.stake_state(&b1).unwrap().clone();
    assert_eq!(stake.total_stake(), 500);
    assert_eq!(stake.stake_of(&v.pk), 500);

    ledger.set_hybrid(hybrid_no_pin());

    let parents = ledger.dag().tips();
    let draw = v.draw(&parents);
    let id = ledger
        .insert_with_vrf(parents, 1_000, draw, &[])
        .expect("full-stake validator is always eligible");

    // Nominal-work pin and registry unchanged by the empty staked block.
    assert_eq!(
        ledger.dag().block(&id).unwrap().work(),
        hybrid_no_pin().stake_nominal_work
    );
    assert_eq!(ledger.stake_state(&id).unwrap(), &stake);
}

#[test]
fn zero_stake_never_eligible() {
    let (mut ledger, _founder, _coin) = funded_ledger(500);
    ledger.set_hybrid(hybrid_no_pin());
    let v = Validator::from_seed(3); // never bonded

    let parents = ledger.dag().tips();
    let draw = v.draw(&parents);
    let err = ledger.insert_with_vrf(parents, 0, draw, &[]).unwrap_err();
    match err {
        LedgerInsertError::NotEligible {
            threshold,
            stake,
            total,
            ..
        } => {
            assert_eq!((threshold, stake, total), (0, 0, 0));
        }
        other => panic!("expected NotEligible, got {other:?}"),
    }
}

#[test]
fn half_stake_threshold_is_half_the_output_space() {
    // Threshold arithmetic behind eligibility: 500/1000 at rate 1/1 means
    // exactly half the 64-bit output space (rounded up); full stake is u64::MAX.
    let half = StakeState::eligibility_threshold(500, 1_000, 1, 1);
    assert_eq!(half, (u64::MAX / 2) + 1);
    let full = StakeState::eligibility_threshold(1_000, 1_000, 1, 1);
    assert_eq!(full, u64::MAX);

    // A maximal output beats the half threshold but not full coverage rules.
    let max_out = VrfOutput::from_bytes([0xff; 32]);
    assert!(max_out.as_u64() >= half);
}

#[test]
fn duplicate_staked_sibling_rejected() {
    let (mut ledger, founder, coin) = funded_ledger(500);
    let v = Validator::from_seed(7);
    ledger
        .insert(
            ledger.dag().tips(),
            1,
            0,
            0,
            &[full_bond_tx(coin, &founder, &v, 500)],
        )
        .unwrap();
    ledger.set_hybrid(hybrid_no_pin());

    let parents = ledger.dag().tips();
    let first = v.draw(&parents);
    ledger
        .insert_with_vrf(parents.clone(), 1_000, first, &[])
        .expect("first staked block accepted");
    // Same (key, selected parent): the sibling-spam guard rejects regardless of
    // payload contents or timestamp.
    let second = v.draw(&parents);
    let err = ledger
        .insert_with_vrf(parents, 2_000, second, &[])
        .unwrap_err();
    assert!(matches!(
        err,
        LedgerInsertError::DuplicateStakedBlock { .. }
    ));
}

#[test]
fn pow_path_rejects_unmined_blocks_but_accepts_mined_ones() {
    let (mut ledger, _founder, _coin) = funded_ledger(500);
    ledger.set_hybrid(hybrid_no_pin());

    // Unmined: nonce 0 almost surely misses a nonzero target.
    let err = ledger
        .insert(ledger.dag().tips(), 100, 1_000, 0, &[])
        .unwrap_err();
    assert!(matches!(err, LedgerInsertError::PowTargetNotMet { .. }));

    // Mined at the same claimed work: admitted.
    let template = Block::new(
        ledger.dag().tips(),
        100,
        1_000,
        0,
        encode_block_payload(&[]),
    );
    let mined = pow::mine(&template);
    let id = ledger.insert_prepared_block(mined, &[]).unwrap();
    assert!(ledger.dag().contains(&id));
}

#[test]
fn pow_path_work_is_pinned_to_the_retarget_policy() {
    let cfg = HybridConfig {
        retarget: Some(Retarget::default()),
        ..hybrid_no_pin()
    };
    let (mut ledger, _founder, _coin) = funded_ledger(500);
    ledger.set_hybrid(cfg);

    let parents = ledger.dag().tips();
    let expected = ledger.expected_work(&parents).expect("policy configured");

    // Mine at expected+1: the hash meets its (harder) target but the claimed
    // work is off-policy, so the pin rejects it — not the target check.
    let inflated = pow::mine(&Block::new(
        parents.clone(),
        expected + 1,
        1_000,
        0,
        encode_block_payload(&[]),
    ));
    let err = ledger.insert_prepared_block(inflated, &[]).unwrap_err();
    assert_eq!(
        err,
        LedgerInsertError::WorkTargetMismatch {
            work: expected + 1,
            expected
        }
    );

    // On-policy work mines and inserts cleanly.
    let mined = pow::mine(&Block::new(
        parents,
        expected,
        1_000,
        0,
        encode_block_payload(&[]),
    ));
    ledger.insert_prepared_block(mined, &[]).unwrap();
}

#[test]
fn timestamp_regression_rejected_on_both_paths() {
    let (mut ledger, founder, coin) = funded_ledger(500);
    let v = Validator::from_seed(7);
    ledger.set_hybrid(hybrid_no_pin());

    // Bond first, then give the tip a positive timestamp.
    ledger
        .insert(
            ledger.dag().tips(),
            1,
            0,
            0,
            &[full_bond_tx(coin, &founder, &v, 500)],
        )
        .unwrap();
    let mined = pow::mine(&Block::new(
        ledger.dag().tips(),
        10,
        5_000,
        0,
        encode_block_payload(&[]),
    ));
    ledger.insert_prepared_block(mined, &[]).unwrap();

    // PoW path regression...
    let err = ledger
        .insert(ledger.dag().tips(), 10, 4_999, 0, &[])
        .unwrap_err();
    assert!(matches!(err, LedgerInsertError::TimestampRegression { .. }));

    // ...and staked path regression (eligible producer, too-early clock).
    let parents = ledger.dag().tips();
    let draw = v.draw(&parents);
    let err = ledger.insert_with_vrf(parents, 0, draw, &[]).unwrap_err();
    assert!(matches!(err, LedgerInsertError::TimestampRegression { .. }));
}

#[test]
fn bad_stake_proof_rejected() {
    let (mut ledger, founder, coin) = funded_ledger(500);
    let v = Validator::from_seed(7);
    ledger
        .insert(
            ledger.dag().tips(),
            1,
            0,
            0,
            &[full_bond_tx(coin, &founder, &v, 500)],
        )
        .unwrap();
    ledger.set_hybrid(hybrid_no_pin());

    let parents = ledger.dag().tips();
    let mut draw = v.draw(&parents);
    // Corrupt the serialized proof: it no longer verifies even though the
    // producer's eligibility would pass.
    let mut proof_bytes = draw.proof.to_bytes();
    proof_bytes[0] ^= 0xff;
    draw.proof = VrfProof::from_bytes(&proof_bytes).unwrap();
    let err = ledger
        .insert_with_vrf(parents, 1_000, draw, &[])
        .unwrap_err();
    assert!(matches!(err, LedgerInsertError::BadStakeProof { .. }));
}

#[test]
fn snapshot_roundtrip_preserves_staked_ids() {
    let (mut ledger, founder, coin) = funded_finality_ledger(500, u64::MAX);
    let v = Validator::from_seed(7);
    ledger
        .insert(
            ledger.dag().tips(),
            1,
            0,
            0,
            &[full_bond_tx(coin, &founder, &v, 500)],
        )
        .unwrap();
    ledger.set_hybrid(hybrid_no_pin());

    let mined = pow::mine(&Block::new(
        ledger.dag().tips(),
        10,
        5_000,
        0,
        encode_block_payload(&[]),
    ));
    ledger.insert_prepared_block(mined, &[]).unwrap();
    let parents = ledger.dag().tips();
    let draw = v.draw(&parents);
    let staked = ledger.insert_with_vrf(parents, 6_000, draw, &[]).unwrap();

    let bytes = ledger.write_snapshot();
    let restored = Ledger::read_snapshot_with_hybrid(&bytes, hybrid_no_pin()).unwrap();
    assert!(restored.hybrid_enabled());
    assert!(
        restored.dag().contains(&staked),
        "staked id survived replay"
    );
    let tip_before = ledger
        .stake_state(&ledger.dag().selected_tip())
        .unwrap()
        .clone();
    assert_eq!(
        restored.stake_state(&restored.dag().selected_tip()),
        Some(&tip_before)
    );
}

#[test]
fn checkpoint_roundtrip_preserves_staked_ids() {
    let (mut ledger, founder, coin) = funded_finality_ledger(500, 3);
    let v = Validator::from_seed(7);
    ledger
        .insert(
            ledger.dag().tips(),
            1,
            0,
            0,
            &[full_bond_tx(coin, &founder, &v, 500)],
        )
        .unwrap();
    ledger.set_hybrid(hybrid_no_pin());

    // Grow past finality, then stake near the top so the tip segment (the part
    // replayed from blocks rather than restored as state) includes it.
    for h in 1..=8u64 {
        let mined = pow::mine(&Block::new(
            ledger.dag().tips(),
            10,
            h * 1_000,
            0,
            encode_block_payload(&[]),
        ));
        ledger.insert_prepared_block(mined, &[]).unwrap();
    }
    let parents = ledger.dag().tips();
    let draw = v.draw(&parents);
    let staked = ledger.insert_with_vrf(parents, 20_000, draw, &[]).unwrap();
    let after = pow::mine(&Block::new(
        ledger.dag().tips(),
        10,
        21_000,
        0,
        encode_block_payload(&[]),
    ));
    ledger.insert_prepared_block(after, &[]).unwrap();

    let bytes = ledger.write_checkpoint().unwrap();
    let restored = Ledger::read_checkpoint_with_hybrid(&bytes, hybrid_no_pin()).unwrap();
    assert!(restored.dag().contains(&staked));
    assert_eq!(
        restored.ledger_state().total_value(),
        ledger.ledger_state().total_value()
    );
}

/// The prepared-block path must also admit plain PoW templates built elsewhere
/// (e.g. received over the wire carrying their original identity).
#[test]
fn prepared_pow_block_round_trips_through_insert_prepared() {
    let (mut ledger, _founder, _coin) = funded_ledger(500);
    ledger.set_hybrid(hybrid_no_pin());
    let mined = pow::mine(&Block::new(
        ledger.dag().tips(),
        42,
        9_000,
        0,
        encode_block_payload(&[]),
    ));
    let expected_id = mined.id();
    let id = ledger.insert_prepared_block(mined, &[]).unwrap();
    assert_eq!(id, expected_id);
}
