//! End-to-end hybrid tests at the node layer: a bonded validator produces a
//! staked-VRF block, it crosses the wire as a gossip record with its VRF
//! bundle intact, and a second node re-admits it under the same hybrid policy
//! — converging on identical DAG ids and stake state.

use kovanica_dag::vrf_keypair_from_seed;
use kovanica_node::net::gossip;
use kovanica_node::Node;
use kovanica_state::stake::bond_tag;
use kovanica_state::{HybridConfig, KeyPair, Transaction, TxOutput};

/// Hybrid policy for the test: every slot winnable (one validator holds all
/// bonds), nominal staked work 1, no retarget pin so PoW-path blocks mine
/// trivially.
fn hybrid_cfg() -> HybridConfig {
    HybridConfig {
        rate_num: 1,
        rate_den: 1,
        stake_nominal_work: 1,
        use_epoch_beacon: true,
        retarget: None,
    }
}

/// The VRF public-key bytes derived from a 32-byte seed — the same derivation
/// [`Node::set_validator_seed`] uses internally.
fn validator_pk(seed: [u8; 32]) -> [u8; 32] {
    let (_sk, vk) = vrf_keypair_from_seed(&seed);
    *vk.as_bytes()
}

#[test]
fn staked_block_produced_gossiped_and_readmitted() {
    let cfg = hybrid_cfg();

    // Two identically-seeded nodes, both running the same hybrid policy.
    let mut producer = Node::new();
    let mut peer = Node::new();
    for node in [&mut producer, &mut peer] {
        node.genesis(3, 1_000, 1_000, 1).unwrap();
        assert!(!node.hybrid_enabled());
        node.enable_hybrid(cfg.clone()).unwrap();
        assert!(node.hybrid_enabled());
    }

    // The producer becomes a validator and bonds its whole coin (a bond is a
    // value-conserving self-pay, so it locks the entire 1_000 input). With a
    // single bonded validator its share is 100% of *bonded* stake, so the
    // eligibility threshold saturates and every draw wins deterministically.
    let validator_seed = [7u8; 32];
    let pk = validator_pk(validator_seed);
    producer.set_validator_seed(validator_seed);
    assert_eq!(
        producer.validator_public_key().map(|k| *k.as_bytes()),
        Some(pk)
    );

    let founder = KeyPair::from_u64(1);
    let (coin, _) = producer
        .utxos_of(&founder.address())
        .unwrap()
        .first()
        .map(|(op, v)| (*op, *v))
        .unwrap();
    let bond = Transaction::signed(
        &[(coin, &founder)],
        vec![TxOutput::new(1_000, founder.address())],
        bond_tag(&pk),
    );
    producer.submit_tx(bond).unwrap();
    producer.produce_block().unwrap().expect("bond block mined");

    // The PoW-path bond block crossed fine already; sync the peer so both see
    // the bonded registry before the staked block exists.
    gossip(&producer, &mut peer).unwrap();
    assert_eq!(peer.total_stake().unwrap(), 1_000);

    // Now produce an EMPTY block (its only tx is the coinbase): hybrid mode
    // tries the staked-VRF path first, the draw wins (full bonded share), and
    // no mining happens.
    let staked_id = producer.produce_empty().unwrap();
    let record = producer
        .block_record(&staked_id)
        .expect("produced block known");
    assert_eq!(
        record.work,
        hybrid_cfg().stake_nominal_work,
        "staked block pinned to nominal work"
    );
    let sv = record.vrf.as_ref().expect("record carries the VRF bundle");
    assert_eq!(sv.vrf_pk, pk);

    // The peer re-admits the exact same block id under the same policy.
    gossip(&producer, &mut peer).unwrap();
    assert_eq!(
        peer.selected_tip().unwrap(),
        producer.selected_tip().unwrap()
    );
    assert!(peer.block_record(&staked_id).is_some());
    assert_eq!(peer.total_stake().unwrap(), 1_000);

    // Convergence includes balances (the empty staked block moved nothing).
    assert_eq!(
        peer.balance(&Node::address(1)).unwrap(),
        producer.balance(&Node::address(1)).unwrap()
    );
}

#[test]
fn unbonded_validator_falls_back_to_pow() {
    let mut node = Node::new();
    node.genesis(3, 1_000, 1_000, 1).unwrap();
    node.enable_hybrid(hybrid_cfg()).unwrap();
    node.set_validator_seed([9u8; 32]); // identity set but NOTHING bonded

    // The draw misses (stake 0), production silently falls back to PoW: the
    // block carries no VRF bundle even though a validator identity exists.
    let id = node.produce_empty().unwrap();
    let record = node.block_record(&id).expect("produced block known");
    assert!(record.vrf.is_none(), "fallback must not carry a VRF bundle");
}

#[test]
fn staking_rpc_reports_state() {
    use kovanica_node::rpc::execute_line;

    let mut node = Node::new();
    node.genesis(3, 1_000, 1_000, 1).unwrap();

    let out = execute_line(&mut node, "staking");
    assert!(out.contains("hybrid=false"), "{out}");
    assert!(out.contains("total_stake=0"), "{out}");

    node.enable_hybrid(hybrid_cfg()).unwrap();
    let validator_seed = [7u8; 32];
    node.set_validator_seed(validator_seed);
    let pk_hex = hex::encode(validator_pk(validator_seed));
    let out = execute_line(&mut node, &format!("staking {pk_hex}"));
    assert!(out.contains("hybrid=true"), "{out}");
    assert!(out.contains(&format!("validator={pk_hex}")), "{out}");
    assert!(out.contains("stake_of=0"), "{out}");
}
