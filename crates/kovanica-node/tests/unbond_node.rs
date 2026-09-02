//! Unbond lifecycle at the node layer: bonds mature after UNBOND_MATURITY
//! blue heights, release FIFO oldest-first, and only through KVU1-tagged
//! transactions signed by the frozen coins' owner.

use kovanica_dag::vrf_keypair_from_seed;
use kovanica_node::Node;
use kovanica_state::stake::{bond_tag, UNBOND_MATURITY};
use kovanica_state::{HybridConfig, KeyPair, Transaction, TxOutput};

fn hybrid_cfg() -> HybridConfig {
    HybridConfig {
        rate_num: 1,
        rate_den: 1,
        stake_nominal_work: 1,
        use_epoch_beacon: true,
        retarget: None,
    }
}

fn validator_pk(seed: [u8; 32]) -> [u8; 32] {
    let (_sk, vk) = vrf_keypair_from_seed(&seed);
    *vk.as_bytes()
}

/// Genesis + hybrid + validator identity. The founder (seed 1) holds exactly
/// one 1000-atom coin and is also the miner.
fn setup() -> (Node, KeyPair, [u8; 32]) {
    let mut n = Node::new();
    n.genesis(3, 1_000, 1_000, 1).unwrap();
    n.enable_hybrid(hybrid_cfg()).unwrap();
    let seed = [7u8; 32];
    n.set_validator_seed(seed);
    (n, KeyPair::from_u64(1), seed)
}

/// Bond `value` from `funder`, splitting a larger coin first when needed.
fn bond(n: &mut Node, funder: &KeyPair, vrf_pk: &[u8; 32], value: u64) {
    let coin = n
        .utxos_of(&funder.address())
        .unwrap()
        .into_iter()
        .filter(|(op, _)| !n.outpoint_is_frozen(op).unwrap())
        .max_by_key(|(_, v)| *v)
        .map(|(op, _)| op)
        .expect("an unfrozen funding coin");

    let source = if utxo_value(n, funder, &coin) == value {
        coin
    } else {
        // Split [value | rest], no fee.
        let rest = utxo_value(n, funder, &coin) - value;
        let mut outs = vec![TxOutput::new(value, funder.address())];
        if rest > 0 {
            outs.push(TxOutput::new(rest, funder.address()));
        }
        let split = Transaction::signed(&[(coin, funder)], outs, Vec::new());
        let split_id = split.id();
        n.submit_tx(split).unwrap();
        n.produce_block().unwrap().expect("split mined");
        outpoint_of(split_id)
    };

    let b = Transaction::signed(
        &[(source, funder)],
        vec![TxOutput::new(value, funder.address())],
        bond_tag(vrf_pk),
    );
    n.submit_tx(b).unwrap();
    n.produce_block().unwrap().expect("bond mined");
}

use kovanica_state::OutPoint;

fn utxo_value(n: &Node, owner: &KeyPair, op: &OutPoint) -> u64 {
    n.utxos_of(&owner.address())
        .unwrap()
        .into_iter()
        .find(|(o, _)| o == op)
        .map(|(_, v)| v)
        .unwrap_or_else(|| panic!("utxo {op:?} gone"))
}

fn outpoint_of(id: kovanica_state::TxId) -> OutPoint {
    OutPoint::new(id, 0)
}

#[test]
fn unbond_lifecycle_matures_releases_and_restores_spendability() {
    let (mut n, founder, seed) = setup();
    let pk = validator_pk(seed);

    bond(&mut n, &founder, &pk, 1_000);
    assert_eq!(n.total_stake().unwrap(), 1_000);

    // Nothing has matured yet: an immediate unbond reports what IS available.
    match n.unbond_with(&founder, &pk, 500, founder.address()) {
        Err(e) => assert!(
            e.to_string().contains("insufficient matured stake"),
            "got: {e}"
        ),
        Ok(_) => panic!("unbond before maturity must fail"),
    }
    let matures_at = n
        .pending_unbond_height(&pk)
        .unwrap()
        .expect("pending unlock");
    let h_after_bond = n.chain_height().unwrap();
    assert!(matures_at > h_after_bond);

    // Advance past maturity (staked blocks are free: full bonded share wins).
    while n.chain_height().unwrap() < matures_at {
        n.produce_empty().unwrap();
    }
    assert_eq!(n.pending_unbond_height(&pk).unwrap(), None);

    let sent = n
        .unbond_with(&founder, &pk, 1_000, founder.address())
        .unwrap();
    let _ = sent;
    assert_eq!(n.total_stake().unwrap(), 0);

    // Released value is spendable again (plus mined coinbase change).
    let receipt = n.send(1, 400, 2).unwrap();
    let _ = receipt;

    // And nothing is left to unbond.
    match n.unbond_with(&founder, &pk, 100, founder.address()) {
        Err(e) => assert!(e.to_string().contains("available 0"), "got: {e}"),
        Ok(_) => panic!("second unbond must fail"),
    }
}

#[test]
fn unbond_is_fifo_over_matured_coins_only() {
    let (mut n, founder, seed) = setup();
    let pk = validator_pk(seed);

    // Two bonds at different heights, well separated so the second stays
    // immature even after the first release's own block advances the chain.
    bond(&mut n, &founder, &pk, 300);
    let h_a = n.chain_height().unwrap();
    for _ in 0..5 {
        n.produce_empty().unwrap();
    }
    bond(&mut n, &founder, &pk, 300);
    let h_b = n.chain_height().unwrap();
    assert!(h_b >= h_a + 5);
    assert_eq!(n.total_stake().unwrap(), 600);

    // Advance only past the FIRST bond's maturity.
    let target = h_a + UNBOND_MATURITY;
    while n.chain_height().unwrap() < target {
        n.produce_empty().unwrap();
    }

    // The 300 unbond consumes only the older (matured) coin.
    n.unbond_with(&founder, &pk, 300, founder.address())
        .unwrap();
    assert_eq!(n.total_stake().unwrap(), 300, "younger bond stays frozen");

    // The younger coin is still immature.
    match n.unbond_with(&founder, &pk, 300, founder.address()) {
        Err(e) => assert!(e.to_string().contains("available 0"), "got: {e}"),
        Ok(_) => panic!("immature coin must not release"),
    }
}

#[test]
fn unbond_rejects_foreign_signers() {
    let (mut n, founder, seed) = setup();
    let pk = validator_pk(seed);
    bond(&mut n, &founder, &pk, 1_000);

    let mallory = KeyPair::from_u64(9);
    match n.unbond_with(&mallory, &pk, 1_000, mallory.address()) {
        Err(e) => assert!(
            e.to_string().contains("not owned by the signing key"),
            "got: {e}"
        ),
        Ok(_) => panic!("a non-owner must not move frozen value"),
    }
    assert_eq!(n.total_stake().unwrap(), 1_000);
}
