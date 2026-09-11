//! Load-testing: sustained multi-node block production and gossip.
//!
//! Unlike the correctness-focused suites (`network.rs`, `p2p.rs`,
//! `dht_discovery.rs`), these scenarios keep an 8-node ring **producing** for
//! many rounds and assert that the mesh still converges — and that propagation
//! stays within a bounded number of discrete ticks. Everything is
//! deterministic: the clock is pinned (`set_now_ms`), difficulty is off, and
//! proof-of-work (when enabled) uses the work-1 target, so `pow::mine` returns
//! immediately and every produced block passes insert on every peer.
//!
//! These are the "high node count / sustained block rate / propagation
//! latency / mempool pressure / fork churn" scenarios Point 2.5 of the plan
//! asks for. Building them exposed one real `Mesh` bug — the shared P2P
//! hardening duplicate tracker, keyed per *sender*, dropped a block/tx for
//! every receiver after the first on any fan-out wider than a line. The
//! per-receiver seen-sets now gate delivery (see `p2p.rs` `on_block`/`on_tx`),
//! and this suite is the regression coverage that would have caught it.

use kovanica_node::{GossipKind, Mesh, Node, P2pHardeningConfig};

const RING_SIZE: usize = 8;
const SUBSIDY: u64 = 1000;
const FOUNDER_AMOUNT: u64 = 1000;

/// A node with a pinned clock and a fresh genesis. All mesh nodes must share
/// the same genesis (a different founder seed would produce an incompatible
/// DAG), so `founder_seed` defaults to 1 like the other mesh suites.
fn genesis_node() -> Node {
    let mut node = Node::new();
    node.set_now_ms(1_000);
    node.genesis(3, SUBSIDY, FOUNDER_AMOUNT, 1).unwrap();
    node
}

/// An honest-network hardening config for the load suites.
///
/// The Mesh simulates N *receiving* nodes with one shared `P2pHardening`
/// instance, but that instance tracks duplicates *per sender*, so a single
/// legitimate fan-out of one block to R receivers registers as R−1 duplicates
/// and the sender's score sinks below the auto-ban threshold mid-flood
/// (`score <= ban_threshold` is a live check). On a real network each receiver
/// keeps its own hardening state and fan-out is never misread as spam. The
/// rate-limiter budget (1000 msgs / 100 ticks per sender by default) is also
/// exhausted by the deliberate 320-tx flood, so under defaults the load suites
/// would silently drop blocks and txs and never exercise gossip. These suites
/// therefore neutralise duplicate scoring, auto-ban, and quota caps — honest
/// flood/DAG convergence is what is measured here; duplicate-flood defence
/// and rate limiting are exercised under the default config in `tests/p2p.rs`
/// and the `p2p_hardening` unit tests.
fn honest_mesh() -> Mesh {
    Mesh::with_hardening_config(P2pHardeningConfig {
        score_duplicate_block: 0,
        score_duplicate_tx: 0,
        ban_threshold: i32::MIN, // auto-ban never fires for honest gossip
        max_messages_per_window: u64::MAX, // no per-sender quota cap
        max_bytes_per_window: u64::MAX, // no per-sender byte cap
        ..Default::default()
    })
}

/// An 8-node ring with directed edges in both directions, discovery settled.
fn ring_mesh() -> Mesh {
    let mut mesh = honest_mesh();
    for i in 0..RING_SIZE {
        mesh.add(format!("node-{i}"), genesis_node());
    }
    for i in 0..RING_SIZE {
        let j = (i + 1) % RING_SIZE;
        let a = format!("node-{i}");
        let b = format!("node-{j}");
        mesh.connect(&a, &b).unwrap();
        mesh.connect(&b, &a).unwrap();
    }
    // Settle hello discovery (hellos advertise peer sets; floods terminate via
    // the per-node seen-sets).
    mesh.drain(64);
    assert!(mesh.is_idle(), "discovery should settle");
    mesh
}

/// Advance the mesh one tick at a time until the relay queue drains.
///
/// Returns the number of *ticks* it took — the in-process stand-in for
/// propagation latency (no thread, socket, or wall-clock wait here).
fn ticks_to_quiesce(mesh: &mut Mesh, cap: u32) -> u64 {
    let start = mesh.now();
    for _ in 0..cap {
        if mesh.is_idle() {
            return mesh.now() - start;
        }
        mesh.drain(1);
    }
    panic!(
        "mesh did not quiesce within {cap} ticks (now={})",
        mesh.now()
    );
}

/// Every node must agree on the DAG: identical block count and identical
/// selected tip. This is the consensus-safety readout of every scenario here.
fn assert_converged(mesh: &Mesh) {
    let mut counts = Vec::new();
    let mut tips = Vec::new();
    for name in mesh.names() {
        let node = mesh.node(&name).unwrap();
        counts.push(node.block_count().unwrap());
        tips.push(node.selected_tip().unwrap());
    }
    assert_eq!(
        counts.iter().min(),
        counts.iter().max(),
        "block counts diverged: {counts:?}"
    );
    assert!(
        tips.windows(2).all(|w| w[0] == w[1]),
        "selected tips diverged: {tips:?}"
    );
}

/// Every announced block must reach every other node at least once.
fn assert_block_fanout(mesh: &Mesh, produced: usize) {
    let block_events = mesh
        .events()
        .iter()
        .filter(|e| e.kind == GossipKind::Block)
        .count();
    assert!(
        block_events >= produced * (RING_SIZE - 1),
        "not every block reached every node: {block_events} events for {produced} blocks"
    );
}

// ----------------------------------------------------------------------------
// Sustained round-robin production
// ----------------------------------------------------------------------------

#[test]
fn eight_node_ring_converges_under_round_robin_production() {
    let mut mesh = ring_mesh();
    let rounds = 30;
    let mut produced = 0;
    let mut total_ticks = 0u64;

    for r in 0..rounds {
        let name = format!("node-{}", r % RING_SIZE);
        mesh.produce_empty(&name).unwrap();
        produced += 1;
        let ticks = ticks_to_quiesce(&mut mesh, 64);
        assert!(ticks >= 1, "a produced block must gossip at least one tick");
        total_ticks += ticks;
    }

    assert_converged(&mesh);
    assert_block_fanout(&mesh, produced);
    for name in mesh.names() {
        let node = mesh.node(&name).unwrap();
        assert_eq!(
            node.block_count().unwrap(),
            1 + produced,
            "{name} did not converge to {produced} produced blocks"
        );
    }

    // Open-ring propagation latency budget: each block settles in at most a
    // couple of relay hops even if the ring never fully meshed, so a generous
    // per-round bound keeps the flood from accidentally going O(n^2) without
    // making the test brittle.
    assert!(
        total_ticks <= 10 * (produced as u64),
        "propagation too slow: {total_ticks} ticks for {produced} blocks"
    );
}

#[test]
fn pow_mining_preserves_convergence() {
    let mut mesh = honest_mesh();
    for i in 0..RING_SIZE {
        let mut node = genesis_node();
        // PoW is consensus-enforced on the ledger; the genesis block is exempt,
        // and every produced block mines against work=1 (no difficulty
        // retarget), so the search is immediate and every peer can re-validate.
        node.set_proof_of_work(true).unwrap();
        mesh.add(format!("node-{i}"), node);
    }
    for i in 0..RING_SIZE {
        let j = (i + 1) % RING_SIZE;
        let a = format!("node-{i}");
        let b = format!("node-{j}");
        mesh.connect(&a, &b).unwrap();
        mesh.connect(&b, &a).unwrap();
    }
    mesh.drain(64);
    assert!(mesh.is_idle());

    for r in 0..20 {
        let name = format!("node-{}", r % RING_SIZE);
        mesh.produce_empty(&name).unwrap();
        let ticks = ticks_to_quiesce(&mut mesh, 64);
        assert!(ticks >= 1);
    }

    assert_converged(&mesh);
    for name in mesh.names() {
        let node = mesh.node(&name).unwrap();
        assert!(node.proof_of_work(), "{name} lost the PoW setting");
        assert_eq!(node.block_count().unwrap(), 21, "{name} missed blocks");
    }
}

// ----------------------------------------------------------------------------
// Mempool pressure: many conflicting spends, one deterministic winner
// ----------------------------------------------------------------------------

#[test]
fn mempool_pressure_drains_and_pays_each_winner_once() {
    const TPS_PER_NODE: u64 = 40;
    const AMOUNT: u64 = 10;
    // All nodes share founder seed 1's genesis output (worth FOUNDER_AMOUNT),
    // so every pooled transfer spends the *same* outpoint: a mesh-wide
    // double-spend churn scaled to 8 * 40 = 320 conflicting txs.
    let total_recipients = RING_SIZE as u64 * TPS_PER_NODE;

    let mut mesh = ring_mesh();
    let mut recipients = Vec::with_capacity(total_recipients as usize);

    for i in 0..RING_SIZE {
        let name = format!("node-{}", i);
        for r in 0..TPS_PER_NODE {
            let recipient = 1000 + i as u64 * TPS_PER_NODE + r;
            mesh.pool(&name, 1, AMOUNT, recipient).unwrap();
            recipients.push(recipient);
        }
    }
    let tx_events_before = mesh
        .events()
        .iter()
        .filter(|e| e.kind == GossipKind::Tx)
        .count();
    let ticks = ticks_to_quiesce(&mut mesh, 128);
    assert!(
        ticks <= 64,
        "tx flood should settle quickly, took {ticks} ticks"
    );

    // Every pooled tx must have reached every other node exactly once pending.
    for name in mesh.names() {
        let node = mesh.node(&name).unwrap();
        assert_eq!(
            node.pending_count(),
            total_recipients as usize,
            "{name} is missing relayed txs"
        );
    }
    // Gossip completeness: each of the 320 txs reached 7 other nodes.
    let tx_events_after = mesh
        .events()
        .iter()
        .filter(|e| e.kind == GossipKind::Tx)
        .count();
    assert!(
        tx_events_after - tx_events_before >= total_recipients as usize * (RING_SIZE - 1),
        "tx flood did not reach every node"
    );

    // Drain the mesh: produce on every node until a full round yields no block.
    // (Conflicting losers are moved to the orphan pool by eviction and age out
    // after `orphan_max_age_blocks`; `pending_count()` is the ready-to-mine
    // invariant — losing txs are no longer minable.)
    let mut produced = 0;
    for _ in 0..64 {
        let mut produced_any = false;
        for i in 0..RING_SIZE {
            let name = format!("node-{}", i);
            if mesh.produce(&name).unwrap().is_some() {
                produced_any = true;
                produced += 1;
            }
            ticks_to_quiesce(&mut mesh, 64);
        }
        if !produced_any {
            break;
        }
    }

    assert_converged(&mesh);
    assert!(produced >= 1, "the genesis output must be spent by someone");
    assert_block_fanout(&mesh, produced);
    for name in mesh.names() {
        assert_eq!(
            mesh.node(&name).unwrap().pending_count(),
            0,
            "{name} still has pending txs"
        );
    }

    // The shared genesis output can be spent exactly once on the selected
    // chain, so exactly one of the 320 recipients ends up paid; every other
    // candidate must be unspent. (Which one wins is decided deterministically
    // by GHOSTDAG linearization, so we assert the consensus *invariant*, not
    // the identity of the winner.)
    let reference = mesh.node("node-0").unwrap();
    let mut paid = 0;
    for &recipient in &recipients {
        let balance = reference.balance(&Node::address(recipient)).unwrap();
        assert!(
            balance == 0 || balance == AMOUNT as u128,
            "unexpected partial payment of {balance} to {recipient}"
        );
        if balance == AMOUNT as u128 {
            paid += 1;
        }
    }
    assert_eq!(paid, 1, "exactly one conflicting spend may win");
}

// ----------------------------------------------------------------------------
// Fork churn: divergent producing gangs, then reconciliation
// ----------------------------------------------------------------------------

#[test]
fn fork_churn_converges_on_shared_history() {
    let mut mesh = ring_mesh();
    let mut produced = 0;

    // Two producer gangs build divergent local chains *without* letting gossip
    // deliver between produces: gang A (node-0..3) mines 4 blocks each, then
    // gang B (node-4..7) mines 4 blocks each on tips that have not yet seen
    // gang A. Each gang leaves a pile of undelivered announcements on the
    // queue; the final drain merges a wide fork (up to 8 parallel chains).
    //
    // The clock tool matters here: with all clocks pinned to the same value
    // the members of a gang would mint byte-identical blocks (same parents,
    // same timestamp, same empty payload, same coinbase) and the "fork" would
    // collapse to one block per round. Each producer therefore gets its own
    // monotone timestamp (`now_ms = base + round*100 + node_idx*10 + k`), so
    // gangs on the same pre-fork history genuinely diverge and GHOSTDAG has a
    // wide mergeset to reconcile.
    for round in 0..3u64 {
        for gang in [0usize, 4usize] {
            for k in 0..4u64 {
                let name = format!("node-{}", gang + k as usize);
                mesh.node_mut(&name)
                    .unwrap()
                    .set_now_ms(1_000 + round * 100 + (gang as u64 + k) * 10 + k);
                mesh.produce_empty(&name).unwrap();
                produced += 1;
                // deliberately no drain between produces
            }
        }
        let ticks = ticks_to_quiesce(&mut mesh, 256);
        assert!(ticks <= 64, "fork reconciliation too slow: {ticks} ticks");
    }

    assert_converged(&mesh);
    assert_block_fanout(&mesh, produced);
    for name in mesh.names() {
        let node = mesh.node(&name).unwrap();
        assert_eq!(
            node.block_count().unwrap(),
            1 + produced,
            "{name} did not merge the fork"
        );
    }
}
