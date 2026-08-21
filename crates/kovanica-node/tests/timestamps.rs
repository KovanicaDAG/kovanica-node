//! Integration tests for the node's wall-clock timestamp policy: produced blocks
//! carry the node's (pinned) wall-clock time, clamped monotone above their
//! parents, and [`Node::receive_block`] rejects a block dated too far ahead of
//! the local clock. This is **node policy**, not pure-DAG consensus — hence it is
//! exercised here at the node layer, with the clock pinned via
//! [`Node::set_now_ms`] so every assertion is deterministic.

use kovanica_node::{net, Node, NodeError};

/// The future-time bound the node enforces (mirrors the private
/// `MAX_FUTURE_DRIFT_MS` in `node.rs`): two hours in milliseconds.
const DRIFT_MS: u64 = 2 * 60 * 60 * 1000;

/// A node with the standard genesis (mints 1000 to actor 1), matching the setup
/// in `network.rs`.
fn genesis_node() -> Node {
    let mut node = Node::new();
    node.genesis(3, 1000, 1000, 1).unwrap();
    node
}

#[test]
fn produced_block_carries_the_pinned_wall_clock_and_is_monotone() {
    // Pin the clock well above the monotone floor (genesis is at 0, so the floor
    // for the first block is 1); the produced block should take the wall-clock
    // value verbatim.
    let now = 1_700_000_000_000; // a plausible UNIX-ms instant
    let mut node = genesis_node();
    node.set_now_ms(now);

    let sent = node.send(1, 400, 2).unwrap();
    let record = node.block_record(&sent.block).unwrap();

    assert_eq!(record.timestamp_ms, now, "stamp should be the pinned now");
    // Its single parent is genesis (timestamp 0), so it is strictly monotone.
    assert!(record.timestamp_ms > 0);
}

#[test]
fn produced_block_clamps_above_parents_when_clock_lags() {
    // If the wall clock reads earlier than the latest parent, the stamp is
    // clamped to one past that parent so the DAG's monotone rule still holds.
    let mut node = genesis_node();
    node.set_now_ms(10_000);
    let first = node.send(1, 400, 2).unwrap();
    let first_ts = node.block_record(&first.block).unwrap().timestamp_ms;
    assert_eq!(first_ts, 10_000);

    // Now move the clock *back* below the parent; the next block must still be
    // strictly after `first`.
    node.set_now_ms(5_000);
    let second = node.send(2, 100, 3).unwrap();
    let second_ts = node.block_record(&second.block).unwrap().timestamp_ms;
    assert_eq!(second_ts, first_ts + 1, "clamped to one past the parent");
}

#[test]
fn receive_block_rejects_a_far_future_timestamp() {
    // Produce a real block on the producer, then hand the receiver that record
    // with its timestamp shoved past the drift window. Bumping the timestamp
    // changes the block id, but it is rejected before any insert, so that is fine.
    let now = 1_700_000_000_000;
    let mut producer = genesis_node();
    producer.set_now_ms(now);
    producer.send(1, 400, 2).unwrap();

    let mut record = producer.export().pop().expect("one produced block");
    record.timestamp_ms = now + DRIFT_MS + 1; // one past the bound

    let mut receiver = genesis_node();
    receiver.set_now_ms(now);
    let err = receiver.receive_block(record).unwrap_err();
    assert!(
        matches!(err, NodeError::TimestampTooFarInFuture { .. }),
        "expected TimestampTooFarInFuture, got {err:?}"
    );
}

#[test]
fn receive_block_accepts_a_timestamp_at_the_drift_boundary() {
    // Exactly `now + DRIFT_MS` is within the window (the check is strictly `>`).
    let now = 1_700_000_000_000;
    let mut producer = genesis_node();
    producer.set_now_ms(now);
    producer.send(1, 400, 2).unwrap();

    let mut record = producer.export().pop().expect("one produced block");
    record.timestamp_ms = now + DRIFT_MS; // right at the bound

    let mut receiver = genesis_node();
    receiver.set_now_ms(now);
    receiver
        .receive_block(record)
        .expect("boundary timestamp should be accepted");
}

#[test]
fn normally_gossiped_blocks_are_accepted() {
    // With both nodes on the same pinned clock, ordinary gossip flows through the
    // future-time check untouched and the receiver matches the producer.
    let now = 1_700_000_000_000;
    let mut producer = genesis_node();
    producer.set_now_ms(now);
    producer.send(1, 400, 2).unwrap();
    producer.send(1, 100, 3).unwrap();

    let mut receiver = genesis_node();
    receiver.set_now_ms(now);
    let applied = net::gossip(&producer, &mut receiver).unwrap();
    assert_eq!(applied, 2);
    assert_eq!(receiver.balance(&Node::address(2)).unwrap(), 400);
    assert_eq!(receiver.balance(&Node::address(3)).unwrap(), 100);
    assert_eq!(
        receiver.selected_tip().unwrap(),
        producer.selected_tip().unwrap()
    );
}

#[test]
fn pinned_clock_makes_production_deterministic() {
    // Two nodes with the same pinned clock and the same spend yield byte-identical
    // block ids — the timestamp is part of the block id, so pinning the clock (not
    // a live wall clock) is what makes production reproducible across nodes.
    let now = 1_700_000_000_000;
    let mut a = genesis_node();
    a.set_now_ms(now);
    let mut b = genesis_node();
    b.set_now_ms(now);

    let sent_a = a.send(1, 400, 2).unwrap();
    let sent_b = b.send(1, 400, 2).unwrap();
    assert_eq!(sent_a.block, sent_b.block, "identical inputs, identical id");
    assert_eq!(sent_a.tx, sent_b.tx);
}
