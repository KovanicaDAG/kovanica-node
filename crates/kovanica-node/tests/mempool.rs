//! Integration tests for the mempool and block production.

use kovanica_node::{rpc::execute_line, Node};

fn run(node: &mut Node, line: &str) -> String {
    execute_line(node, line)
}

fn bal(node: &mut Node, seed: u64) -> u128 {
    run(node, &format!("balance {seed}"))
        .strip_prefix("ok ")
        .unwrap()
        .parse()
        .unwrap()
}

#[test]
fn a_pooled_transfer_is_packed_into_a_block() {
    let mut node = Node::new();
    run(&mut node, "genesis 3 1000 1000 1");
    assert!(run(&mut node, "pool 1 400 2").starts_with("ok tx "));
    assert_eq!(run(&mut node, "pending"), "ok 1");

    assert!(run(&mut node, "produce").starts_with("ok block "));
    assert_eq!(run(&mut node, "pending"), "ok 0");
    assert_eq!(bal(&mut node, 2), 400);
    assert_eq!(bal(&mut node, 1), 1600); // 600 change + 1000 KVNC subsidy
    assert_eq!(run(&mut node, "len"), "ok 2"); // genesis + produced block
}

#[test]
fn non_conflicting_entries_from_two_actors_pack_together() {
    let mut node = Node::new();
    run(&mut node, "genesis 3 1000 1000 1");
    // Fund actor 2 immediately so two actors each have a spendable output.
    run(&mut node, "send 1 500 2");
    // Now pool spends from each (different outputs — no conflict).
    run(&mut node, "pool 1 100 3");
    run(&mut node, "pool 2 100 4");
    assert_eq!(run(&mut node, "pending"), "ok 2");

    assert!(run(&mut node, "produce").starts_with("ok block "));
    assert_eq!(run(&mut node, "pending"), "ok 0");
    assert_eq!(bal(&mut node, 1), 1400); // 400 change + 1000 subsidy coinbase
    assert_eq!(bal(&mut node, 2), 399); // 500 - 100 - 1 fee
    assert_eq!(bal(&mut node, 3), 100);
    assert_eq!(bal(&mut node, 4), 100);
}

#[test]
fn conflicting_pool_entries_are_partially_included() {
    // Both pooled transfers spend actor 1's single 1000 output, so only one can
    // be included. The loser is then evicted: its input is gone from the
    // selected-tip UTXO, so it can never apply on this branch.
    let mut node = Node::new();
    run(&mut node, "genesis 3 1000 1000 1");
    run(&mut node, "pool 1 400 2");
    run(&mut node, "pool 1 300 3");
    assert_eq!(run(&mut node, "pending"), "ok 2");

    assert!(run(&mut node, "produce").starts_with("ok block "));
    let (b2, b3) = (bal(&mut node, 2), bal(&mut node, 3));
    assert!((b2 == 400 && b3 == 0) || (b2 == 0 && b3 == 300));
    assert_eq!(run(&mut node, "pending"), "ok 0");

    assert_eq!(run(&mut node, "produce"), "ok empty");
    assert_eq!(run(&mut node, "pending"), "ok 0");
}

#[test]
fn producing_from_an_empty_mempool_is_a_noop() {
    let mut node = Node::new();
    run(&mut node, "genesis 3 1000 500 1");
    assert_eq!(run(&mut node, "produce"), "ok empty");
    assert_eq!(run(&mut node, "len"), "ok 1");
}
