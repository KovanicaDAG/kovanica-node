//! Integration tests driving the node through its line RPC — the same surface
//! the binary exposes over stdin/stdout.

use std::time::{SystemTime, UNIX_EPOCH};

use kovanica_node::{rpc::execute_line, Node};

/// Run a command and return the response line.
fn run(node: &mut Node, line: &str) -> String {
    execute_line(node, line)
}

#[test]
fn end_to_end_transfers_update_balances() {
    let mut node = Node::new();
    assert!(run(&mut node, "genesis 3 1000 500 1").starts_with("ok genesis "));
    assert_eq!(run(&mut node, "balance 1"), "ok 500");

    assert!(run(&mut node, "send 1 200 2").starts_with("ok block "));
    assert_eq!(run(&mut node, "balance 1"), "ok 299"); // 500 - 200 - 1 fee
    assert_eq!(run(&mut node, "balance 2"), "ok 200");

    assert!(run(&mut node, "send 2 50 3").starts_with("ok block "));
    assert_eq!(run(&mut node, "balance 2"), "ok 149");
    assert_eq!(run(&mut node, "balance 3"), "ok 50");

    assert_eq!(run(&mut node, "len"), "ok 3"); // genesis + 2 transfer blocks
}

#[test]
fn balance_accepts_a_hex_address() {
    let mut node = Node::new();
    run(&mut node, "genesis 3 1000 500 7");
    let addr = run(&mut node, "address 7");
    let addr_hex = addr.strip_prefix("ok ").unwrap();
    assert_eq!(run(&mut node, &format!("balance {addr_hex}")), "ok 500");
}

#[test]
fn errors_are_reported_not_panicked() {
    let mut node = Node::new();
    // Operating before genesis.
    assert!(run(&mut node, "send 1 10 2").starts_with("err"));
    assert!(run(&mut node, "balance 1").starts_with("err"));

    run(&mut node, "genesis 3 1000 500 1");
    // Second genesis.
    assert!(run(&mut node, "genesis 3 1000 500 1").starts_with("err"));
    // No single output covers 10_000.
    assert!(run(&mut node, "send 1 100000 2").starts_with("err"));
    // Spending from an actor with nothing.
    assert!(run(&mut node, "send 9 1 2").starts_with("err"));
    // Zero amount.
    assert!(run(&mut node, "send 1 0 2").starts_with("err"));
    // Unknown command.
    assert!(run(&mut node, "wat").starts_with("err unknown command"));
}

#[test]
fn snapshot_roundtrip_through_rpc_preserves_balances() {
    let path = {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("kovanica-node-test-{nanos}.snap"))
    };
    let path_str = path.to_str().unwrap();

    let mut node = Node::new();
    run(&mut node, "genesis 3 1000 500 1");
    run(&mut node, "send 1 200 2");
    run(&mut node, "send 2 50 3");
    assert_eq!(
        run(&mut node, &format!("save {path_str}")),
        format!("ok saved {path_str}")
    );

    // Fresh node loads the snapshot and sees the same balances and height.
    let mut restored = Node::new();
    assert_eq!(run(&mut restored, &format!("load {path_str}")), "ok loaded");
    assert_eq!(run(&mut restored, "balance 1"), "ok 299");
    assert_eq!(run(&mut restored, "balance 2"), "ok 149");
    assert_eq!(run(&mut restored, "balance 3"), "ok 50");
    assert_eq!(run(&mut restored, "len"), "ok 3");

    // A restored node keeps working: actor 3 forwards to actor 4.
    assert!(run(&mut restored, "send 3 40 4").starts_with("ok block "));
    assert_eq!(run(&mut restored, "balance 4"), "ok 40");

    let _ = std::fs::remove_file(&path);
}

#[test]
fn checkpoint_roundtrip_through_rpc_preserves_balances() {
    let path = {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("kovanica-node-test-{nanos}.chk"))
    };
    let path_str = path.to_str().unwrap();

    let mut node = Node::new();
    // Use genesis_finality with finality_depth=3 to enable finality
    run(&mut node, "genesis_finality 3 1000 500 1 3");
    run(&mut node, "send 1 200 2");
    run(&mut node, "send 2 50 3");
    run(&mut node, "send 3 10 4");
    run(&mut node, "send 4 2 5"); // reach tip blue score 4 so finality score (4 - 3 = 1) is active
    assert_eq!(
        run(&mut node, &format!("checkpoint {path_str}")),
        format!("ok checkpoint saved {path_str}")
    );

    // Fresh node loads the checkpoint and sees the same balances.
    let mut restored = Node::new();
    assert_eq!(
        run(&mut restored, &format!("load_checkpoint {path_str}")),
        "ok loaded"
    );
    assert_eq!(run(&mut restored, "balance 1"), "ok 299");
    assert_eq!(run(&mut restored, "balance 2"), "ok 149");
    assert_eq!(run(&mut restored, "balance 3"), "ok 39");

    // A restored node keeps working: actor 3 forwards to actor 5.
    assert!(run(&mut restored, "send 3 20 5").starts_with("ok block "));
    assert_eq!(run(&mut restored, "balance 5"), "ok 22");

    let _ = std::fs::remove_file(&path);
}

#[test]
fn parallel_sends_from_two_actors_both_land() {
    // Two actors funded from genesis change spend in separate blocks; the DAG
    // grows and both transfers take effect.
    let mut node = Node::new();
    run(&mut node, "genesis 3 1000 1000 1");
    run(&mut node, "send 1 400 2"); // 1 -> 2 (400), change 599 to 1 (1 fee)
    run(&mut node, "send 1 300 3"); // 1 -> 3 (300), change 298 to 1
    assert_eq!(run(&mut node, "balance 1"), "ok 298");
    assert_eq!(run(&mut node, "balance 2"), "ok 400");
    assert_eq!(run(&mut node, "balance 3"), "ok 300");
}
