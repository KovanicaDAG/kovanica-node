//! # kovanica-node
//!
//! A runnable node for the Kovanica DAG ledger. It ties the stack together —
//! `kovanica_dag` (the block DAG + GHOSTDAG consensus) and `kovanica_state` (the
//! UTXO [`Ledger`](kovanica_state::Ledger), signatures, per-block state,
//! snapshots) — behind a small, testable interface.
//!
//! * [`Node`] holds the ledger in memory and exposes the high-level operations:
//!   bring up a genesis, submit signed transfers, query balances / tips, and
//!   save or load a snapshot.
//! * [`rpc::execute_line`] is a line-based command protocol (string in, string
//!   out) — the node's "RPC". The binary wires it to stdin/stdout (`serve`) or
//!   replays a scripted `demo`.
//!
//! Nodes are multi-node aware: a [`Mempool`](mempool::Mempool) holds pending
//! transactions, [`Node::produce_block`] packs the valid ones into a block, and
//! blocks gossip between nodes ([`net::gossip`] in-process, or
//! [`net::serve_blocks`] / [`net::pull_blocks`] over TCP :9000) so peers
//! converge on the same DAG. [`p2p::Mesh`] is the in-process overlay used by
//! tests and the explorer's internal tick. The **only** on-wire path is
//! plaintext TCP (`KOVANICA_LISTEN`, default `0.0.0.0:9000`).
//! Actors are integer *seeds* the node signs for — a demo convenience,
//! not how a real node handles keys (see [`node`]).
//!
//! ```
//! use kovanica_node::{rpc, Node};
//!
//! let mut node = Node::new();
//! // Genesis mints 500 to actor 1; actor 1 sends 200 to actor 2.
//! assert!(rpc::execute_line(&mut node, "genesis 3 1000 500 1").starts_with("ok genesis"));
//! assert!(rpc::execute_line(&mut node, "send 1 200 2").starts_with("ok block"));
//! assert_eq!(rpc::execute_line(&mut node, "balance 1"), "ok 299");
//! assert_eq!(rpc::execute_line(&mut node, "balance 2"), "ok 200");
//! ```

pub mod dht;
pub mod dns_seed;
pub mod explorer;
#[cfg(any(test, feature = "fuzzing"))]
pub mod fuzz;
pub mod mempool;
pub mod mempool_v2;
pub mod metrics;
pub mod net;
pub mod node;
pub mod p2p;
pub mod p2p_hardening;
pub mod relay;
pub mod rpc;
pub mod spv;

pub use dht::{
    DhtMsg, KBucket, NodeId, NodeLookup, PeerContact, RoutingTable, UpdateResult,
    TAG_DHT_FIND_NODE, TAG_DHT_NODES, TAG_DHT_PING, TAG_DHT_PONG,
};
pub use dns_seed::{
    mock_resolver, production_resolver, DnsResolver, DnsSeedConfig, DnsSeedResolver,
    MockDnsResolver, StdDnsResolver,
};
pub use explorer::serve as serve_explorer;
pub use mempool::Mempool;
pub use mempool_v2::{Added, MempoolConfig, MempoolError, MempoolV2};
pub use metrics::{
    block_span, dht_span, init_metrics, names, peer_span, record_block_produced,
    record_block_validation, record_checkpoint_size, record_dht_bootstrap, record_dht_find_node,
    record_dht_pruned, record_dht_query_received, record_dht_query_sent,
    record_explorer_http_request, record_mempool_evicted, record_mempool_promoted,
    record_p2p_message_received, record_p2p_message_sent, record_peer_banned,
    record_peer_connected, record_peer_disconnected, record_reorg, record_rpc_request,
    record_snapshot_size, record_store_append, record_sync_complete, record_tx_validation,
    rpc_span, set_dht_routing_table_size, set_explorer_ws_clients, set_mempool_counts,
    set_peer_count, set_peer_score, sync_span, TimerGuard,
};
pub use net::{
    decode_bodies, decode_getbodies, decode_getheaders, decode_headers, decode_inventory,
    encode_bodies, encode_getbodies, encode_getheaders, encode_headers, encode_inventory,
    exchange_full_dump, serve_headers_first, sync_headers_first, NetError, SyncStats,
};
pub use node::{
    BlockHeader, BlockRecord, MerkleBlock, MiningTemplate, Node, NodeError, Prepared, Sent,
    WalletDirection, WalletEvent,
};
pub use p2p::{GossipEvent, GossipKind, Mesh, P2pError};
pub use p2p_hardening::{P2pHardening, P2pHardeningConfig, PeerStats};
pub use relay::{apply_relay, handle_relay_query, RelayMsg, RelaySession};
pub use spv::{
    build_locator, request_merkle_block, sync_headers_via_relay, sync_headers_via_relay_with_clock,
    verify_merkle_block,
};
