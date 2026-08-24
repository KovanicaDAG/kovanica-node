//! Prometheus metrics and structured logging for the Kovanica node.
//!
//! Provides:
//! - Prometheus metrics (counters, gauges, histograms) for block rate, peer count,
//!   mempool size, reorg depth, sync latency, etc.
//! - Structured JSON logging via tracing
//! - `/metrics` HTTP endpoint for Prometheus scraping

use std::sync::{Once, OnceLock};
use std::time::Duration;

use metrics::{counter, gauge, histogram};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};

/// Global metrics recorder initialization guard.
static METRICS_INIT: Once = Once::new();

/// Handle to the installed Prometheus recorder, used to render the
/// exposition payload for the explorer `/metrics` route.
static METRICS_HANDLE: OnceLock<PrometheusHandle> = OnceLock::new();

/// Initialize the Prometheus metrics recorder and tracing subscriber.
/// Call once at startup (e.g., in `main()` or `serve_explorer()`).
///
/// `listen_addr` optionally starts a standalone scrape endpoint serving the
/// same payload as the explorer's `/metrics` route; bind failure is non-fatal.
pub fn init_metrics(listen_addr: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut result = Ok(());
    METRICS_INIT.call_once(|| {
        // Install the global recorder and keep a render handle.
        let handle = match PrometheusBuilder::new().install_recorder() {
            Ok(h) => h,
            Err(e) => {
                result = Err(e.into());
                return;
            }
        };
        if METRICS_HANDLE.set(handle).is_err() {
            result = Err("metrics handle already installed".into());
            return;
        }

        // Optional dedicated scrape port (0.0.0.0:9090 by default).
        let addr: std::net::SocketAddr = match listen_addr.parse() {
            Ok(a) => a,
            Err(e) => {
                result = Err(e.into());
                return;
            }
        };
        spawn_metrics_listener(addr);

        // Install tracing subscriber with JSON output
        tracing_subscriber::fmt()
            .json()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .with_current_span(true)
            .with_span_list(true)
            .init();
    });
    result
}

/// Render the current Prometheus exposition payload. Falls back to a bare
/// `kovanica_up 1` gauge when metrics were never initialized.
pub fn render_prometheus() -> String {
    match METRICS_HANDLE.get() {
        Some(handle) => handle.render(),
        None => "# HELP kovanica_up Node is up\n# TYPE kovanica_up gauge\nkovanica_up 1\n".into(),
    }
}

fn spawn_metrics_listener(addr: std::net::SocketAddr) {
    let _ = std::thread::Builder::new().name("metrics-http".into()).spawn(move || {
        use std::io::Write;
        let listener = match std::net::TcpListener::bind(addr) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("metrics scrape endpoint on {addr}: {e}");
                return;
            }
        };
        for conn in listener.incoming() {
            let Ok(mut stream) = conn else { continue };
            let body = render_prometheus();
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: text/plain; version=0.0.4; charset=utf-8\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        }
    });
}

/// Metric names — keep consistent for alerting/dashboarding.
pub mod names {
    // Block production
    pub const BLOCKS_PRODUCED_TOTAL: &str = "kovanica_blocks_produced_total";
    pub const BLOCK_PRODUCTION_DURATION_SECONDS: &str =
        "kovanica_block_production_duration_seconds";
    pub const BLOCK_HEIGHT: &str = "kovanica_block_height";

    // DAG consensus
    pub const DAG_TIP_COUNT: &str = "kovanica_dag_tip_count";
    pub const DAG_BLUE_SCORE: &str = "kovanica_dag_blue_score";
    pub const DAG_REORG_DEPTH: &str = "kovanica_dag_reorg_depth_total";
    pub const DAG_SELECTED_TIP_CHANGES_TOTAL: &str = "kovanica_dag_selected_tip_changes_total";

    // Peer / P2P
    pub const PEER_COUNT: &str = "kovanica_peer_count";
    pub const PEER_CONNECTED_TOTAL: &str = "kovanica_peer_connected_total";
    pub const PEER_DISCONNECTED_TOTAL: &str = "kovanica_peer_disconnected_total";
    pub const PEER_BANNED_TOTAL: &str = "kovanica_peer_banned_total";
    pub const PEER_SCORE: &str = "kovanica_peer_score";
    pub const P2P_MESSAGES_SENT_TOTAL: &str = "kovanica_p2p_messages_sent_total";
    pub const P2P_MESSAGES_RECEIVED_TOTAL: &str = "kovanica_p2p_messages_received_total";
    pub const P2P_MESSAGE_BYTES_SENT: &str = "kovanica_p2p_message_bytes_sent_total";
    pub const P2P_MESSAGE_BYTES_RECEIVED: &str = "kovanica_p2p_message_bytes_received_total";

    // Mempool
    pub const MEMPOOL_TX_COUNT: &str = "kovanica_mempool_tx_count";
    pub const MEMPOOL_ORPHAN_COUNT: &str = "kovanica_mempool_orphan_count";
    pub const MEMPOOL_BYTES: &str = "kovanica_mempool_bytes";
    pub const MEMPOOL_EVICTED_TOTAL: &str = "kovanica_mempool_evicted_total";
    pub const MEMPOOL_PROMOTED_TOTAL: &str = "kovanica_mempool_promoted_total";

    // Sync
    pub const SYNC_DURATION_SECONDS: &str = "kovanica_sync_duration_seconds";
    pub const SYNC_HEADERS_RECEIVED: &str = "kovanica_sync_headers_received_total";
    pub const SYNC_BODIES_APPLIED: &str = "kovanica_sync_bodies_applied_total";
    pub const SYNC_PEER_COUNT: &str = "kovanica_sync_peer_count";

    // DHT
    pub const DHT_ROUTING_TABLE_SIZE: &str = "kovanica_dht_routing_table_size";
    pub const DHT_BOOTSTRAP_DURATION_SECONDS: &str = "kovanica_dht_bootstrap_duration_seconds";
    pub const DHT_FIND_NODE_DURATION_SECONDS: &str = "kovanica_dht_find_node_duration_seconds";
    pub const DHT_PEERS_DISCOVERED_TOTAL: &str = "kovanica_dht_peers_discovered_total";
    pub const DHT_PEERS_PRUNED_TOTAL: &str = "kovanica_dht_peers_pruned_total";
    pub const DHT_QUERIES_SENT_TOTAL: &str = "kovanica_dht_queries_sent_total";
    pub const DHT_QUERIES_RECEIVED_TOTAL: &str = "kovanica_dht_queries_received_total";

    // RPC / Explorer
    pub const RPC_REQUESTS_TOTAL: &str = "kovanica_rpc_requests_total";
    pub const RPC_REQUEST_DURATION_SECONDS: &str = "kovanica_rpc_request_duration_seconds";
    pub const EXPLORER_WS_CLIENTS: &str = "kovanica_explorer_ws_clients";
    pub const EXPLORER_HTTP_REQUESTS_TOTAL: &str = "kovanica_explorer_http_requests_total";

    // Storage
    pub const SNAPSHOT_SIZE_BYTES: &str = "kovanica_snapshot_size_bytes";
    pub const CHECKPOINT_SIZE_BYTES: &str = "kovanica_checkpoint_size_bytes";
    pub const STORE_APPEND_DURATION_SECONDS: &str = "kovanica_store_append_duration_seconds";

    // Consensus validation
    pub const BLOCK_VALIDATION_DURATION_SECONDS: &str =
        "kovanica_block_validation_duration_seconds";
    pub const BLOCK_REJECTED_TOTAL: &str = "kovanica_block_rejected_total";
    pub const TX_VALIDATION_DURATION_SECONDS: &str = "kovanica_tx_validation_duration_seconds";
    pub const TX_REJECTED_TOTAL: &str = "kovanica_tx_rejected_total";
}

/// Record a produced (or mined) block.
pub fn record_block_produced(height: u64, blue_score: u64, duration: Duration) {
    counter!(names::BLOCKS_PRODUCED_TOTAL).increment(1);
    gauge!(names::BLOCK_HEIGHT).set(height as f64);
    gauge!(names::DAG_BLUE_SCORE).set(blue_score as f64);
    histogram!(names::BLOCK_PRODUCTION_DURATION_SECONDS).record(duration.as_secs_f64());
}

/// Record a re-org of `depth` blocks.
pub fn record_reorg(depth: u64) {
    counter!(names::DAG_REORG_DEPTH).increment(depth);
}

pub fn record_peer_connected() {
    counter!(names::PEER_CONNECTED_TOTAL).increment(1);
}

pub fn record_peer_disconnected() {
    counter!(names::PEER_DISCONNECTED_TOTAL).increment(1);
}

pub fn record_peer_banned() {
    counter!(names::PEER_BANNED_TOTAL).increment(1);
}

pub fn set_peer_count(count: usize) {
    gauge!(names::PEER_COUNT).set(count as f64);
}

pub fn set_peer_score(peer: &str, score: i32) {
    gauge!(names::PEER_SCORE, "peer" => peer.to_owned()).set(score as f64);
}

pub fn record_p2p_message_sent(kind: &str, bytes: usize) {
    counter!(names::P2P_MESSAGES_SENT_TOTAL, "kind" => kind.to_owned()).increment(1);
    counter!(names::P2P_MESSAGE_BYTES_SENT, "kind" => kind.to_owned()).increment(bytes as u64);
}

pub fn record_p2p_message_received(kind: &str, bytes: usize) {
    counter!(names::P2P_MESSAGES_RECEIVED_TOTAL, "kind" => kind.to_owned()).increment(1);
    counter!(names::P2P_MESSAGE_BYTES_RECEIVED, "kind" => kind.to_owned()).increment(bytes as u64);
}

pub fn set_mempool_counts(pending: usize, orphans: usize, bytes: usize) {
    gauge!(names::MEMPOOL_TX_COUNT).set(pending as f64);
    gauge!(names::MEMPOOL_ORPHAN_COUNT).set(orphans as f64);
    gauge!(names::MEMPOOL_BYTES).set(bytes as f64);
}

pub fn record_mempool_evicted(count: usize) {
    if count > 0 {
        counter!(names::MEMPOOL_EVICTED_TOTAL).increment(count as u64);
    }
}

pub fn record_mempool_promoted(count: usize) {
    if count > 0 {
        counter!(names::MEMPOOL_PROMOTED_TOTAL).increment(count as u64);
    }
}

pub fn record_sync_complete(duration: Duration, headers: usize, bodies: usize, peers: usize) {
    histogram!(names::SYNC_DURATION_SECONDS).record(duration.as_secs_f64());
    counter!(names::SYNC_HEADERS_RECEIVED).increment(headers as u64);
    counter!(names::SYNC_BODIES_APPLIED).increment(bodies as u64);
    gauge!(names::SYNC_PEER_COUNT).set(peers as f64);
}

pub fn set_dht_routing_table_size(size: usize) {
    gauge!(names::DHT_ROUTING_TABLE_SIZE).set(size as f64);
}

pub fn record_dht_bootstrap(duration: Duration, peers_added: usize) {
    histogram!(names::DHT_BOOTSTRAP_DURATION_SECONDS).record(duration.as_secs_f64());
    if peers_added > 0 {
        counter!(names::DHT_PEERS_DISCOVERED_TOTAL).increment(peers_added as u64);
    }
}

pub fn record_dht_find_node(duration: Duration, results: usize) {
    histogram!(names::DHT_FIND_NODE_DURATION_SECONDS).record(duration.as_secs_f64());
    if results > 0 {
        counter!(names::DHT_PEERS_DISCOVERED_TOTAL).increment(results as u64);
    }
}

pub fn record_dht_pruned(count: usize) {
    if count > 0 {
        counter!(names::DHT_PEERS_PRUNED_TOTAL).increment(count as u64);
    }
}

pub fn record_dht_query_sent() {
    counter!(names::DHT_QUERIES_SENT_TOTAL).increment(1);
}

pub fn record_dht_query_received() {
    counter!(names::DHT_QUERIES_RECEIVED_TOTAL).increment(1);
}

pub fn record_rpc_request(method: &str, duration: Duration) {
    counter!(names::RPC_REQUESTS_TOTAL, "method" => method.to_owned()).increment(1);
    histogram!(names::RPC_REQUEST_DURATION_SECONDS).record(duration.as_secs_f64());
}

pub fn set_explorer_ws_clients(count: usize) {
    gauge!(names::EXPLORER_WS_CLIENTS).set(count as f64);
}

pub fn record_explorer_http_request(path: &str, status: u16) {
    counter!(
        names::EXPLORER_HTTP_REQUESTS_TOTAL,
        "path" => path.to_owned(),
        "status" => status.to_string()
    )
    .increment(1);
}

pub fn record_snapshot_size(bytes: usize) {
    gauge!(names::SNAPSHOT_SIZE_BYTES).set(bytes as f64);
}

pub fn record_checkpoint_size(bytes: usize) {
    gauge!(names::CHECKPOINT_SIZE_BYTES).set(bytes as f64);
}

pub fn record_store_append(duration: Duration) {
    histogram!(names::STORE_APPEND_DURATION_SECONDS).record(duration.as_secs_f64());
}

pub fn record_block_validation(duration: Duration, rejected: bool) {
    histogram!(names::BLOCK_VALIDATION_DURATION_SECONDS).record(duration.as_secs_f64());
    if rejected {
        counter!(names::BLOCK_REJECTED_TOTAL).increment(1);
    }
}

pub fn record_tx_validation(duration: Duration, rejected: bool) {
    histogram!(names::TX_VALIDATION_DURATION_SECONDS).record(duration.as_secs_f64());
    if rejected {
        counter!(names::TX_REJECTED_TOTAL).increment(1);
    }
}

/// A timer guard that records a histogram on drop.
pub struct TimerGuard {
    name: &'static str,
    start: std::time::Instant,
}

impl TimerGuard {
    pub fn new(name: &'static str) -> Self {
        Self {
            name,
            start: std::time::Instant::now(),
        }
    }
}

impl Drop for TimerGuard {
    fn drop(&mut self) {
        histogram!(self.name).record(self.start.elapsed().as_secs_f64());
    }
}

/// Convenience macro for timing a block of code.
#[macro_export]
macro_rules! time_block {
    ($name:expr, $body:block) => {{
        let _guard = $crate::metrics::TimerGuard::new($name);
        $body
    }};
}

/// Initialize a tracing span for a block operation.
pub fn block_span(height: u64, block_id: &str) -> tracing::Span {
    tracing::info_span!("block", height, block_id = %block_id)
}

/// Initialize a tracing span for a peer operation.
pub fn peer_span(peer: &str) -> tracing::Span {
    tracing::info_span!("peer", peer = %peer)
}

/// Initialize a tracing span for a sync operation.
pub fn sync_span(peer: &str) -> tracing::Span {
    tracing::info_span!("sync", peer = %peer)
}

/// Initialize a tracing span for a DHT operation.
pub fn dht_span(operation: &str) -> tracing::Span {
    tracing::info_span!("dht", operation = %operation)
}

/// Initialize a tracing span for an RPC request.
pub fn rpc_span(method: &str) -> tracing::Span {
    tracing::info_span!("rpc", method = %method)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_and_renders_prometheus_payload() {
        // First call installs the global recorder; repeat calls are no-ops.
        init_metrics("127.0.0.1:39091").expect("metrics init");

        record_block_produced(7, 42, Duration::from_millis(12));
        record_reorg(6);
        record_peer_connected();
        record_peer_disconnected();
        record_peer_banned();
        set_peer_count(3);
        set_peer_score("peer-a", -25);
        record_p2p_message_sent("block", 512);
        record_p2p_message_received("tx", 96);
        set_mempool_counts(11, 2, 4096);
        record_mempool_evicted(4);
        record_mempool_promoted(9);
        record_sync_complete(Duration::from_millis(250), 10, 10, 2);
        set_dht_routing_table_size(17);
        record_dht_bootstrap(Duration::from_millis(30), 5);
        record_dht_find_node(Duration::from_millis(5), 8);
        record_dht_pruned(1);
        record_dht_query_sent();
        record_dht_query_received();
        record_rpc_request("balance", Duration::from_micros(120));
        set_explorer_ws_clients(2);
        record_explorer_http_request("/api/state", 200);
        record_snapshot_size(1024);
        record_checkpoint_size(256);
        record_store_append(Duration::from_micros(80));
        record_block_validation(Duration::from_micros(50), false);
        record_block_validation(Duration::from_micros(60), true);
        record_tx_validation(Duration::from_micros(20), true);

        let body = render_prometheus();
        for series in [
            names::BLOCKS_PRODUCED_TOTAL,
            names::BLOCK_HEIGHT,
            names::DAG_BLUE_SCORE,
            names::DAG_REORG_DEPTH,
            names::PEER_COUNT,
            names::PEER_CONNECTED_TOTAL,
            names::PEER_BANNED_TOTAL,
            names::PEER_SCORE,
            names::P2P_MESSAGES_SENT_TOTAL,
            names::P2P_MESSAGE_BYTES_RECEIVED,
            names::MEMPOOL_TX_COUNT,
            names::MEMPOOL_ORPHAN_COUNT,
            names::MEMPOOL_EVICTED_TOTAL,
            names::MEMPOOL_PROMOTED_TOTAL,
            names::SYNC_DURATION_SECONDS,
            names::SYNC_HEADERS_RECEIVED,
            names::DHT_ROUTING_TABLE_SIZE,
            names::DHT_BOOTSTRAP_DURATION_SECONDS,
            names::DHT_PEERS_DISCOVERED_TOTAL,
            names::DHT_PEERS_PRUNED_TOTAL,
            names::DHT_QUERIES_SENT_TOTAL,
            names::RPC_REQUEST_DURATION_SECONDS,
            names::EXPLORER_WS_CLIENTS,
            names::EXPLORER_HTTP_REQUESTS_TOTAL,
            names::SNAPSHOT_SIZE_BYTES,
            names::CHECKPOINT_SIZE_BYTES,
            names::STORE_APPEND_DURATION_SECONDS,
            names::BLOCK_VALIDATION_DURATION_SECONDS,
            names::BLOCK_REJECTED_TOTAL,
            names::TX_REJECTED_TOTAL,
        ] {
            assert!(body.contains(series), "missing series {series} in:\n{body}");
        }
    }

    #[test]
    fn timer_guard_records_histogram() {
        init_metrics("127.0.0.1:39091").expect("metrics init");
        {
            let _guard = TimerGuard::new(names::BLOCK_PRODUCTION_DURATION_SECONDS);
        }
        let body = render_prometheus();
        assert!(
            body.contains(names::BLOCK_PRODUCTION_DURATION_SECONDS),
            "TimerGuard did not record its histogram:\n{body}"
        );
    }
}
