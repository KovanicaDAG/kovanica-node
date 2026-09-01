//! Self-hosted BlockDAG explorer: JSON API + a static UI, served from the
//! Rust node. The page never reimplements consensus — it only renders what
//! [`Mesh`] / [`Node`] already computed.

use base64::Engine;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use kovanica_dag::{Block, BlockId};
use kovanica_state::{
    decode_block_payload, encode_block_payload, Address, HybridConfig, OutPoint, Transaction, TxId,
    TxOutput,
};

use crate::dht::{NodeId, PeerContact, RoutingTable};
use crate::dns_seed::{DnsSeedConfig, DnsSeedResolver};
use crate::metrics::{
    init_metrics, record_explorer_http_request, render_prometheus, set_explorer_ws_clients,
    set_peer_count,
};
use crate::net::{
    decode_records, encode_records, pull_blocks_timeout, serve_exchange, serve_headers_first,
    sync_headers_first,
};
use crate::node::{BlockRecord, Node, WalletDirection, HALVING_ERA};
use crate::p2p::Mesh;

const UI: &str = include_str!("explorer.html");
const BIP39: &str = include_str!("bip39-english.txt");
const DOCS: &str = include_str!("../../../TESTNET.md");
/// 1 KVNC = 10^8 base units (atoms).
const ATOM: u64 = 100_000_000;
const GENESIS_SUBSIDY: u64 = 200 * ATOM;
const GENESIS_PREMINE: u64 = 200 * ATOM;
/// Founder actor seed used by `genesis_node()` (deterministic keys).
const FOUNDER_SEED: u64 = 1;
/// Finality depth used by the live testnet (blocks below this score become final).
const TESTNET_FINALITY_DEPTH: u64 = 100;
/// Payload pruning depth used by the live testnet (blocks below this score have payloads evicted).
const TESTNET_PAYLOAD_PRUNING_DEPTH: u64 = 1000;
const ACTORS: [u64; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
/// Single P2P path: plaintext TCP. Not 80/443/3010/8080 and not libp2p :30333.
const P2P_LISTEN_DEFAULT: &str = "0.0.0.0:9000";
const P2P_BOOTSTRAP: &str = "seed.kovanica.online:9000,seed3.kovanica.online:9000";

/// A network profile: identity, genesis parameters, and data-dir isolation.
///
/// The active profile is selected once at boot from `KOVANICA_NETWORK`
/// (default `kovanica-testnet`). Each profile owns a distinct data directory,
/// so a node booted for one network can never wipe another network's data via
/// the [`ensure_network`] marker check — a mainnet node cannot destroy testnet
/// state and vice versa.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NetworkProfile {
    /// Network id — reported by `/api/bootstrap`, `/api/head` and the
    /// snapshot, and written to the `network` marker file.
    id: &'static str,
    /// GHOSTDAG `k` parameter for this network's genesis.
    genesis_k: u16,
    /// Per-block subsidy cap at genesis (atoms).
    genesis_subsidy: u64,
    /// Founder premine minted by the genesis coinbase (atoms).
    genesis_premine: u64,
    /// Founder actor seed (deterministic keys).
    founder_seed: u64,
    /// Finality depth: blocks more than this many blue score below the tip
    /// become final. `u64::MAX` disables finality pruning.
    finality_depth: u64,
    /// Payload pruning depth: blocks more than this many blue score below the
    /// tip have their payloads evicted. `u64::MAX` disables payload pruning.
    payload_pruning_depth: u64,
    /// Dormant placeholder: genesis parameters are TBD and the profile refuses
    /// to boot unless explicitly overridden.
    dormant: bool,
}

impl NetworkProfile {
    /// The live testnet — the default profile.
    fn testnet() -> Self {
        Self {
            id: "kovanica-testnet",
            genesis_k: 3,
            genesis_subsidy: GENESIS_SUBSIDY,
            genesis_premine: GENESIS_PREMINE,
            founder_seed: FOUNDER_SEED,
            finality_depth: TESTNET_FINALITY_DEPTH,
            payload_pruning_depth: TESTNET_PAYLOAD_PRUNING_DEPTH,
            dormant: false,
        }
    }

    /// The mainnet profile — **DORMANT**. Final genesis parameters are TBD and
    /// must be decided by the protocol owners before launch; this placeholder
    /// exists so the profile plumbing (network id, data-dir isolation, faucet
    /// gating) is in place without inventing consensus values. Do not fill in
    /// numbers here — that is a consensus decision, not an implementation one.
    fn mainnet() -> Self {
        Self {
            id: "kovanica-mainnet",
            genesis_k: 0,             // TBD — do not invent
            genesis_subsidy: 0,       // TBD — do not invent
            genesis_premine: 0,       // TBD — do not invent
            founder_seed: 0,          // TBD — do not invent
            finality_depth: 0,        // TBD — do not invent
            payload_pruning_depth: 0, // TBD — do not invent
            dormant: true,
        }
    }
}

/// The active network profile, selected from `KOVANICA_NETWORK` (default
/// `kovanica-testnet`). The mainnet profile is dormant: selecting it without
/// `KOVANICA_MAINNET_OVERRIDE=1` refuses to boot rather than inventing
/// consensus parameters. The default is always testnet — mainnet is never
/// activated implicitly.
fn network_profile() -> NetworkProfile {
    match std::env::var("KOVANICA_NETWORK").as_deref() {
        Ok("kovanica-mainnet") | Ok("mainnet") => {
            if !env_flag("KOVANICA_MAINNET_OVERRIDE", false) {
                panic!(
                    "kovanica-mainnet is DORMANT: genesis parameters are TBD.                      Set KOVANICA_MAINNET_OVERRIDE=1 to force boot (unsafe; do not use in production)."
                );
            }
            NetworkProfile::mainnet()
        }
        _ => NetworkProfile::testnet(),
    }
}

/// WebSocket message types for real-time updates
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
#[serde(tag = "type")]
enum WsMsg {
    #[serde(rename = "block")]
    Block { id: String, blue_score: u64 },
    #[serde(rename = "tx")]
    Tx {
        id: String,
        from: String,
        to: String,
        amount: u64,
    },
    #[serde(rename = "tip")]
    Tip { id: String, blue_score: u64 },
    #[serde(rename = "peer")]
    Peer { addr: String, connected: bool },
    #[serde(rename = "state")]
    State { snapshot: String },
    #[serde(rename = "ping")]
    Ping,
    #[serde(rename = "pong")]
    Pong,
}

/// Bind `addr` (e.g. `0.0.0.0:8080`) and serve the explorer until killed.
pub fn serve(addr: impl ToSocketAddrs) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr)?;
    listener.set_nonblocking(true)?;
    let bound = listener.local_addr()?;
    eprintln!("kovanica explorer on http://{bound}");

    // Initialize metrics (Prometheus + tracing)
    let metrics_addr = "0.0.0.0:9090";
    if let Err(e) = init_metrics(metrics_addr) {
        eprintln!("Failed to init metrics: {e}");
    } else {
        eprintln!("kovanica metrics on http://{metrics_addr}/metrics");
    }

    let mut app = Explorer::boot_persist();
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                if let Err(e) = handle(&mut app, stream) {
                    eprintln!("explorer: {e}");
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                app.tick();
                // Refresh peer gauge periodically so the standalone :9090
                // metrics listener serves fresh values between scrapes.
                if app.ticks % 125 == 0 {
                    set_peer_count(app.live_peers.len());
                }
                app.ws_broadcast_state();
                thread::sleep(Duration::from_millis(40));
            }
            Err(e) => return Err(e),
        }
    }
}

pub struct Explorer {
    pub mesh: Mesh,
    pub selected: String,
    pub mining: bool,
    pub mine_every: u64,
    pub ticks: u64,
    pub rotate: usize,
    pub faucet: bool,
    /// Total atoms the faucet has paid out per address (lifetime, persisted).
    faucet_given: HashMap<String, u64>,
    /// Per-IP token buckets for HTTP API rate limiting.
    rate_limits: HashMap<String, TokenBucket>,
    /// Tokens refilled per second per IP.
    rate_limit_rate: f64,
    /// Token bucket capacity (burst) per IP.
    rate_limit_burst: f64,
    pub allow_reset: bool,
    pub operator: bool,
    pub listen: Vec<TcpListener>,
    pub listen_addr: String,
    pub peers: Vec<String>,
    pub origins: HashMap<String, u64>,
    /// Peers that answered our last sync attempt (live connectivity).
    pub live_peers: HashSet<String>,
    pub ws_clients: Arc<Mutex<Vec<Arc<Mutex<TcpStream>>>>>,
    /// DHT routing table for the explorer's alpha node.
    pub dht_table: Option<RoutingTable>,
    /// DHT NodeId for the explorer.
    pub dht_node_id: Option<NodeId>,
    /// DNS seed resolver for multi-seed discovery.
    pub dns_resolver: Option<DnsSeedResolver<crate::dns_seed::StdDnsResolver>>,
    /// Last time DHT bootstrap was attempted.
    pub last_dht_bootstrap: u64,
    /// Last time DHT peer replenishment was attempted.
    pub last_dht_replenish: u64,
}

impl Explorer {
    /// Test constructor: a fresh in-memory mesh, no persistence or sockets.
    pub fn boot() -> Self {
        let mut mesh = line_mesh();
        mesh.drain(16);
        Self {
            mesh,
            selected: "alpha".into(),
            mining: false,
            mine_every: mine_every_ticks(),
            ticks: 0,
            rotate: 0,
            faucet: true,
            faucet_given: HashMap::new(),
            rate_limits: HashMap::new(),
            // Tests: effectively unlimited so existing suites stay deterministic.
            rate_limit_rate: 1_000.0,
            rate_limit_burst: 1_000.0,
            allow_reset: true,
            operator: true,
            listen: Vec::new(),
            listen_addr: String::new(),
            peers: Vec::new(),
            origins: HashMap::new(),
            live_peers: HashSet::new(),
            ws_clients: Arc::new(Mutex::new(Vec::new())),
            dht_table: None,
            dht_node_id: None,
            dns_resolver: None,
            last_dht_bootstrap: 0,
            last_dht_replenish: 0,
        }
    }

    fn tick(&mut self) {
        self.mesh.tick();
        self.ticks += 1;
        self.tick_p2p();
        self.tick_dht();
        if self.mining && self.mine_every > 0 && self.ticks % self.mine_every == 0 {
            let names = self.mesh.names();
            if !names.is_empty() {
                let name = &names[self.rotate % names.len()];
                let _ = self.mesh.produce_empty(name);
                self.rotate += 1;
                persist_all(&mut self.mesh);
            }
        }
    }

    /// DHT background task: bootstrap from DNS seeds, discover peers, replenish connections.
    fn tick_dht(&mut self) {
        // Initialize DHT on first tick
        if self.dht_table.is_none() {
            if let Some(n) = self.mesh.node_mut("alpha") {
                let node_id = NodeId::random();
                n.init_dht_routing_table(node_id, 8);
                self.dht_node_id = Some(node_id);
                self.dht_table = Some(n.dht_routing_table().unwrap().clone());

                // Initialize DNS resolver
                let _config = DnsSeedConfig::default();
                self.dns_resolver = Some(DnsSeedResolver::new(crate::dns_seed::StdDnsResolver));
            }
        }

        // Periodic DHT bootstrap from DNS seeds (every ~5 minutes)
        if self.ticks > self.last_dht_bootstrap + 7500 {
            // 7500 ticks * 40ms = 300s = 5min
            self.last_dht_bootstrap = self.ticks;
            if let Some(resolver) = &self.dns_resolver {
                let seed_addrs = resolver.resolve_all();
                if !seed_addrs.is_empty() {
                    eprintln!("kovanica dht: resolved {} seed addresses", seed_addrs.len());
                    // Convert seed addresses to peer contacts for bootstrap
                    let mut seed_contacts = Vec::new();
                    for addr in seed_addrs {
                        // Generate a deterministic NodeId for each seed address
                        let seed_id = NodeId::from_public_key(addr.to_string().as_bytes());
                        seed_contacts.push(PeerContact::new(seed_id, addr.to_string()));
                    }
                    if let Some(n) = self.mesh.node_mut("alpha") {
                        if let Ok(added) = n.dht_bootstrap(seed_contacts) {
                            if added > 0 {
                                eprintln!(
                                    "kovanica dht: bootstrapped {} new contacts from DNS seeds",
                                    added
                                );
                                // Sync local dht_table with node's table
                                self.dht_table = n.dht_routing_table().cloned();
                            }
                        }
                    }
                }
            }
        }

        // Periodic DHT peer replenishment (every ~2 minutes)
        if self.ticks > self.last_dht_replenish + 3000 {
            // 3000 ticks * 40ms = 120s = 2min
            self.last_dht_replenish = self.ticks;
            // Prune unreachable peers from DHT tables
            if let Some(n) = self.mesh.node_mut("alpha") {
                if let Some(table) = n.dht_routing_table_mut() {
                    let pruned = table.prune_unresponsive(3);
                    if !pruned.is_empty() {
                        eprintln!("kovanica dht: pruned {} unreachable peers", pruned.len());
                    }
                    // Sync local dht_table
                    self.dht_table = n.dht_routing_table().cloned();
                }
            }
            // Replenish peer connections from DHT (separate borrow)
            let added = self.mesh.replenish_peers_from_dht(8);
            if added > 0 {
                eprintln!(
                    "kovanica dht: replenished {} peer connections from DHT",
                    added
                );
            }
        }
    }

    fn ws_broadcast_state(&self) {
        if self.ws_clients.lock().unwrap().is_empty() {
            return;
        }
        let snapshot = self.snapshot_json();
        let msg = WsMsg::State { snapshot };
        let text = serde_json::to_string(&msg).unwrap_or_default();
        let frame = ws_frame_text(&text);
        let mut clients = self.ws_clients.lock().unwrap();
        clients.retain_mut(|client| {
            if let Ok(mut c) = client.lock() {
                c.write_all(&frame).is_ok() && c.flush().is_ok()
            } else {
                false
            }
        });
    }

    fn snapshot_json(&self) -> String {
        snapshot(self)
    }

    fn tick_p2p(&mut self) {
        let mut incoming = Vec::new();
        for listener in &self.listen {
            while let Ok((stream, peer)) = listener.accept() {
                incoming.push((stream, peer));
            }
        }
        for (mut stream, peer) in incoming {
            if let Some(n) = self.mesh.node_mut("alpha") {
                // Try headers-first sync serve first
                match serve_headers_first(&mut stream, n, Duration::from_millis(800)) {
                    Ok(()) => {
                        eprintln!("kovanica p2p headers-first served {peer}");
                        persist_all(&mut self.mesh);
                    }
                    Err(_e) => {
                        // Fall back to legacy full-dump exchange
                        stream.set_nonblocking(false).unwrap();
                        match serve_exchange(&mut stream, n, Duration::from_millis(800)) {
                            Ok(got) => {
                                eprintln!(
                                    "kovanica p2p exchanged with {peer} (peer sent {got} records)"
                                );
                                if got > 0 {
                                    persist_all(&mut self.mesh);
                                }
                            }
                            Err(e) => {
                                eprintln!("kovanica p2p exchange {peer}: {e}");
                            }
                        }
                    }
                }
            }
        }
        if !self.peers.is_empty() && self.ticks % 250 == 0 {
            self.sync_peers(Duration::from_millis(800), false);
        }
    }

    fn sync_peers(&mut self, timeout: Duration, log: bool) {
        let peers = self.peers.clone();
        if peers.is_empty() {
            return;
        }
        let mut answered: HashSet<String> = HashSet::new();
        if let Some(n) = self.mesh.node_mut("alpha") {
            for addr in peers {
                // Try headers-first sync first (more efficient)
                match sync_headers_first(&addr, n, timeout) {
                    Ok(stats) if stats.bodies_applied > 0 => {
                        eprintln!(
                            "kovanica p2p headers-first sync from {addr}: {} headers, {} bodies applied",
                            stats.headers_received, stats.bodies_applied
                        );
                        answered.insert(addr.clone());
                    }
                    Ok(_) => {
                        // Reachable, just nothing new to apply.
                        answered.insert(addr.clone());
                    }
                    Err(e) => {
                        // Fall back to legacy full-dump pull
                        if log {
                            eprintln!("kovanica p2p headers-first failed {addr}: {e}, falling back to full dump");
                        }
                        match pull_blocks_timeout(&addr, n, timeout) {
                            Ok(k) if k > 0 => {
                                eprintln!(
                                    "kovanica p2p pulled {k} records from {addr} (full dump)"
                                );
                                answered.insert(addr.clone());
                            }
                            Ok(_) => {}
                            Err(_) => {}
                        }
                    }
                }
            }
        }
        // Live connectivity = peers that answered this round. Peers no longer
        // in the config drop out immediately; silent ones drop out here too.
        self.live_peers = answered;
        set_peer_count(self.live_peers.len());
        persist_all(&mut self.mesh);
    }

    fn boot_persist() -> Self {
        let _ = fs::create_dir_all(data_dir());
        ensure_network();
        let mut mesh = Mesh::new();
        // Create alpha node with DHT
        let mut alpha_node = load_or_genesis("alpha");
        let node_id = NodeId::random();
        alpha_node.init_dht_routing_table(node_id, 8);
        mesh.add_with_dht("alpha", alpha_node, node_id);

        if env_flag("KOVANICA_DEMO_MESH", false) {
            mesh.add("beta", load_or_genesis("beta"));
            mesh.add("gamma", load_or_genesis("gamma"));
            let _ = mesh.connect("alpha", "beta");
            let _ = mesh.connect("beta", "gamma");
        }
        mesh.drain(16);
        persist_all(&mut mesh);
        let listen = bind_p2p();
        let listen_addr = listen
            .iter()
            .filter_map(|l| l.local_addr().ok())
            .map(|a| a.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let peers = peer_list();
        if !listen_addr.is_empty() || !peers.is_empty() {
            eprintln!("kovanica p2p listen={listen_addr} peers={peers:?}");
        }
        let _config = DnsSeedConfig::default();
        let dns_resolver = Some(DnsSeedResolver::new(crate::dns_seed::StdDnsResolver));
        let (rate_limit_rate, rate_limit_burst) = rate_limit_from_env();
        let mut app = Self {
            mesh,
            selected: "alpha".into(),
            mining: env_flag("KOVANICA_MINE", false),
            mine_every: mine_every_ticks(),
            ticks: 0,
            rotate: 0,
            faucet: env_flag("KOVANICA_FAUCET", false),
            faucet_given: load_faucet_given(),
            rate_limits: HashMap::new(),
            rate_limit_rate,
            rate_limit_burst,
            allow_reset: env_flag("KOVANICA_ALLOW_RESET", false),
            operator: env_flag("KOVANICA_OPERATOR", false),
            listen,
            listen_addr,
            peers,
            origins: load_origins(),
            live_peers: HashSet::new(),
            ws_clients: Arc::new(Mutex::new(Vec::new())),
            dht_table: None,
            dht_node_id: Some(node_id),
            dns_resolver,
            last_dht_bootstrap: 0,
            last_dht_replenish: 0,
        };
        app.sync_peers(Duration::from_secs(3), true);
        app
    }

    fn select(&mut self, name: &str) {
        if self.mesh.node(name).is_some() {
            self.selected = name.to_string();
        }
    }
}

fn data_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("KOVANICA_DATA") {
        return PathBuf::from(dir);
    }
    data_dir_for(&network_profile())
}

/// The data directory a profile owns. The default testnet keeps the legacy
/// `data/` location (existing deployments live there); every other network —
/// mainnet included — gets its own `data/<network-id>/` subdirectory so the
/// [`ensure_network`] wipe can never cross network boundaries.
fn data_dir_for(profile: &NetworkProfile) -> PathBuf {
    if profile.id == "kovanica-testnet" {
        PathBuf::from("data")
    } else {
        PathBuf::from("data").join(profile.id)
    }
}

fn snap_path(name: &str) -> PathBuf {
    data_dir().join(format!("{name}.snap"))
}

fn log_path(name: &str) -> PathBuf {
    data_dir().join(format!("{name}.log"))
}

fn miner_path(name: &str) -> PathBuf {
    data_dir().join(format!("{name}.miner"))
}

/// Persist every node's ledger **incrementally**: each node appends only the
/// blocks inserted since the last call to its append-only replay log (see
/// [`Node::persist_incremental`]), instead of rewriting a whole-file snapshot
/// after every API write. Whole-file snapshots remain available for portable
/// backups via [`Node::save`] / [`Node::load`]; the log is the primary store.
fn persist_all(mesh: &mut Mesh) {
    let _ = fs::create_dir_all(data_dir());
    for name in mesh.names() {
        if let Some(n) = mesh.node_mut(&name) {
            if let Some(p) = log_path(&name).to_str() {
                let _ = n.persist_incremental(p);
            }
            if let Some(m) = n.miner() {
                let _ = fs::write(miner_path(&name), m.to_hex());
            }
        }
    }
}

fn wipe_data() {
    let dir = data_dir();
    if let Ok(rd) = fs::read_dir(&dir) {
        for e in rd.flatten() {
            let p = e.path();
            if p.extension().and_then(|s| s.to_str()) == Some("snap")
                || p.extension().and_then(|s| s.to_str()) == Some("miner")
                || p.extension().and_then(|s| s.to_str()) == Some("log")
            {
                let _ = fs::remove_file(p);
            }
        }
    }
}

fn load_or_genesis(name: &str) -> Node {
    // Incremental store first: the append-only replay log is the primary
    // persistence format. Loading replays the log through the ledger, so all
    // derived state is recomputed, never trusted from disk.
    let log = log_path(name);
    if log.is_file() {
        if let Some(p) = log.to_str() {
            // Hybrid-era logs must replay under the same policy or staked ids
            // silently change (identity-preserving replay lesson). Load with
            // the hybrid reader when the operator runs hybrid mode.
            let loaded = if env_flag("KOVANICA_HYBRID", false) {
                Node::load_log_with_hybrid(p, HybridConfig::default())
            } else {
                Node::load_log(p)
            };
            if let Ok(mut node) = loaded {
                restore_miner_and_policy(&mut node, name);
                return node;
            }
        }
    }
    // Whole-file snapshot fallback (portable backups / pre-log deployments).
    let snap = snap_path(name);
    if snap.is_file() {
        let mut node = Node::new();
        if let Some(p) = snap.to_str() {
            let loaded = if env_flag("KOVANICA_HYBRID", false) {
                node.load_with_hybrid(p, HybridConfig::default())
            } else {
                node.load(p)
            };
            if loaded.is_ok() {
                restore_miner_and_policy(&mut node, name);
                // Migrate to the incremental store so subsequent persistence
                // appends only new blocks.
                if let Some(lp) = log.to_str() {
                    let _ = node.create_log(lp);
                }
                return node;
            }
        }
    }
    let mut node = genesis_node();
    if let Some(p) = log.to_str() {
        let _ = node.create_log(p);
    }
    node
}

/// Restore a node's miner address and PoW/hybrid policy after loading it from
/// disk (log or snapshot). Hybrid admission is already active on a ledger
/// loaded under the hybrid reader; otherwise PoW is re-enabled when the
/// operator runs PoW mode.
fn restore_miner_and_policy(node: &mut Node, name: &str) {
    if let Ok(h) = fs::read_to_string(miner_path(name)) {
        if let Ok(addr) = parse_addr(h.trim()) {
            node.set_miner(addr);
        }
    } else {
        node.set_miner(Node::address(1));
    }
    if env_flag("KOVANICA_HYBRID", false) {
        // Hybrid admission is already active on the loaded ledger.
    } else if env_flag("KOVANICA_POW", true) {
        let _ = node.set_proof_of_work(true);
    }
}

fn line_mesh() -> Mesh {
    let mut mesh = Mesh::new();
    mesh.add("alpha", genesis_node());
    mesh.add("beta", genesis_node());
    mesh.add("gamma", genesis_node());
    let _ = mesh.connect("alpha", "beta");
    let _ = mesh.connect("beta", "gamma");
    mesh
}

fn genesis_node() -> Node {
    let profile = network_profile();
    let mut node = Node::new();
    node.genesis_with_finality(
        profile.genesis_k,
        profile.genesis_subsidy,
        profile.genesis_premine,
        profile.founder_seed,
        profile.finality_depth,
        profile.payload_pruning_depth,
    )
    .expect("genesis");
    // Hybrid PoW + staked-VRF admission (A2 uplink): opt-in via
    // `KOVANICA_HYBRID=1`. When on, the ledger owns admission and the DAG's
    // own PoW switch is cleared by `set_hybrid` — so the two modes are
    // mutually exclusive here, never stacked.
    if env_flag("KOVANICA_HYBRID", false) {
        let _ = node.enable_hybrid(HybridConfig::default());
    } else if env_flag("KOVANICA_POW", true) {
        let _ = node.set_proof_of_work(true);
    }
    node
}

fn env_flag(name: &str, default: bool) -> bool {
    match std::env::var(name) {
        Ok(v) => matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "on"),
        Err(_) => default,
    }
}

/// A token bucket: `capacity` tokens, refilled at `rate` per second.
/// [`TokenBucket::allow`] consumes one token and reports whether the request
/// may proceed. Deterministic in the sense that the refill is a pure function
/// of elapsed time; tests drive it with `rate = 0` (no refill) so exhaustion
/// is immediate and stable.
#[derive(Clone, Debug)]
struct TokenBucket {
    rate: f64,
    capacity: f64,
    tokens: f64,
    last: std::time::Instant,
}

impl TokenBucket {
    fn new(rate: f64, capacity: f64) -> Self {
        Self {
            rate,
            capacity,
            tokens: capacity,
            last: std::time::Instant::now(),
        }
    }

    fn allow(&mut self) -> bool {
        let now = std::time::Instant::now();
        let elapsed = now.duration_since(self.last).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.rate).min(self.capacity);
        self.last = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Per-IP HTTP rate limiting, from `KOVANICA_RATE_LIMIT` (tokens/second,
/// default 10) and `KOVANICA_RATE_BURST` (bucket capacity, default 60).
fn rate_limit_from_env() -> (f64, f64) {
    let rate: f64 = std::env::var("KOVANICA_RATE_LIMIT")
        .ok()
        .and_then(|s| s.parse::<f64>().ok())
        .unwrap_or(10.0)
        .max(0.0);
    let burst: f64 = std::env::var("KOVANICA_RATE_BURST")
        .ok()
        .and_then(|s| s.parse::<f64>().ok())
        .unwrap_or(60.0)
        .max(1.0);
    (rate, burst)
}

/// Faucet: testnet-only, per-address lifetime cap (5 KVNC).
const FAUCET_MAX_PER_ADDRESS: u64 = 5 * ATOM;

fn faucet_path() -> PathBuf {
    data_dir().join("faucet.txt")
}

fn load_faucet_given() -> HashMap<String, u64> {
    let mut map = HashMap::new();
    let Ok(text) = fs::read_to_string(faucet_path()) else {
        return map;
    };
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        let Some(addr) = parts.next() else {
            continue;
        };
        let Some(n) = parts.next().and_then(|s| s.parse().ok()) else {
            continue;
        };
        map.insert(addr.to_string(), n);
    }
    map
}

fn save_faucet_given(map: &HashMap<String, u64>) {
    let mut rows: Vec<_> = map.iter().collect();
    rows.sort_by(|a, b| a.0.cmp(b.0));
    let body: String = rows
        .into_iter()
        .map(|(k, v)| format!("{k} {v}\n"))
        .collect();
    let _ = fs::create_dir_all(data_dir());
    let _ = fs::write(faucet_path(), body);
}

/// Explorer loop sleeps 40ms per tick.
const TICK_MS: u64 = 40;
/// Default public mine interval when `KOVANICA_MINE=1` (seconds).
const MINE_SECS_DEFAULT: u64 = 120;

fn mine_every_ticks() -> u64 {
    let secs = std::env::var("KOVANICA_MINE_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(MINE_SECS_DEFAULT);
    (secs.saturating_mul(1000) / TICK_MS).max(1)
}

fn ensure_network() {
    let marker = data_dir().join("network");
    let ok = fs::read_to_string(&marker)
        .map(|s| s.trim() == network_profile().id)
        .unwrap_or(false);
    if !ok {
        wipe_data();
        let _ = fs::create_dir_all(data_dir());
        let _ = fs::write(marker, network_profile().id);
    }
}

fn bind_p2p() -> Vec<TcpListener> {
    let raw = std::env::var("KOVANICA_LISTEN").unwrap_or_else(|_| P2P_LISTEN_DEFAULT.into());
    if env_off(&raw) {
        eprintln!("kovanica p2p listen disabled");
        return Vec::new();
    }
    let listeners = bind_p2p_addrs(&raw);
    if listeners.is_empty() && !raw.is_empty() {
        eprintln!("kovanica p2p listen {raw} produced no listeners");
    }
    listeners
}

fn bind_p2p_addrs(raw: &str) -> Vec<TcpListener> {
    let mut addrs = vec![raw.to_string()];
    if let Some(port) = raw.strip_prefix("0.0.0.0:") {
        addrs.push(format!("[::]:{port}"));
    }
    let mut out = Vec::new();
    for addr in addrs {
        let listener = if addr.starts_with("[::]:") {
            // A wildcard [::] socket with the default v6only=0 covers IPv4
            // too, so it would collide with the 0.0.0.0 listener already
            // bound above (EADDRINUSE). Mark it v6-only first — that needs a
            // setsockopt before bind, hence socket2 rather than std.
            match bind_v6_only(&addr) {
                Ok(l) => Some(l),
                Err(e) => {
                    eprintln!("kovanica p2p listen {addr} failed: {e}");
                    None
                }
            }
        } else {
            match TcpListener::bind(&addr) {
                Ok(l) => Some(l),
                Err(e) => {
                    eprintln!("kovanica p2p listen {addr} failed: {e}");
                    None
                }
            }
        };
        let Some(listener) = listener else { continue };
        if let Err(e) = listener.set_nonblocking(true) {
            eprintln!("kovanica p2p listen {addr} nonblocking failed: {e}");
            continue;
        }
        if let Ok(local) = listener.local_addr() {
            eprintln!("kovanica p2p listen {local}");
        }
        out.push(listener);
    }
    out
}

/// Bind an `[::]:port` listener with IPV6_V6ONLY set, so it accepts IPv6
/// only and leaves the IPv4 wildcard to its sibling socket.
fn bind_v6_only(addr: &str) -> std::io::Result<TcpListener> {
    use socket2::{Domain, Protocol, Socket, Type};
    let sock_addr: std::net::SocketAddr = addr
        .parse()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("{e}")))?;
    let socket = Socket::new(
        Domain::for_address(sock_addr),
        Type::STREAM,
        Some(Protocol::TCP),
    )?;
    socket.set_only_v6(true)?;
    socket.bind(&sock_addr.into())?;
    socket.listen(128)?;
    let listener: std::net::TcpListener = socket.into();
    listener.set_nonblocking(true)?;
    Ok(listener)
}

pub const DEFAULT_PEERS: &[&str] = &[
    "seed.kovanica.online:9000",
    "seed2.kovanica.online:9000",
    "seed3.kovanica.online:9000",
];

fn peer_list() -> Vec<String> {
    match std::env::var("KOVANICA_PEERS") {
        Ok(s) if env_off(s.trim()) => Vec::new(),
        Ok(s) => s
            .split(',')
            .map(|x| x.trim().to_string())
            .filter(|x| !x.is_empty())
            .collect(),
        Err(_) => DEFAULT_PEERS.iter().map(|s| s.to_string()).collect(),
    }
}

fn env_off(v: &str) -> bool {
    matches!(v, "" | "0" | "off" | "none" | "false" | "FALSE")
}

fn origins_path() -> PathBuf {
    data_dir().join("origins.txt")
}

fn load_origins() -> HashMap<String, u64> {
    let mut map = HashMap::new();
    let Ok(text) = fs::read_to_string(origins_path()) else {
        return map;
    };
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        let Some(iso) = parts.next() else {
            continue;
        };
        let Some(n) = parts.next().and_then(|s| s.parse().ok()) else {
            continue;
        };
        if iso.len() == 3 && iso.chars().all(|c| c.is_ascii_alphabetic()) {
            map.insert(iso.to_ascii_uppercase(), n);
        }
    }
    map
}

fn save_origins(map: &HashMap<String, u64>) {
    let mut rows: Vec<_> = map.iter().collect();
    rows.sort_by(|a, b| a.0.cmp(b.0));
    let body: String = rows
        .into_iter()
        .map(|(k, v)| format!("{k} {v}\n"))
        .collect();
    let _ = fs::create_dir_all(data_dir());
    let _ = fs::write(origins_path(), body);
}

fn origins_json(map: &HashMap<String, u64>) -> String {
    let mut rows: Vec<_> = map.iter().collect();
    rows.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
    let items = rows
        .into_iter()
        .map(|(iso, n)| format!("{{\"iso3\":{},\"pulses\":{}}}", jstr(iso), n));
    format!("{{\"pulses\":{}}}", jarr(items))
}

fn handle_websocket(app: &mut Explorer, mut stream: TcpStream, req: &str) -> std::io::Result<()> {
    // Extract Sec-WebSocket-Key
    let key = req
        .lines()
        .find(|l| l.to_lowercase().starts_with("sec-websocket-key:"))
        .and_then(|l| l.split(':').nth(1))
        .map(|s| s.trim())
        .unwrap_or("");
    let accept = {
        use sha1::{Digest, Sha1};
        let mut hasher = Sha1::new();
        hasher.update(key.as_bytes());
        hasher.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
        base64::engine::general_purpose::STANDARD.encode(hasher.finalize())
    };
    let resp = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
    );
    stream.write_all(resp.as_bytes())?;
    stream.flush()?;

    // Register client
    let client = Arc::new(Mutex::new(stream));
    app.ws_clients.lock().unwrap().push(client.clone());
    set_explorer_ws_clients(app.ws_clients.lock().unwrap().len());

    // Read loop (handle ping/pong, keep alive)
    let mut buf = [0u8; 1024];
    loop {
        match client.lock().unwrap().read(&mut buf) {
            Ok(0) => break, // Connection closed
            Ok(n) => {
                // Simple WebSocket frame parsing (just handle ping/pong)
                if n >= 2 && (buf[0] & 0x80) != 0 && (buf[0] & 0x0F) == 0x9 {
                    // Ping frame - respond with pong
                    let pong = vec![0x8A, 0x00]; // Pong frame, no payload
                    if let Ok(mut c) = client.lock() {
                        let _ = c.write_all(&pong);
                        let _ = c.flush();
                    }
                }
            }
            Err(_) => break,
        }
    }

    // Unregister client
    app.ws_clients
        .lock()
        .unwrap()
        .retain(|c| !Arc::ptr_eq(c, &client));
    set_explorer_ws_clients(app.ws_clients.lock().unwrap().len());
    Ok(())
}

fn parse_json_u128(val: &serde_json::Value) -> Option<u128> {
    if let Some(n) = val.as_u64() {
        Some(n as u128)
    } else if let Some(s) = val.as_str() {
        s.parse::<u128>().ok()
    } else {
        val.as_f64().map(|n| n as u128)
    }
}

fn parse_json_u64(val: &serde_json::Value) -> Option<u64> {
    if let Some(n) = val.as_u64() {
        Some(n)
    } else if let Some(s) = val.as_str() {
        s.parse::<u64>().ok()
    } else {
        val.as_f64().map(|n| n as u64)
    }
}

pub fn handle(app: &mut Explorer, mut stream: TcpStream) -> std::io::Result<()> {
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    let mut buf = [0u8; 8192];
    let n = match stream.read(&mut buf) {
        Ok(0) => return Ok(()),
        Ok(n) => n,
        Err(_) => return Ok(()),
    };

    // Extract headers and body
    let (headers_raw, body_initial) =
        if let Some(pos) = buf[..n].windows(4).position(|w| w == b"\r\n\r\n") {
            (&buf[..pos], &buf[pos + 4..n])
        } else if let Some(pos) = buf[..n].windows(2).position(|w| w == b"\n\n") {
            (&buf[..pos], &buf[pos + 2..n])
        } else {
            (&buf[..n], &[][..])
        };

    let headers_str = String::from_utf8_lossy(headers_raw);

    let mut content_length = None;
    for line in headers_str.lines() {
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case("content-length") {
                if let Ok(cl) = v.trim().parse::<usize>() {
                    content_length = Some(cl);
                }
            }
        }
    }

    let mut body_bytes = body_initial.to_vec();
    if let Some(cl) = content_length {
        const MAX_BODY_SIZE: usize = 2 * 1024 * 1024; // 2MB max
        let target_len = cl.min(MAX_BODY_SIZE);
        while body_bytes.len() < target_len {
            let to_read = target_len - body_bytes.len();
            let mut chunk = vec![0u8; to_read.min(8192)];
            match stream.read(&mut chunk) {
                Ok(0) => break,
                Ok(read_n) => {
                    body_bytes.extend_from_slice(&chunk[..read_n]);
                }
                Err(_) => break,
            }
        }
    }

    let body_str = String::from_utf8_lossy(&body_bytes);
    let first = headers_str.lines().next().unwrap_or("");
    let mut parts = first.split_whitespace();
    let method = parts.next().unwrap_or("GET");
    let target = parts.next().unwrap_or("/");
    let (path, query) = split_query(target);

    // Record HTTP request metric
    record_explorer_http_request(path, 200); // Will update with actual status later

    // Per-IP token-bucket rate limiting (D1): a misbehaving client cannot
    // hammer the API. Every request counts — static assets, the WS upgrade,
    // and the JSON endpoints alike; a browser's normal polling sits far below
    // the default 10 req/s. Exhausted buckets get 429.
    let peer_ip = stream
        .peer_addr()
        .map(|a| a.ip().to_string())
        .unwrap_or_default();
    let allowed = {
        let bucket = app
            .rate_limits
            .entry(peer_ip)
            .or_insert_with(|| TokenBucket::new(app.rate_limit_rate, app.rate_limit_burst));
        bucket.allow()
    };
    if !allowed {
        return respond(
            &mut stream,
            429,
            "application/json",
            b"{\"ok\":false,\"error\":\"rate limit exceeded\"}",
        );
    }

    // WebSocket upgrade
    if method == "GET" && path == "/ws" && headers_str.contains("Upgrade: websocket") {
        return handle_websocket(app, stream, &headers_str);
    }

    // Prometheus metrics endpoint
    if method == "GET" && path == "/metrics" {
        // Sample live gauges on every scrape so Prometheus always sees fresh
        // values even when no block/mempool event fired recently.
        set_peer_count(app.live_peers.len());
        return respond_prometheus_metrics(&mut stream);
    }

    if method == "HEAD" && (path == "/" || path == "/index.html" || path == "/wallet") {
        return respond(&mut stream, 200, "text/html; charset=utf-8", b"");
    }
    if method == "GET" && (path == "/" || path == "/index.html" || path == "/wallet") {
        return respond(&mut stream, 200, "text/html; charset=utf-8", UI.as_bytes());
    }
    if method == "GET" && path == "/bip39.txt" {
        return respond(
            &mut stream,
            200,
            "text/plain; charset=utf-8",
            BIP39.as_bytes(),
        );
    }
    if method == "GET" && path == "/kovanica-explorer-wallet.patch" {
        let body = std::fs::read("/workspace/kovanica-explorer-wallet.patch")
            .or_else(|_| std::fs::read("/tmp/kovanica-explorer-wallet.patch"))
            .unwrap_or_default();
        return respond_download(
            &mut stream,
            "text/x-patch; charset=utf-8",
            "kovanica-explorer-wallet.patch",
            &body,
        );
    }
    if method == "GET" && path == "/docs" {
        return respond(
            &mut stream,
            200,
            "text/plain; charset=utf-8",
            DOCS.as_bytes(),
        );
    }
    if method == "GET" && path == "/api/mine/template" {
        let node_name = query
            .get("node")
            .map(|s| s.as_str())
            .unwrap_or(&app.selected);
        let Some(node) = app.mesh.node(node_name) else {
            let err = format!("{{\"ok\":false,\"error\":\"unknown node {}\"}}", node_name);
            return respond(&mut stream, 400, "application/json", err.as_bytes());
        };
        let custom_miner = query.get("miner").and_then(|s| parse_addr(s).ok());
        let template_res = if custom_miner.is_some() {
            node.mining_template_for(custom_miner)
        } else {
            node.mining_template()
        };
        match template_res {
            Ok(template) => {
                let body = template.to_json();
                return respond(&mut stream, 200, "application/json", body.as_bytes());
            }
            Err(e) => {
                let err = format!("{{\"ok\":false,\"error\":{}}}", jstr(&e.to_string()));
                return respond(&mut stream, 400, "application/json", err.as_bytes());
            }
        }
    }
    if method == "GET" && path == "/api/bootstrap" {
        let n = app.mesh.node(&app.selected);
        let genesis = n
            .and_then(|n| n.ledger().ok())
            .map(|l| l.genesis().to_string())
            .unwrap_or_default();
        let tip = n
            .and_then(|n| n.selected_tip().ok())
            .map(|t| t.to_string())
            .unwrap_or_default();
        let pow = n.map(|n| n.proof_of_work()).unwrap_or(false);
        let min_fee = n.map(|n| n.min_fee()).unwrap_or(0);
        let peers = jarr(
            app.peers
                .iter()
                .cloned()
                .chain(std::iter::once(app.listen_addr.clone()).filter(|s| !s.is_empty()))
                .map(|s| jstr(&s)),
        );
        let profile = network_profile();
        let body = format!(
            "{{\"network\":{},\"genesis\":{},\"tip\":{},\"listen\":{},\"peers\":{},\"pow\":{},\"min_fee\":{},\"atom\":{},\"token\":\"KVNC\",\"k\":{},\"subsidy\":{},\"founder_amount\":{},\"founder_seed\":{},\"finality_depth\":{},\"payload_pruning_depth\":{},\"light_config\":{{\"k\":{},\"subsidy\":{},\"premine\":{},\"founder_seed\":{},\"finality_depth\":{},\"payload_pruning_depth\":{}}}}}",
            jstr(profile.id),
            jstr(&genesis),
            jstr(&tip),
            jstr(&app.listen_addr),
            peers,
            pow,
            min_fee,
            ATOM,
            profile.genesis_k,
            profile.genesis_subsidy,
            profile.genesis_premine,
            profile.founder_seed,
            profile.finality_depth,
            profile.payload_pruning_depth,
            profile.genesis_k,
            profile.genesis_subsidy,
            profile.genesis_premine,
            profile.founder_seed,
            profile.finality_depth,
            profile.payload_pruning_depth,
        );
        return respond(&mut stream, 200, "application/json", body.as_bytes());
    }
    if method == "GET" && path == "/api/state" {
        if let Some(node) = query.get("node") {
            app.select(node);
        }
        let body = snapshot(app);
        return respond(&mut stream, 200, "application/json", body.as_bytes());
    }
    if method == "GET" && path == "/api/head" {
        if let Some(n) = app.mesh.node(&app.selected) {
            let genesis = n
                .ledger()
                .ok()
                .map(|l| l.genesis().to_string())
                .unwrap_or_default();
            let tip = n.selected_tip().map(|t| t.to_string()).unwrap_or_default();
            let blocks = n.block_count().unwrap_or(0);
            let body = format!(
                "{{\"network\":{},\"genesis\":{},\"tip\":{},\"blocks\":{},\"min_fee\":{},\"atom\":{}}}",
                jstr(network_profile().id),
                jstr(&genesis),
                jstr(&tip),
                blocks,
                n.min_fee(),
                ATOM
            );
            return respond(&mut stream, 200, "application/json", body.as_bytes());
        }
    }
    if method == "GET" && path == "/api/p2p" {
        let body = format!(
            "{{\"path\":\"tcp\",\"listen\":{},\"peers\":{},\"bootstrap\":{}}}",
            jstr(&app.listen_addr),
            jarr(app.peers.iter().map(|s| jstr(s))),
            jstr(P2P_BOOTSTRAP)
        );
        return respond(&mut stream, 200, "application/json", body.as_bytes());
    }
    if method == "GET" && path == "/api/origins" {
        return respond(
            &mut stream,
            200,
            "application/json",
            origins_json(&app.origins).as_bytes(),
        );
    }
    if method == "GET" && path == "/api/blocks" {
        if let Some(n) = app.mesh.node(&app.selected) {
            let records = match query.get("from") {
                Some(s) => match decode_block_id_hex(s) {
                    Ok(id) => n.export_from(&id),
                    Err(e) => {
                        let body = format!("{{\"ok\":false,\"error\":{}}}", jstr(&e));
                        return respond(&mut stream, 400, "application/json", body.as_bytes());
                    }
                },
                None => n.export(),
            };
            let bytes = encode_records(&records);
            return respond(&mut stream, 200, "application/octet-stream", &bytes);
        }
    }
    if method == "GET" && path == "/api/light_sync" {
        // SPV light-sync blob (A3): the selected chain as verified headers +
        // per-block Golomb-Rice filters, byte-compatible with the FFI's `KVLS`
        // v1 format so a phone's `receive_light_sync` consumes it directly.
        // `?from=<block-id>` returns only headers strictly after that block
        // (the client already has it) for incremental sync; an unknown or
        // off-chain `from` falls back to the full blob.
        if let Some(n) = app.mesh.node(&app.selected) {
            let bytes = light_sync_blob(n, query.get("from").map(|s| s.as_str()));
            return respond(&mut stream, 200, "application/octet-stream", &bytes);
        }
    }
    if method == "GET" && path == "/api/light_proof" {
        // Merkle-inclusion proof for one transaction, for a light client to
        // verify against the header it already synced (`merkle_proof` helper).
        let Some(block_hex) = query.get("block") else {
            let err = "{\"ok\":false,\"error\":\"block id required\"}";
            return respond(&mut stream, 400, "application/json", err.as_bytes());
        };
        let Some(tx_hex) = query.get("tx") else {
            let err = "{\"ok\":false,\"error\":\"tx id required\"}";
            return respond(&mut stream, 400, "application/json", err.as_bytes());
        };
        let block_id = match hex::decode(block_hex.trim())
            .ok()
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
            .map(BlockId::from_bytes)
        {
            Some(id) => id,
            None => {
                let err = format!(
                    "{{\"ok\":false,\"error\":{}}}",
                    jstr("block id must be 32-byte hex")
                );
                return respond(&mut stream, 400, "application/json", err.as_bytes());
            }
        };
        let tx_id = match hex::decode(tx_hex.trim())
            .ok()
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
            .map(kovanica_state::TxId::from_bytes)
        {
            Some(id) => id,
            None => {
                let err = format!(
                    "{{\"ok\":false,\"error\":{}}}",
                    jstr("tx id must be 32-byte hex")
                );
                return respond(&mut stream, 400, "application/json", err.as_bytes());
            }
        };
        if let Some(n) = app.mesh.node(&app.selected) {
            match n.merkle_proof(&block_id, &tx_id) {
                Some(proof) => {
                    let bytes = encode_merkle_proof(&proof);
                    return respond(&mut stream, 200, "application/octet-stream", &bytes);
                }
                None => {
                    let err = format!(
                        "{{\"ok\":false,\"error\":{}}}",
                        jstr("no proof: unknown block or tx")
                    );
                    return respond(&mut stream, 404, "application/json", err.as_bytes());
                }
            }
        }
    }
    if method == "GET" && path == "/api/history" {
        match history_json(app, &query) {
            Ok(body) => return respond(&mut stream, 200, "application/json", body.as_bytes()),
            Err(e) => return respond(&mut stream, 400, "text/plain; charset=utf-8", e.as_bytes()),
        }
    }
    if method == "GET" && path == "/api/utxos" {
        match utxos_json(app, &query) {
            Ok(body) => return respond(&mut stream, 200, "application/json", body.as_bytes()),
            Err(e) => return respond(&mut stream, 400, "text/plain; charset=utf-8", e.as_bytes()),
        }
    }
    if method == "GET" && path.starts_with("/api/block/") {
        let id = path.trim_start_matches("/api/block/");
        match block_detail_json(app, id) {
            Ok(body) => return respond(&mut stream, 200, "application/json", body.as_bytes()),
            Err(e) if e == "block not found" => {
                return respond(
                    &mut stream,
                    404,
                    "application/json",
                    err_json(&e).as_bytes(),
                );
            }
            Err(e) => {
                return respond(
                    &mut stream,
                    400,
                    "application/json",
                    err_json(&e).as_bytes(),
                )
            }
        }
    }
    if method == "GET" && path.starts_with("/api/tx/") {
        let id = path.trim_start_matches("/api/tx/");
        match tx_detail_json(app, id) {
            Ok(body) => return respond(&mut stream, 200, "application/json", body.as_bytes()),
            Err(e) if e == "tx not found" || e == "block not found" => {
                return respond(
                    &mut stream,
                    404,
                    "application/json",
                    err_json(&e).as_bytes(),
                );
            }
            Err(e) => {
                return respond(
                    &mut stream,
                    400,
                    "application/json",
                    err_json(&e).as_bytes(),
                )
            }
        }
    }
    if method == "GET" && path.starts_with("/api/address/") {
        let addr = path.trim_start_matches("/api/address/");
        match address_detail_json(app, addr, &query) {
            Ok(body) => return respond(&mut stream, 200, "application/json", body.as_bytes()),
            Err(e) if e == "address not found" => {
                return respond(
                    &mut stream,
                    404,
                    "application/json",
                    err_json(&e).as_bytes(),
                );
            }
            Err(e) => {
                return respond(
                    &mut stream,
                    400,
                    "application/json",
                    err_json(&e).as_bytes(),
                )
            }
        }
    }
    if method == "GET" && path == "/api/fee_estimate" {
        match fee_estimate_json(app, &query) {
            Ok(body) => return respond(&mut stream, 200, "application/json", body.as_bytes()),
            Err(e) => {
                let err = format!("{{\"ok\":false,\"error\":{}}}", jstr(&e));
                return respond(&mut stream, 400, "application/json", err.as_bytes());
            }
        }
    }
    if method == "POST" && path == "/api/mine/submit" {
        let node_name = query
            .get("node")
            .cloned()
            .unwrap_or_else(|| app.selected.clone());

        // Staked-block uplink (plan 9d-a, locked decision): a phone that won
        // the VRF sortition uploads its block in the gossip wire format
        // (`encode_records` — the same octet-stream framing `/api/blocks`
        // serves), which carries the VRF bundle a JSON body cannot express.
        // `Content-Type: application/octet-stream` selects the wire path; the
        // JSON path below is unchanged for PoW miners.
        let is_wire = headers_str.lines().any(|l| {
            let l = l.to_ascii_lowercase();
            l.starts_with("content-type:") && l.contains("application/octet-stream")
        });
        if is_wire {
            return submit_wire_block(app, &node_name, &body_bytes, &mut stream);
        }

        // Parse JSON request body
        let json_body: serde_json::Value = match serde_json::from_str(&body_str) {
            Ok(val) => val,
            Err(e) => {
                let err = format!(
                    "{{\"ok\":false,\"error\":{}}}",
                    jstr(&format!("invalid json body: {e}"))
                );
                return respond(&mut stream, 400, "application/json", err.as_bytes());
            }
        };

        // Extract parents
        let parents_val = match json_body.get("parents") {
            Some(serde_json::Value::Array(arr)) if !arr.is_empty() => arr,
            _ => {
                let err = format!(
                    "{{\"ok\":false,\"error\":{}}}",
                    jstr("missing or empty 'parents' field")
                );
                return respond(&mut stream, 400, "application/json", err.as_bytes());
            }
        };

        let mut parents = Vec::with_capacity(parents_val.len());
        for p_val in parents_val {
            let Some(p_str) = p_val.as_str() else {
                let err = format!(
                    "{{\"ok\":false,\"error\":{}}}",
                    jstr("parent block id must be a hex string")
                );
                return respond(&mut stream, 400, "application/json", err.as_bytes());
            };
            let bytes = match hex::decode(p_str.trim()) {
                Ok(b) => b,
                Err(_) => {
                    let err = format!(
                        "{{\"ok\":false,\"error\":{}}}",
                        jstr(&format!("invalid hex in parent block id: {p_str}"))
                    );
                    return respond(&mut stream, 400, "application/json", err.as_bytes());
                }
            };
            let arr: [u8; 32] = match bytes.try_into() {
                Ok(a) => a,
                Err(_) => {
                    let err = format!(
                        "{{\"ok\":false,\"error\":{}}}",
                        jstr(&format!("parent block id must be 32 bytes: {p_str}"))
                    );
                    return respond(&mut stream, 400, "application/json", err.as_bytes());
                }
            };
            parents.push(BlockId::from_bytes(arr));
        }

        // Extract work
        let work = match json_body.get("work") {
            Some(v) => match parse_json_u128(v) {
                Some(w) => w,
                None => {
                    let err = format!(
                        "{{\"ok\":false,\"error\":{}}}",
                        jstr("invalid 'work' field")
                    );
                    return respond(&mut stream, 400, "application/json", err.as_bytes());
                }
            },
            None => {
                let err = format!(
                    "{{\"ok\":false,\"error\":{}}}",
                    jstr("missing 'work' field")
                );
                return respond(&mut stream, 400, "application/json", err.as_bytes());
            }
        };

        // Extract timestamp_ms
        let timestamp_ms = match json_body.get("timestamp_ms") {
            Some(v) => match parse_json_u64(v) {
                Some(ts) => ts,
                None => {
                    let err = format!(
                        "{{\"ok\":false,\"error\":{}}}",
                        jstr("invalid 'timestamp_ms' field")
                    );
                    return respond(&mut stream, 400, "application/json", err.as_bytes());
                }
            },
            None => {
                let err = format!(
                    "{{\"ok\":false,\"error\":{}}}",
                    jstr("missing 'timestamp_ms' field")
                );
                return respond(&mut stream, 400, "application/json", err.as_bytes());
            }
        };

        // Extract nonce
        let nonce = match json_body.get("nonce") {
            Some(v) => match parse_json_u64(v) {
                Some(nc) => nc,
                None => {
                    let err = format!(
                        "{{\"ok\":false,\"error\":{}}}",
                        jstr("invalid 'nonce' field")
                    );
                    return respond(&mut stream, 400, "application/json", err.as_bytes());
                }
            },
            None => {
                let err = format!(
                    "{{\"ok\":false,\"error\":{}}}",
                    jstr("missing 'nonce' field")
                );
                return respond(&mut stream, 400, "application/json", err.as_bytes());
            }
        };

        // Extract payload hex and decode transactions
        let txs = if let Some(payload_val) = json_body.get("payload").and_then(|v| v.as_str()) {
            let payload_bytes = match hex::decode(payload_val.trim()) {
                Ok(b) => b,
                Err(e) => {
                    let err = format!(
                        "{{\"ok\":false,\"error\":{}}}",
                        jstr(&format!("invalid hex in 'payload': {e}"))
                    );
                    return respond(&mut stream, 400, "application/json", err.as_bytes());
                }
            };
            match decode_block_payload(&payload_bytes) {
                Ok(t) => t,
                Err(e) => {
                    let err = format!(
                        "{{\"ok\":false,\"error\":{}}}",
                        jstr(&format!("undecodable block payload: {e:?}"))
                    );
                    return respond(&mut stream, 400, "application/json", err.as_bytes());
                }
            }
        } else {
            let err = format!(
                "{{\"ok\":false,\"error\":{}}}",
                jstr("missing 'payload' field")
            );
            return respond(&mut stream, 400, "application/json", err.as_bytes());
        };

        let record = BlockRecord {
            parents,
            work,
            timestamp_ms,
            nonce,
            vrf: None,
            txs,
        };

        let Some(node) = app.mesh.node_mut(&node_name) else {
            let err = format!("{{\"ok\":false,\"error\":\"unknown node {}\"}}", node_name);
            return respond(&mut stream, 400, "application/json", err.as_bytes());
        };

        // Check PoW target if node enforces proof of work
        if node.proof_of_work() {
            let block = Block::new(
                record.parents.clone(),
                record.work,
                record.timestamp_ms,
                record.nonce,
                encode_block_payload(&record.txs),
            );
            if !kovanica_dag::pow::meets_target(&block.id(), record.work) {
                let err = format!(
                    "{{\"ok\":false,\"error\":{}}}",
                    jstr(&format!(
                        "proof of work target not met for block {}",
                        block.id()
                    ))
                );
                return respond(&mut stream, 400, "application/json", err.as_bytes());
            }
        }

        match node.receive_block(record.clone()) {
            Ok(block_id) => {
                app.mesh.announce_block(&node_name, record);
                persist_all(&mut app.mesh);
                let body = format!("{{\"ok\":true,\"block\":{}}}", jstr(&block_id.to_string()));
                return respond(&mut stream, 200, "application/json", body.as_bytes());
            }
            Err(e) => {
                let err = format!("{{\"ok\":false,\"error\":{}}}", jstr(&e.to_string()));
                return respond(&mut stream, 400, "application/json", err.as_bytes());
            }
        }
    }
    // ------------------------------------------------------------------
    // Raw transaction submission (multisig, hardware, mobile)
    // ------------------------------------------------------------------
    if method == "POST" && path == "/api/submit_tx" {
        let json_body: serde_json::Value = match serde_json::from_str(&body_str) {
            Ok(val) => val,
            Err(e) => {
                let err = format!(
                    "{{\"ok\":false,\"error\":{}}}",
                    jstr(&format!("invalid json body: {e}"))
                );
                return respond(&mut stream, 400, "application/json", err.as_bytes());
            }
        };
        let tx_hex = match json_body.get("tx_hex").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => {
                let err = format!(
                    "{{\"ok\":false,\"error\":{}}}",
                    jstr("missing 'tx_hex' field")
                );
                return respond(&mut stream, 400, "application/json", err.as_bytes());
            }
        };
        let tx_bytes = match hex::decode(tx_hex.trim()) {
            Ok(b) => b,
            Err(e) => {
                let err = format!(
                    "{{\"ok\":false,\"error\":{}}}",
                    jstr(&format!("invalid hex in 'tx_hex': {e}"))
                );
                return respond(&mut stream, 400, "application/json", err.as_bytes());
            }
        };
        let tx = match Transaction::decode(&tx_bytes) {
            Ok(t) => t,
            Err(e) => {
                let err = format!(
                    "{{\"ok\":false,\"error\":{}}}",
                    jstr(&format!("undecodable transaction: {e:?}"))
                );
                return respond(&mut stream, 400, "application/json", err.as_bytes());
            }
        };
        let node_name = query
            .get("node")
            .cloned()
            .unwrap_or_else(|| app.selected.clone());
        let Some(node) = app.mesh.node_mut(&node_name) else {
            let err = format!("{{\"ok\":false,\"error\":\"unknown node {}\"}}", node_name);
            return respond(&mut stream, 400, "application/json", err.as_bytes());
        };
        match node.submit_tx(tx) {
            Ok(tx_id) => {
                persist_all(&mut app.mesh);
                let body = format!("{{\"ok\":true,\"tx\":{}}}", jstr(&tx_id.to_string()));
                return respond(&mut stream, 200, "application/json", body.as_bytes());
            }
            Err(e) => {
                let err = format!("{{\"ok\":false,\"error\":{}}}", jstr(&e.to_string()));
                return respond(&mut stream, 400, "application/json", err.as_bytes());
            }
        }
    }
    // ------------------------------------------------------------------
    // Multisig wallet endpoints (M-of-N P2SH)
    if method == "POST" && path == "/api/multisig/create" {
        return handle_multisig_create(app, &query, &body_str, &mut stream);
    }
    if method == "POST" && path == "/api/multisig/build" {
        return handle_multisig_build(app, &query, &body_str, &mut stream);
    }
    if method == "POST" && path == "/api/multisig/sign" {
        return handle_multisig_sign(app, &query, &body_str, &mut stream);
    }
    if method == "POST" && path == "/api/multisig/combine" {
        return handle_multisig_combine(app, &query, &body_str, &mut stream);
    }
    if method == "POST" && path == "/api/multisig/submit" {
        return handle_multisig_submit(app, &query, &body_str, &mut stream);
    }
    if method == "POST" && path.starts_with("/api/") {
        let action = path.trim_start_matches("/api/");
        if let Some(node) = query.get("node") {
            app.select(node);
        }
        match dispatch(app, action, &query) {
            Ok(body) => {
                persist_all(&mut app.mesh);
                return respond(&mut stream, 200, "application/json", body.as_bytes());
            }
            Err(e) => return respond(&mut stream, 400, "text/plain; charset=utf-8", e.as_bytes()),
        }
    }
    respond(&mut stream, 404, "text/plain; charset=utf-8", b"not found")
}

/// Accept one or more blocks in the gossip wire format (`encode_records`
/// framing) on `POST /api/mine/submit`. This is the staked-block uplink: the
/// wire format is the only body that can carry a [`BlockRecord`]'s VRF bundle,
/// so a phone that won the sortition can push its block exactly as a peer
/// would receive it. Records are applied in order — parents must precede
/// children, the same contract as a full `/api/blocks` sync. Admission is
/// delegated entirely to [`Node::receive_block`] (and through it the ledger's
/// hybrid PoW / staked-VRF rules); no PoW pre-check is duplicated here.
/// Returns the last admitted block id.
fn submit_wire_block(
    app: &mut Explorer,
    node_name: &str,
    body: &[u8],
    stream: &mut TcpStream,
) -> std::io::Result<()> {
    let records = match decode_records(body) {
        Ok(records) if !records.is_empty() => records,
        Ok(_) => {
            let err = "{\"ok\":false,\"error\":\"empty wire body: no block records\"}";
            return respond(stream, 400, "application/json", err.as_bytes());
        }
        Err(e) => {
            let err = format!(
                "{{\"ok\":false,\"error\":{}}}",
                jstr(&format!("undecodable wire body: {e}"))
            );
            return respond(stream, 400, "application/json", err.as_bytes());
        }
    };

    let mut admitted: Vec<(BlockRecord, BlockId)> = Vec::with_capacity(records.len());
    {
        let Some(node) = app.mesh.node_mut(node_name) else {
            let err = format!("{{\"ok\":false,\"error\":\"unknown node {}\"}}", node_name);
            return respond(stream, 400, "application/json", err.as_bytes());
        };
        for record in &records {
            match node.receive_block(record.clone()) {
                Ok(id) => admitted.push((record.clone(), id)),
                Err(e) => {
                    let err = format!("{{\"ok\":false,\"error\":{}}}", jstr(&e.to_string()));
                    return respond(stream, 400, "application/json", err.as_bytes());
                }
            }
        }
    }
    for (record, _id) in &admitted {
        app.mesh.announce_block(node_name, record.clone());
    }
    persist_all(&mut app.mesh);
    let body = match admitted.last() {
        Some((_, id)) => format!("{{\"ok\":true,\"block\":{}}}", jstr(&id.to_string())),
        None => "{\"ok\":true}".into(),
    };
    respond(stream, 200, "application/json", body.as_bytes())
}

/// Light-sync blob framing, byte-compatible with the FFI's `KVLS` v1 format
/// (`crates/kovanica-ffi` `export_light_sync`): magic + version + count, then
/// per selected-chain block a 160-byte header followed by its Golomb-Rice
/// filter. A phone's `receive_light_sync` consumes this blob directly.
const LIGHT_SYNC_MAGIC: &[u8; 4] = b"KVLS";
const LIGHT_SYNC_VERSION: u8 = 1;
/// Golomb-Rice parameter for the per-block filters (the FFI's reference choice).
const LIGHT_SYNC_FILTER_K: u8 = 8;

fn encode_spv_header(h: &kovanica_state::spv::BlockHeader, out: &mut Vec<u8>) {
    out.extend_from_slice(h.id.as_bytes());
    out.extend_from_slice(h.prev_hash.as_bytes());
    out.extend_from_slice(&h.merkle_root);
    out.extend_from_slice(&h.work.to_be_bytes());
    out.extend_from_slice(&h.timestamp_ms.to_be_bytes());
    out.extend_from_slice(&h.nonce.to_be_bytes());
    out.extend_from_slice(&h.blue_score.to_be_bytes());
    out.extend_from_slice(&h.chain_blue_work.to_be_bytes());
    out.extend_from_slice(&h.height.to_be_bytes());
}

fn encode_spv_filter(f: &kovanica_state::spv::BlockFilter, out: &mut Vec<u8>) {
    out.push(f.k);
    out.extend_from_slice(&f.n.to_be_bytes());
    out.extend_from_slice(&(f.data.len() as u32).to_be_bytes());
    out.extend_from_slice(&f.data);
}

/// Assemble the light-sync blob from the shipped node helpers
/// ([`Node::export_spv_headers`] + [`Node::block_filter`]). `from` selects an
/// incremental window: headers strictly after `from` (exclusive) to the tip.
fn light_sync_blob(n: &Node, from: Option<&str>) -> Vec<u8> {
    let headers = n.export_spv_headers();
    let start = from
        .and_then(|s| hex::decode(s.trim()).ok())
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .and_then(|bytes| {
            let from_id = BlockId::from_bytes(bytes);
            headers.iter().position(|h| h.id == from_id).map(|i| i + 1)
        })
        .unwrap_or(0);
    let mut out = Vec::new();
    out.extend_from_slice(LIGHT_SYNC_MAGIC);
    out.push(LIGHT_SYNC_VERSION);
    out.extend_from_slice(&((headers.len() - start) as u32).to_be_bytes());
    for h in &headers[start..] {
        encode_spv_header(h, &mut out);
        match n.block_filter(&h.id, LIGHT_SYNC_FILTER_K) {
            Some(f) => encode_spv_filter(&f, &mut out),
            None => encode_spv_filter(
                &kovanica_state::spv::BlockFilter {
                    k: LIGHT_SYNC_FILTER_K,
                    n: 1,
                    data: Vec::new(),
                },
                &mut out,
            ),
        }
    }
    out
}

/// Merkle-proof blob, byte-compatible with the FFI's `encode_proof` layout:
/// tx_id(32) + merkle_root(32) + path_len(4) + path(32 each) + index(8) +
/// tx_count(8).
fn encode_merkle_proof(p: &kovanica_state::spv::MerkleProof) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&p.tx_id);
    out.extend_from_slice(&p.merkle_root);
    out.extend_from_slice(&(p.path.len() as u32).to_be_bytes());
    for s in &p.path {
        out.extend_from_slice(s);
    }
    out.extend_from_slice(&(p.index as u64).to_be_bytes());
    out.extend_from_slice(&(p.tx_count as u64).to_be_bytes());
    out
}

fn estimate_fee(node: &Node, _amount: u64) -> Result<(u64, u64, u64), String> {
    let mut block_tx_count = 0;
    let mut blocks_scanned = 0;

    if let Ok(mut current) = node.selected_tip() {
        for _ in 0..10 {
            if let Some(record) = node.block_record(&current) {
                block_tx_count += record.txs.len();
                blocks_scanned += 1;
                if let Some(parent) = record.parents.first() {
                    current = *parent;
                } else {
                    break;
                }
            } else {
                break;
            }
        }
    }

    let min = node.min_fee();
    // Assuming > 20 txs per block average is congested for this testnet
    let is_congested = blocks_scanned > 0 && (block_tx_count as f64 / blocks_scanned as f64) > 20.0;

    let pending = node.pending_txs();
    if pending.is_empty() {
        let base = if is_congested { min * 2 } else { min };
        return Ok((
            base,
            std::cmp::max(min + 1, base * 2),
            std::cmp::max(min + 2, base * 3),
        ));
    }

    let mut fees: Vec<u64> = pending
        .iter()
        .filter_map(|t| {
            if let Ok(ledger) = node.ledger() {
                let utxo = ledger.ledger_state();
                let mut sum_in = 0u64;
                for input in t.inputs() {
                    if let Some(prev) = utxo.get(&input.outpoint) {
                        sum_in = sum_in.saturating_add(prev.value);
                    }
                }
                let sum_out: u64 = t.outputs().iter().map(|o| o.value).sum();
                if sum_in > sum_out {
                    Some(sum_in - sum_out)
                } else {
                    None
                }
            } else {
                None
            }
        })
        .collect();

    if fees.is_empty() {
        let base = if is_congested { min * 2 } else { min };
        return Ok((
            base,
            std::cmp::max(min + 1, base * 2),
            std::cmp::max(min + 2, base * 3),
        ));
    }

    fees.sort();
    let p50_idx = (fees.len() as f64 * 0.5).floor() as usize;
    let p90_idx = (fees.len() as f64 * 0.9).floor() as usize;

    let p50 = fees[p50_idx.min(fees.len() - 1)];
    let p90 = fees[p90_idx.min(fees.len() - 1)];

    let mut slow = std::cmp::max(min, p50);
    let mut normal = std::cmp::max(min, p90);
    let mut fast = std::cmp::max(min, (p90 as f64 * 1.2) as u64);

    if is_congested {
        slow = std::cmp::max(slow, min * 2);
        normal = std::cmp::max(normal, min * 3);
        fast = std::cmp::max(fast, min * 5);
    }

    Ok((slow, normal, fast))
}

/// Parse a JSON body or respond with a 400 error.
fn parse_json_body(body_str: &str) -> Result<serde_json::Value, String> {
    serde_json::from_str(body_str).map_err(|e| format!("invalid json body: {e}"))
}

/// Return the named node, or respond with a 400 error.
fn selected_node<'a>(app: &'a Explorer, q: &HashMap<String, String>) -> Option<&'a Node> {
    let name = q.get("node").map(|s| s.as_str()).unwrap_or(&app.selected);
    app.mesh.node(name)
}

fn bad_request(stream: &mut TcpStream, msg: &str) -> std::io::Result<()> {
    let body = format!("{{\"ok\":false,\"error\":{}}}", jstr(msg));
    respond(stream, 400, "application/json", body.as_bytes())
}

fn ok_json(stream: &mut TcpStream, body: &str) -> std::io::Result<()> {
    respond(stream, 200, "application/json", body.as_bytes())
}

fn handle_multisig_create(
    app: &mut Explorer,
    q: &HashMap<String, String>,
    body_str: &str,
    stream: &mut TcpStream,
) -> std::io::Result<()> {
    let json = match parse_json_body(body_str) {
        Ok(j) => j,
        Err(e) => return bad_request(stream, &e),
    };
    let threshold = match json.get("threshold").and_then(|v| v.as_u64()) {
        Some(t) if (1..=16).contains(&t) => t as u8,
        _ => return bad_request(stream, "threshold must be between 1 and 16"),
    };
    let pubkeys_hex = match json.get("pubkeys_hex").and_then(|v| v.as_array()) {
        Some(arr) => arr,
        None => return bad_request(stream, "pubkeys_hex must be an array"),
    };
    let mut pubkeys = Vec::with_capacity(pubkeys_hex.len());
    for (i, pk) in pubkeys_hex.iter().enumerate() {
        let s = match pk.as_str() {
            Some(s) => s,
            None => return bad_request(stream, &format!("pubkeys_hex[{i}] is not a string")),
        };
        let bytes = match hex::decode(s.trim()) {
            Ok(b) => b,
            Err(_) => return bad_request(stream, &format!("pubkeys_hex[{i}] is not hex")),
        };
        let arr = match <[u8; 32]>::try_from(bytes) {
            Ok(a) => a,
            Err(_) => return bad_request(stream, &format!("pubkeys_hex[{i}] must be 32 bytes")),
        };
        pubkeys.push(arr);
    }

    let node_name = q
        .get("node")
        .map(|s| s.as_str())
        .unwrap_or(&app.selected)
        .to_string();
    let node = match app.mesh.node_mut(&node_name) {
        Some(n) => n,
        None => return bad_request(stream, &format!("unknown node {node_name}")),
    };

    match node.create_multisig_address(threshold, pubkeys) {
        Ok((address, redeem_script)) => {
            let body = format!(
                "{{\"address\":{},\"redeem_script_hex\":{}}}",
                jstr(&address.to_kvnc()),
                jstr(&hex::encode(redeem_script))
            );
            ok_json(stream, &body)
        }
        Err(e) => bad_request(stream, &e.to_string()),
    }
}

fn handle_multisig_build(
    app: &mut Explorer,
    q: &HashMap<String, String>,
    body_str: &str,
    stream: &mut TcpStream,
) -> std::io::Result<()> {
    let json = match parse_json_body(body_str) {
        Ok(j) => j,
        Err(e) => return bad_request(stream, &e),
    };
    let address = match json.get("address").and_then(|v| v.as_str()) {
        Some(s) => match parse_addr(s) {
            Ok(a) => a,
            Err(e) => return bad_request(stream, &e),
        },
        None => return bad_request(stream, "address is required"),
    };
    let outputs_arr = match json.get("outputs").and_then(|v| v.as_array()) {
        Some(arr) => arr,
        None => return bad_request(stream, "outputs must be an array"),
    };
    let mut outputs = Vec::with_capacity(outputs_arr.len());
    for (i, o) in outputs_arr.iter().enumerate() {
        let addr = match o.get("address").and_then(|v| v.as_str()) {
            Some(s) => match parse_addr(s) {
                Ok(a) => a,
                Err(e) => return bad_request(stream, &format!("outputs[{i}].address: {e}")),
            },
            None => return bad_request(stream, &format!("outputs[{i}].address is required")),
        };
        let amount = match o.get("amount_atoms").and_then(|v| v.as_u64()) {
            Some(v) => v,
            None => return bad_request(stream, &format!("outputs[{i}].amount_atoms is required")),
        };
        outputs.push(TxOutput::new(amount, addr));
    }

    let node = match selected_node(app, q) {
        Some(n) => n,
        None => return bad_request(stream, "unknown node"),
    };

    match node.build_multisig_spend(address, outputs) {
        Ok(tx) => {
            let body = format!(
                "{{\"tx_blob_hex\":{},\"sighash_hex\":{}}}",
                jstr(&hex::encode(tx.encode())),
                jstr(&hex::encode(tx.sighash()))
            );
            ok_json(stream, &body)
        }
        Err(e) => bad_request(stream, &e.to_string()),
    }
}

fn decode_tx_blob(body: &serde_json::Value, field: &str) -> Result<Transaction, String> {
    let hex_str = body
        .get(field)
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("{field} is required"))?;
    let bytes = hex::decode(hex_str.trim()).map_err(|_| format!("{field} is not hex"))?;
    Transaction::decode(&bytes).map_err(|e| format!("{field} decode error: {e:?}"))
}

fn parse_partial_sigs(body: &serde_json::Value) -> Result<Vec<[u8; 64]>, String> {
    let arr = body
        .get("partial_sigs_hex")
        .and_then(|v| v.as_array())
        .ok_or("partial_sigs_hex must be an array")?;
    let mut out = Vec::with_capacity(arr.len());
    for (i, sig) in arr.iter().enumerate() {
        let s = sig
            .as_str()
            .ok_or_else(|| format!("partial_sigs_hex[{i}] is not a string"))?;
        let bytes =
            hex::decode(s.trim()).map_err(|_| format!("partial_sigs_hex[{i}] is not hex"))?;
        let arr = <[u8; 64]>::try_from(bytes)
            .map_err(|_| format!("partial_sigs_hex[{i}] must be 64 bytes"))?;
        out.push(arr);
    }
    Ok(out)
}

fn handle_multisig_sign(
    app: &mut Explorer,
    q: &HashMap<String, String>,
    body_str: &str,
    stream: &mut TcpStream,
) -> std::io::Result<()> {
    let json = match parse_json_body(body_str) {
        Ok(j) => j,
        Err(e) => return bad_request(stream, &e),
    };
    let tx = match decode_tx_blob(&json, "tx_blob_hex") {
        Ok(t) => t,
        Err(e) => return bad_request(stream, &e),
    };
    let secret_hex = match json.get("secret_hex").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return bad_request(stream, "secret_hex is required"),
    };

    let node = match selected_node(app, q) {
        Some(n) => n,
        None => return bad_request(stream, "unknown node"),
    };

    match node.sign_multisig_partial(&tx, secret_hex) {
        Ok(sig) => {
            let body = format!("{{\"partial_sig_hex\":{}}}", jstr(&hex::encode(sig)));
            ok_json(stream, &body)
        }
        Err(e) => bad_request(stream, &e.to_string()),
    }
}

fn handle_multisig_combine(
    app: &mut Explorer,
    q: &HashMap<String, String>,
    body_str: &str,
    stream: &mut TcpStream,
) -> std::io::Result<()> {
    let json = match parse_json_body(body_str) {
        Ok(j) => j,
        Err(e) => return bad_request(stream, &e),
    };
    let tx = match decode_tx_blob(&json, "tx_blob_hex") {
        Ok(t) => t,
        Err(e) => return bad_request(stream, &e),
    };
    let partial_sigs = match parse_partial_sigs(&json) {
        Ok(s) => s,
        Err(e) => return bad_request(stream, &e),
    };

    let node = match selected_node(app, q) {
        Some(n) => n,
        None => return bad_request(stream, "unknown node"),
    };

    match node.combine_multisig_sigs(&tx, partial_sigs) {
        Ok(tx) => {
            let body = format!(
                "{{\"signed_tx_blob_hex\":{}}}",
                jstr(&hex::encode(tx.encode()))
            );
            ok_json(stream, &body)
        }
        Err(e) => bad_request(stream, &e.to_string()),
    }
}

fn handle_multisig_submit(
    app: &mut Explorer,
    q: &HashMap<String, String>,
    body_str: &str,
    stream: &mut TcpStream,
) -> std::io::Result<()> {
    let json = match parse_json_body(body_str) {
        Ok(j) => j,
        Err(e) => return bad_request(stream, &e),
    };
    let tx = match decode_tx_blob(&json, "signed_tx_blob_hex") {
        Ok(t) => t,
        Err(e) => return bad_request(stream, &e),
    };

    let node_name = q
        .get("node")
        .map(|s| s.as_str())
        .unwrap_or(&app.selected)
        .to_string();
    let node = match app.mesh.node_mut(&node_name) {
        Some(n) => n,
        None => return bad_request(stream, &format!("unknown node {node_name}")),
    };

    match node.submit_multisig_tx(tx) {
        Ok(tx_id) => {
            let body = format!("{{\"tx_id_hex\":{}}}", jstr(&hex::encode(tx_id.as_bytes())));
            ok_json(stream, &body)
        }
        Err(e) => bad_request(stream, &e.to_string()),
    }
}

fn dispatch(
    app: &mut Explorer,
    action: &str,
    q: &std::collections::HashMap<String, String>,
) -> Result<String, String> {
    let node = q
        .get("node")
        .cloned()
        .unwrap_or_else(|| app.selected.clone());
    match action {
        "mine" | "produce" => match app.mesh.produce(&node).map_err(|e| e.to_string())? {
            Some(_) => {}
            None => {
                if !app.operator {
                    return Err("mempool empty".into());
                }
                app.mesh.produce_empty(&node).map_err(|e| e.to_string())?;
            }
        },
        "empty" | "send" | "pool" | "parallel" | "fork" | "mining" | "miner" => {
            if !app.operator {
                return Err("operator only".into());
            }
            match action {
                "empty" => {
                    app.mesh.produce_empty(&node).map_err(|e| e.to_string())?;
                }
                "send" => {
                    let from = parse_u64(q, "from", 1)?;
                    let amount = parse_u64(q, "amount", 50)?;
                    let to = parse_u64(q, "to", 2)?;
                    app.mesh
                        .send(&node, from, amount, to)
                        .map_err(|e| e.to_string())?;
                }
                "pool" => {
                    let from = parse_u64(q, "from", 1)?;
                    let amount = parse_u64(q, "amount", 50)?;
                    let to = parse_u64(q, "to", 2)?;
                    app.mesh
                        .pool(&node, from, amount, to)
                        .map_err(|e| e.to_string())?;
                }
                "parallel" => {
                    let _ = app.mesh.send("alpha", 1, ATOM, 2);
                    let _ = app.mesh.send("beta", 1, ATOM, 3);
                }
                "fork" => {
                    for name in app.mesh.names() {
                        let _ = app.mesh.produce_empty(&name);
                    }
                }
                "mining" => {
                    app.mining = q.get("on").map(|v| v != "0").unwrap_or(true);
                }
                "miner" => {
                    let addr = parse_addr(q.get("addr").ok_or("addr required")?)?;
                    let n = app
                        .mesh
                        .node_mut(&node)
                        .ok_or_else(|| "unknown node".to_string())?;
                    n.set_miner(addr);
                    return Ok(format!(
                        "{{\"ok\":true,\"miner\":{}}}",
                        jstr(&addr.to_hex())
                    ));
                }
                _ => {}
            }
        }
        "reset" => {
            if !app.allow_reset {
                return Err("reset disabled on this network".into());
            }
            wipe_data();
            *app = Explorer::boot_persist();
        }
        "origin" => {
            let iso = q.get("iso3").ok_or("iso3 required")?;
            if iso.len() != 3 || !iso.chars().all(|c| c.is_ascii_alphabetic()) {
                return Err("iso3 required".into());
            }
            let code = iso.to_ascii_uppercase();
            let pulses = {
                let n = app.origins.entry(code.clone()).or_insert(0);
                *n = n.saturating_add(1);
                *n
            };
            save_origins(&app.origins);
            return Ok(format!(
                "{{\"ok\":true,\"iso3\":{},\"pulses\":{}}}",
                jstr(&code),
                pulses
            ));
        }
        "prepare" => {
            let from = parse_addr(q.get("from").ok_or("from address required")?)?;
            let to = parse_addr(q.get("to").ok_or("to address required")?)?;
            let amount = parse_u64(q, "amount", 0)?;
            let n = app.mesh.node(&node).ok_or("unknown node")?;
            let p = n
                .prepare_transfer(from, amount, to)
                .map_err(|e| e.to_string())?;
            return Ok(format!(
                "{{\"ok\":true,\"sighash\":{},\"value\":{},\"fee\":{},\"change\":{},\"outpoint\":{{\"tx\":{},\"index\":{}}}}}",
                jstr(&hex::encode(p.sighash)),
                p.value,
                p.fee,
                p.value.saturating_sub(amount.saturating_add(p.fee)),
                jstr(&p.outpoint.tx.to_string()),
                p.outpoint.index
            ));
        }
        "submit" => {
            let from = parse_addr(q.get("from").ok_or("from address required")?)?;
            let to = parse_addr(q.get("to").ok_or("to address required")?)?;
            let amount = parse_u64(q, "amount", 0)?;
            let sig = parse_sig(q.get("sig").ok_or("sig required")?)?;
            let id = app
                .mesh
                .submit_signed(&node, from, amount, to, sig)
                .map_err(|e| e.to_string())?;
            app.mesh.drain(8);
            return Ok(format!("{{\"ok\":true,\"tx\":{}}}", jstr(&id.to_string())));
        }
        "faucet" => {
            if !app.faucet {
                return Err("faucet disabled".into());
            }
            // D1: the faucet is testnet-only. On any other profile (mainnet
            // included) it refuses to pay out regardless of the operator flag.
            if network_profile().id != "kovanica-testnet" {
                return Err("faucet is testnet-only".into());
            }
            let to = parse_addr(q.get("to").ok_or("to address required")?)?;
            let amount = parse_u64(q, "amount", ATOM)?;
            if amount > FAUCET_MAX_PER_ADDRESS {
                return Err(format!(
                    "faucet max {FAUCET_MAX_PER_ADDRESS} atoms per request"
                ));
            }
            // Per-address lifetime cap: an address cannot drain the operator
            // funds by replaying the faucet.
            let key = to.to_hex();
            let given = app.faucet_given.get(&key).copied().unwrap_or(0);
            if given.saturating_add(amount) > FAUCET_MAX_PER_ADDRESS {
                return Err("faucet per-address cap reached".into());
            }
            let block = app
                .mesh
                .send_to(&node, 1, amount, to)
                .map_err(|e| e.to_string())?;
            app.faucet_given.insert(key, given + amount);
            save_faucet_given(&app.faucet_given);
            app.mesh.drain(8);
            return Ok(format!(
                "{{\"ok\":true,\"block\":{}}}",
                jstr(&block.to_string())
            ));
        }
        "fee_estimate" => {
            let amount = parse_u64(q, "amount", 0)?;
            let n = app.mesh.node(&node).ok_or("unknown node")?;
            let (slow, normal, fast) = estimate_fee(n, amount)?;
            return Ok(format!(
                "{{\"ok\":true,\"slow\":{},\"normal\":{},\"fast\":{}}}",
                slow, normal, fast
            ));
        }
        other => return Err(format!("unknown action {other}")),
    }
    app.mesh.drain(8);
    Ok("{\"ok\":true}".into())
}

fn history_json(
    app: &Explorer,
    q: &std::collections::HashMap<String, String>,
) -> Result<String, String> {
    let addr = parse_addr(q.get("address").ok_or("address required")?)?;
    let node_name = q
        .get("node")
        .cloned()
        .unwrap_or_else(|| app.selected.clone());
    let n = app.mesh.node(&node_name).ok_or("unknown node")?;
    let ledger = n.ledger().map_err(|e| e.to_string())?;
    let limit = parse_u64(q, "limit", 100)?.min(1000);
    let offset = parse_u64(q, "offset", 0)?;
    let order = ledger.dag().linearize();
    let mut by_id: HashMap<kovanica_state::TxId, kovanica_state::Transaction> = HashMap::new();
    let mut items = Vec::new();
    for id in &order {
        let Some(rec) = n.block_record(id) else {
            continue;
        };
        for tx in rec.txs {
            by_id.insert(tx.id(), tx);
        }
    }
    for id in &order {
        let Some(rec) = n.block_record(id) else {
            continue;
        };
        for tx in &rec.txs {
            let mut delta: i128 = 0;
            for o in tx.outputs() {
                if o.owner == addr {
                    delta += o.value as i128;
                }
            }
            for inp in tx.inputs() {
                if let Some(prev) = by_id.get(&inp.outpoint.tx) {
                    if let Some(o) = prev.outputs().get(inp.outpoint.index as usize) {
                        if o.owner == addr {
                            delta -= o.value as i128;
                        }
                    }
                }
            }
            if delta == 0 {
                continue;
            }
            let kind = if tx.is_coinbase() {
                "coinbase"
            } else if delta > 0 {
                "in"
            } else {
                "out"
            };
            items.push(format!(
                "{{\"block\":{},\"tx\":{},\"kind\":{},\"delta\":{}}}",
                jstr(&id.to_string()),
                jstr(&tx.id().to_string()),
                jstr(kind),
                delta
            ));
        }
    }
    let total = items.len();
    let paginated: Vec<_> = items
        .into_iter()
        .skip(offset as usize)
        .take(limit as usize)
        .collect();
    Ok(format!(
        "{{\"address\":{},\"balance\":{},\"txs\":{},\"limit\":{},\"offset\":{},\"total\":{}}}",
        jstr(&addr.to_hex()),
        n.balance(&addr).map_err(|e| e.to_string())?,
        jarr(paginated.into_iter()),
        limit,
        offset,
        total
    ))
}

fn utxos_json(
    app: &Explorer,
    q: &std::collections::HashMap<String, String>,
) -> Result<String, String> {
    let addr = parse_addr(q.get("address").ok_or("address required")?)?;
    let node = q
        .get("node")
        .cloned()
        .unwrap_or_else(|| app.selected.clone());
    let n = app.mesh.node(&node).ok_or("unknown node")?;
    let bal = n.balance(&addr).map_err(|e| e.to_string())?;
    let limit = parse_u64(q, "limit", 100)?.min(1000);
    let offset = parse_u64(q, "offset", 0)?;
    let rows = n.utxos_of(&addr).map_err(|e| e.to_string())?;
    let total = rows.len();
    let items = rows
        .into_iter()
        .skip(offset as usize)
        .take(limit as usize)
        .map(|(op, value)| {
            format!(
                "{{\"tx\":{},\"index\":{},\"value\":{}}}",
                jstr(&op.tx.to_string()),
                op.index,
                value
            )
        });
    Ok(format!(
        "{{\"address\":{},\"balance\":{},\"utxos\":{},\"limit\":{},\"offset\":{},\"total\":{}}}",
        jstr(&addr.to_hex()),
        bal,
        jarr(items),
        limit,
        offset,
        total
    ))
}

fn err_json(msg: &str) -> String {
    format!("{{\"ok\":false,\"error\":{}}}", jstr(msg))
}

fn parse_block_id(s: &str) -> Result<BlockId, String> {
    let bytes = hex::decode(s.trim()).map_err(|_| "block id is not hex".to_string())?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "block id must be 32 bytes".to_string())?;
    Ok(BlockId::from_bytes(arr))
}

fn parse_tx_id(s: &str) -> Result<TxId, String> {
    let bytes = hex::decode(s.trim()).map_err(|_| "tx id is not hex".to_string())?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "tx id must be 32 bytes".to_string())?;
    Ok(TxId::from_bytes(arr))
}

fn block_kind(
    id: BlockId,
    genesis: BlockId,
    chain: &HashSet<BlockId>,
    blue: &HashSet<BlockId>,
) -> &'static str {
    if id == genesis {
        "genesis"
    } else if chain.contains(&id) {
        "chain"
    } else if blue.contains(&id) {
        "blue"
    } else {
        "red"
    }
}

fn block_detail_json(app: &Explorer, id_hex: &str) -> Result<String, String> {
    let id = parse_block_id(id_hex)?;
    let node_name = app.selected.clone();
    let n = app.mesh.node(&node_name).ok_or("unknown node")?;
    let ledger = n.ledger().map_err(|e| e.to_string())?;
    let dag = ledger.dag();
    if dag.block(&id).is_none() {
        return Err("block not found".into());
    }
    let rec = n.block_record(&id).ok_or("block not found")?;
    let children = n.block_children(&id).map_err(|e| e.to_string())?;
    let genesis = dag.genesis();
    let chain: HashSet<BlockId> = dag.selected_chain().into_iter().collect();
    let tip_id = n.selected_tip().ok();
    let gd = tip_id.as_ref().and_then(|id| dag.ghostdag(id));
    let blue_set: HashSet<BlockId> = gd
        .map(|g| g.blue_anticone_sizes.keys().copied().collect())
        .unwrap_or_default();
    let colour = block_kind(id, genesis, &chain, &blue_set);
    let kind = if rec.vrf.is_some() { "staked" } else { "pow" };
    let confirming_status = if tip_id == Some(id) {
        "tip"
    } else if chain.contains(&id) {
        "confirmed"
    } else if blue_set.contains(&id) {
        "accepted"
    } else {
        "pending"
    };
    let ghostdag = dag.ghostdag(&id);
    let blue_score = ghostdag.map(|g| g.blue_score).unwrap_or(0);
    let chain_blue_work = ghostdag.map(|g| g.blue_work).unwrap_or(0);

    let (prev_hash, merkle_root, height) = {
        let mut height = 0u64;
        let mut cur = ghostdag.and_then(|g| g.selected_parent);
        while let Some(pid) = cur {
            height += 1;
            cur = dag.ghostdag(&pid).and_then(|g| g.selected_parent);
        }
        let prev = ghostdag
            .and_then(|g| g.selected_parent)
            .unwrap_or_else(|| BlockId::from_bytes([0u8; 32]));
        (prev, kovanica_state::spv::merkle_root(&rec.txs), height)
    };

    Ok(format!(
        "{{\"id\":{},\"prev_hash\":{},\"merkle_root\":{},\"height\":{},\"timestamp_ms\":{},\"nonce\":{},\"blue_score\":{},\"chain_blue_work\":{},\"work\":{},\"parents\":{},\"children\":{},\"txs\":{},\"kind\":{},\"colour\":{},\"confirming_status\":{}}}",
        jstr(&id.to_string()),
        jstr(&prev_hash.to_string()),
        jstr(&hex::encode(merkle_root)),
        height,
        rec.timestamp_ms,
        rec.nonce,
        blue_score,
        chain_blue_work,
        rec.work,
        jarr(rec.parents.iter().map(|p| jstr(&p.to_string()))),
        jarr(children.iter().map(|c| jstr(&c.to_string()))),
        jarr(rec.txs.iter().map(|tx| jstr(&tx.id().to_string()))),
        jstr(kind),
        jstr(colour),
        jstr(confirming_status)
    ))
}

fn tx_input_json(
    input: &kovanica_state::TxInput,
    prev_by_tx: &HashMap<TxId, Transaction>,
    prev_by_outpoint: &HashMap<OutPoint, TxOutput>,
) -> String {
    let prev = prev_by_outpoint.get(&input.outpoint).copied().or_else(|| {
        prev_by_tx
            .get(&input.outpoint.tx)
            .and_then(|p| p.outputs().get(input.outpoint.index as usize).copied())
    });
    let prev_owner = prev.map(|o| o.owner.to_hex());
    format!(
        "{{\"tx\":{},\"index\":{},\"prev_owner\":{},\"value\":{}}}",
        jstr(&input.outpoint.tx.to_string()),
        input.outpoint.index,
        prev_owner
            .as_deref()
            .map(jstr)
            .unwrap_or_else(|| "null".into()),
        prev.map(|o| o.value).unwrap_or(0)
    )
}

fn tx_detail_json(app: &Explorer, id_hex: &str) -> Result<String, String> {
    let id = parse_tx_id(id_hex)?;
    let node_name = app.selected.clone();
    let n = app.mesh.node(&node_name).ok_or("unknown node")?;

    // Mempool path: the tx may spend outputs still in the UTXO set.
    if let Some(tx) = n.mempool_tx(&id) {
        let ledger = n.ledger().map_err(|e| e.to_string())?;
        let utxo = ledger.ledger_state();
        let mut prev_by_outpoint = HashMap::new();
        for input in tx.inputs() {
            if let Some(out) = utxo.get(&input.outpoint) {
                prev_by_outpoint.insert(input.outpoint, *out);
            }
        }
        let amount: u64 = tx.outputs().iter().map(|o| o.value).sum();
        let input_value: u64 = tx
            .inputs()
            .iter()
            .map(|inp| {
                prev_by_outpoint
                    .get(&inp.outpoint)
                    .map(|o| o.value)
                    .unwrap_or(0)
            })
            .sum();
        let fee = if tx.is_coinbase() {
            0
        } else {
            input_value.saturating_sub(amount)
        };
        let addresses = tx_addresses(&tx, &HashMap::new(), &prev_by_outpoint);
        let inputs = jarr(
            tx.inputs()
                .iter()
                .map(|inp| tx_input_json(inp, &HashMap::new(), &prev_by_outpoint)),
        );
        let outputs = jarr(tx.outputs().iter().map(|o| {
            format!(
                "{{\"value\":{},\"owner\":{}}}",
                o.value,
                jstr(&o.owner.to_hex())
            )
        }));
        return Ok(format!(
            "{{\"id\":{},\"coinbase\":{},\"confirmed\":false,\"confirmations\":0,\"block\":null,\"blue_score\":null,\"amount\":{},\"fee\":{},\"addresses\":{},\"inputs\":{},\"outputs\":{},\"size\":{}}}",
            jstr(&tx.id().to_string()),
            tx.is_coinbase(),
            amount,
            fee,
            jarr(addresses.into_iter().map(|s| jstr(&s))),
            inputs,
            outputs,
            tx.encode().len()
        ));
    }

    let confirmation = n.tx_confirmation(&id).map_err(|e| e.to_string())?;
    let (block_id, blue_score) = confirmation.ok_or("tx not found")?;
    let rec = n.block_record(&block_id).ok_or("block not found")?;
    let tx = rec
        .txs
        .iter()
        .find(|t| t.id() == id)
        .ok_or("tx not found")?;

    let ledger = n.ledger().map_err(|e| e.to_string())?;
    let tip_blue_score = n
        .selected_tip()
        .ok()
        .and_then(|tip| ledger.dag().ghostdag(&tip))
        .map(|g| g.blue_score)
        .unwrap_or(0);
    let confirmations = tip_blue_score.saturating_sub(blue_score) + 1;

    let mut prev_by_tx: HashMap<TxId, Transaction> = HashMap::new();
    for block_id2 in ledger.dag().linearize() {
        if let Some(rec2) = n.block_record(&block_id2) {
            for t in rec2.txs {
                prev_by_tx.insert(t.id(), t);
            }
        }
    }

    let amount: u64 = tx.outputs().iter().map(|o| o.value).sum();
    let input_value: u64 = tx
        .inputs()
        .iter()
        .map(|inp| {
            prev_by_tx
                .get(&inp.outpoint.tx)
                .and_then(|p| {
                    p.outputs()
                        .get(inp.outpoint.index as usize)
                        .map(|o| o.value)
                })
                .unwrap_or(0)
        })
        .sum();
    let fee = if tx.is_coinbase() {
        0
    } else {
        input_value.saturating_sub(amount)
    };
    let addresses = tx_addresses(tx, &prev_by_tx, &HashMap::new());
    let inputs = jarr(
        tx.inputs()
            .iter()
            .map(|inp| tx_input_json(inp, &prev_by_tx, &HashMap::new())),
    );
    let outputs = jarr(tx.outputs().iter().map(|o| {
        format!(
            "{{\"value\":{},\"owner\":{}}}",
            o.value,
            jstr(&o.owner.to_hex())
        )
    }));

    Ok(format!(
        "{{\"id\":{},\"coinbase\":{},\"confirmed\":true,\"confirmations\":{},\"block\":{},\"blue_score\":{},\"amount\":{},\"fee\":{},\"addresses\":{},\"inputs\":{},\"outputs\":{},\"size\":{}}}",
        jstr(&tx.id().to_string()),
        tx.is_coinbase(),
        confirmations,
        jstr(&block_id.to_string()),
        blue_score,
        amount,
        fee,
        jarr(addresses.into_iter().map(|s| jstr(&s))),
        inputs,
        outputs,
        tx.encode().len()
    ))
}

fn tx_addresses(
    tx: &Transaction,
    prev_by_tx: &HashMap<TxId, Transaction>,
    prev_by_outpoint: &HashMap<OutPoint, TxOutput>,
) -> Vec<String> {
    let mut set = HashSet::new();
    for input in tx.inputs() {
        if let Some(prev) = prev_by_outpoint.get(&input.outpoint).copied().or_else(|| {
            prev_by_tx
                .get(&input.outpoint.tx)
                .and_then(|p| p.outputs().get(input.outpoint.index as usize).copied())
        }) {
            set.insert(prev.owner.to_hex());
        }
    }
    for output in tx.outputs() {
        set.insert(output.owner.to_hex());
    }
    let mut v: Vec<_> = set.into_iter().collect();
    v.sort_unstable();
    v
}

fn address_detail_json(
    app: &Explorer,
    addr_hex: &str,
    q: &std::collections::HashMap<String, String>,
) -> Result<String, String> {
    let addr = parse_addr(addr_hex)?;
    let node_name = q
        .get("node")
        .cloned()
        .unwrap_or_else(|| app.selected.clone());
    let n = app.mesh.node(&node_name).ok_or("unknown node")?;
    let balance = n.balance(&addr).map_err(|e| e.to_string())?;

    let page = q
        .get("page")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(1)
        .max(1);
    let per_page = q
        .get("per_page")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(20)
        .clamp(1, 100);
    let offset = (page - 1) * per_page;

    let events = n.history_of(&addr, 0).map_err(|e| e.to_string())?;
    let total = events.len();
    let page_events: Vec<_> = events.into_iter().skip(offset).take(per_page).collect();

    let items = page_events.into_iter().map(|e| {
        let kind = match e.direction {
            WalletDirection::Received => "in",
            WalletDirection::Sent => "out",
        };
        format!(
            "{{\"tx\":{},\"block\":{},\"kind\":{},\"amount\":{}}}",
            jstr(&e.tx_id.to_string()),
            jstr(&e.block_id.to_string()),
            jstr(kind),
            e.amount
        )
    });

    let pages = total.div_ceil(per_page);

    Ok(format!(
        "{{\"address\":{},\"balance\":{},\"page\":{},\"per_page\":{},\"total\":{},\"pages\":{},\"txs\":{}}}",
        jstr(&addr.to_hex()),
        balance,
        page,
        per_page,
        total,
        pages,
        jarr(items)
    ))
}
fn fee_estimate_json(
    app: &Explorer,
    q: &std::collections::HashMap<String, String>,
) -> Result<String, String> {
    let node = q
        .get("node")
        .cloned()
        .unwrap_or_else(|| app.selected.clone());
    let n = app.mesh.node(&node).ok_or("unknown node")?;
    let rate = n.fee_estimate().map_err(|e| e.to_string())?;
    Ok(format!(
        "{{\"fee_rate\":{},\"unit\":{},\"mempool\":{},\"bytes\":{}}}",
        rate,
        jstr("atoms/byte"),
        n.pending_count(),
        n.mempool_bytes()
    ))
}

fn parse_addr(s: &str) -> Result<Address, String> {
    Address::parse(s).map_err(|e| e.to_string())
}

fn decode_block_id_hex(s: &str) -> Result<BlockId, String> {
    let bytes = hex::decode(s.trim()).map_err(|_| "from is not hex".to_string())?;
    let arr = bytes
        .try_into()
        .map_err(|_| "from must be 32 bytes".to_string())?;
    Ok(BlockId::from_bytes(arr))
}

fn parse_sig(s: &str) -> Result<[u8; 64], String> {
    let bytes = hex::decode(s.trim()).map_err(|_| "sig is not hex".to_string())?;
    bytes
        .try_into()
        .map_err(|_| "sig must be 64 bytes".to_string())
}

fn parse_u64(
    q: &std::collections::HashMap<String, String>,
    key: &str,
    default: u64,
) -> Result<u64, String> {
    match q.get(key) {
        None => Ok(default),
        Some(s) => s.parse().map_err(|_| format!("bad {key}")),
    }
}

fn split_query(target: &str) -> (&str, std::collections::HashMap<String, String>) {
    match target.split_once('?') {
        None => (target, std::collections::HashMap::new()),
        Some((path, q)) => {
            let mut map = std::collections::HashMap::new();
            for pair in q.split('&') {
                if let Some((k, v)) = pair.split_once('=') {
                    map.insert(k.to_string(), urlencoding_decode(v));
                }
            }
            (path, map)
        }
    }
}

fn urlencoding_decode(s: &str) -> String {
    // Query values here are digits / node names; keep it strict.
    s.replace('+', " ")
}

fn respond(stream: &mut TcpStream, code: u16, ctype: &str, body: &[u8]) -> std::io::Result<()> {
    let reason = match code {
        200 => "OK",
        400 => "Bad Request",
        _ => "Not Found",
    };
    let head = format!(
        "HTTP/1.1 {code} {reason}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()
}

fn respond_download(
    stream: &mut TcpStream,
    ctype: &str,
    filename: &str,
    body: &[u8],
) -> std::io::Result<()> {
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: {ctype}\r\nContent-Disposition: attachment; filename=\"{filename}\"\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()
}

fn respond_prometheus_metrics(stream: &mut TcpStream) -> std::io::Result<()> {
    // Render the live recorder payload (same series the dedicated scrape
    // endpoint on :9090 serves).
    let body = render_prometheus();
    respond(
        stream,
        200,
        "text/plain; version=0.0.4; charset=utf-8",
        body.as_bytes(),
    )
}

fn snapshot(app: &Explorer) -> String {
    let selected = &app.selected;
    let node = app.mesh.node(selected).expect("selected exists");
    let mut nodes = Vec::new();
    for name in app.mesh.names() {
        let n = app.mesh.node(&name).expect("named");
        let tip = n.selected_tip().map(|t| t.to_string()).unwrap_or_default();
        nodes.push(format!(
            "{{\"name\":{},\"blocks\":{},\"tip\":{},\"peers\":{},\"mempool\":{}}}",
            jstr(&name),
            n.block_count().unwrap_or(0),
            jstr(&tip),
            jarr(app.mesh.peers_of(&name).iter().map(|s| jstr(s))),
            n.pending_count()
        ));
    }
    let events: Vec<String> = app
        .mesh
        .events()
        .iter()
        .rev()
        .take(48)
        .map(|e| {
            format!(
                "{{\"at\":{},\"from\":{},\"to\":{},\"kind\":{}}}",
                e.at,
                jstr(&e.from),
                jstr(&e.to),
                jstr(&format!("{:?}", e.kind).to_lowercase())
            )
        })
        .collect();
    format!(
        "{{\"selected\":{},\"mining\":{},\"faucet\":{},\"allow_reset\":{},\"operator\":{},\"network\":{},\"listen\":{},\"peers\":{},\"mesh\":{{\"now\":{},\"queued\":{},\"nodes\":{},\"events\":{}}},\"node\":{},\"wallets\":{}}}",
        jstr(selected),
        app.mining,
        app.faucet,
        app.allow_reset,
        app.operator,
        jstr(network_profile().id),
        jstr(&app.listen_addr),
        jarr(app.peers.iter().map(|s| jstr(s))),
        app.mesh.now(),
        app.mesh.queued(),
        jarr(nodes.into_iter()),
        jarr(events.into_iter()),
        node_json(node),
        wallets_json(node),
    )
}

fn node_json(node: &Node) -> String {
    let Ok(ledger) = node.ledger() else {
        return "{\"blocks\":0,\"dag\":[],\"order\":[],\"tips\":[],\"pending\":[]}".into();
    };
    let dag = ledger.dag();
    let selected_tip = node
        .selected_tip()
        .map(|t| t.to_string())
        .unwrap_or_default();
    let chain: Vec<BlockId> = dag.selected_chain();
    let chain_set: HashSet<BlockId> = chain.iter().copied().collect();
    let tip_id = node.selected_tip().ok();
    let gd = tip_id.as_ref().and_then(|id| dag.ghostdag(id));
    let blue_set: HashSet<BlockId> = gd
        .map(|g| g.blue_anticone_sizes.keys().copied().collect())
        .unwrap_or_default();
    let genesis = dag.genesis();
    let order = dag.linearize();
    let mut tx_count = 0usize;
    let dag_json: Vec<String> = order
        .iter()
        .filter_map(|id| {
            let rec = node.block_record(id)?;
            tx_count += rec.txs.len();
            let colour = colour_of(*id, genesis, &chain_set, &blue_set);
            let g = dag.ghostdag(id)?;
            Some(format!(
                "{{\"id\":{},\"parents\":{},\"selected_parent\":{},\"work\":{},\"timestamp_ms\":{},\"nonce\":{},\"blue_score\":{},\"colour\":{},\"txs\":{}}}",
                jstr(&id.to_string()),
                jarr(rec.parents.iter().map(|p| jstr(&p.to_string()))),
                match g.selected_parent {
                    Some(sp) => jstr(&sp.to_string()),
                    None => "null".into(),
                },
                rec.work,
                rec.timestamp_ms,
                rec.nonce,
                g.blue_score,
                jstr(colour),
                jarr(rec.txs.iter().map(tx_json)),
            ))
        })
        .collect();
    let pending = jarr(node.pending_txs().iter().map(|tx| pending_json(node, tx)));
    let utxo = ledger.ledger_state();
    format!(
        "{{\"blocks\":{},\"tips\":{},\"selected_tip\":{},\"blue_score\":{},\"blue_work\":{},\"k\":{},\"subsidy\":{},\"issuance\":{},\"halving_era\":{},\"min_fee\":{},\"genesis\":{},\"supply\":{},\"token\":{},\"decimals\":{},\"miner\":{},\"atom\":{},\"pow\":{},\"ui\":{},\"utxos\":{},\"chain_len\":{},\"mempool\":{},\"tx_count\":{},\"dag\":{},\"order\":{},\"pending\":{}}}",
        dag.len(),
        jarr(dag.tips().iter().map(|t| jstr(&t.to_string()))),
        jstr(&selected_tip),
        gd.map(|g| g.blue_score).unwrap_or(0),
        gd.map(|g| g.blue_work).unwrap_or(0),
        dag.k(),
        ledger.subsidy(),
        node.issuance().unwrap_or(0),
        HALVING_ERA,
        node.min_fee(),
        jstr(&ledger.genesis().to_string()),
        utxo.total_value(),
        jstr("KVNC"),
        8,
        match node.miner() {
            Some(m) => jstr(&m.to_hex()),
            None => "null".into(),
        },
        ATOM,
        node.proof_of_work(),
        jstr("v5"),
        utxo.len(),
        chain.len(),
        node.pending_count(),
        tx_count,
        jarr(dag_json.into_iter()),
        jarr(order.iter().map(|id| jstr(&id.to_string()))),
        pending,
    )
}

fn colour_of<'a>(
    id: BlockId,
    genesis: BlockId,
    chain: &HashSet<BlockId>,
    blue: &HashSet<BlockId>,
) -> &'a str {
    if id == genesis {
        "genesis"
    } else if chain.contains(&id) {
        "chain"
    } else if blue.contains(&id) {
        "blue"
    } else {
        "red"
    }
}

fn tx_json(tx: &Transaction) -> String {
    format!(
        "{{\"id\":{},\"coinbase\":{},\"inputs\":{},\"outputs\":{}}}",
        jstr(&tx.id().to_string()),
        tx.is_coinbase(),
        tx.inputs().len(),
        jarr(tx.outputs().iter().map(|o| format!(
            "{{\"value\":{},\"owner\":{}}}",
            o.value,
            jstr(&o.owner.to_hex())
        ))),
    )
}

fn pending_json(node: &Node, tx: &Transaction) -> String {
    let fee = if let Ok(ledger) = node.ledger() {
        let utxo = ledger.ledger_state();
        let mut sum_in = 0u64;
        for input in tx.inputs() {
            if let Some(prev) = utxo.get(&input.outpoint) {
                sum_in = sum_in.saturating_add(prev.value);
            }
        }
        let sum_out: u64 = tx.outputs().iter().map(|o| o.value).sum();
        sum_in.saturating_sub(sum_out)
    } else {
        0
    };
    format!(
        "{{\"id\":{},\"coinbase\":{},\"fee\":{},\"inputs\":{},\"outputs\":{}}}",
        jstr(&tx.id().to_string()),
        tx.is_coinbase(),
        fee,
        tx.inputs().len(),
        jarr(tx.outputs().iter().map(|o| format!(
            "{{\"value\":{},\"owner\":{}}}",
            o.value,
            jstr(&o.owner.to_hex())
        ))),
    )
}

fn wallets_json(node: &Node) -> String {
    let rows: Vec<String> = ACTORS
        .iter()
        .map(|seed| {
            let addr = Node::address(*seed);
            let bal = node.balance(&addr).unwrap_or(0);
            format!(
                "{{\"seed\":{},\"address\":{},\"balance\":{}}}",
                seed,
                jstr(&addr.to_hex()),
                bal
            )
        })
        .collect();
    jarr(rows.into_iter())
}

fn jstr(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn jarr(items: impl Iterator<Item = String>) -> String {
    let mut out = String::from("[");
    for (i, item) in items.enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(&item);
    }
    out.push(']');
    out
}

fn ws_frame_text(text: &str) -> Vec<u8> {
    let payload = text.as_bytes();
    let mut frame = Vec::with_capacity(2 + payload.len());
    frame.push(0x81); // FIN + text frame
    if payload.len() < 126 {
        frame.push(payload.len() as u8);
    } else if payload.len() < 65536 {
        frame.push(126);
        frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    } else {
        frame.push(127);
        frame.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    }
    frame.extend_from_slice(payload);
    frame
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_has_three_nodes_and_genesis() {
        let app = Explorer::boot();
        let json = snapshot(&app);
        assert!(json.contains("\"alpha\""));
        assert!(json.contains("\"beta\""));
        assert!(json.contains("\"gamma\""));
        assert!(json.contains("\"genesis\""));
        assert!(json.contains("\"supply\":20000000000"));
        assert!(json.contains("\"token\":\"KVNC\""));
        assert!(json.contains("\"ui\":\"v5\""));
        assert!(json.contains("\"pow\":true"));
        assert!(json.contains("\"network\":\"kovanica-testnet\""));
        assert!(json.contains("\"subsidy\":20000000000"));
    }

    #[test]
    fn empty_block_mints_kvnc_subsidy_to_miner() {
        let mut app = Explorer::boot();
        app.mining = false;
        let founder = kovanica_state::KeyPair::from_u64(1).address();
        let before = app.mesh.node("alpha").unwrap().balance(&founder).unwrap();
        app.mesh.produce_empty("alpha").unwrap();
        let after = app.mesh.node("alpha").unwrap().balance(&founder).unwrap();
        assert_eq!(after, before + u128::from(GENESIS_SUBSIDY));
    }

    #[test]
    fn produce_block_mints_kvnc_subsidy_with_the_spend() {
        let mut app = Explorer::boot();
        app.mining = false;
        let founder = kovanica_state::KeyPair::from_u64(1).address();
        app.mesh.pool("alpha", 1, ATOM, 2).unwrap();
        app.mesh.produce("alpha").unwrap();
        let n = app.mesh.node("alpha").unwrap();
        assert_eq!(
            n.balance(&kovanica_state::KeyPair::from_u64(2).address())
                .unwrap(),
            ATOM.into()
        );
        assert_eq!(
            n.balance(&founder).unwrap(),
            u128::from(GENESIS_PREMINE - ATOM + GENESIS_SUBSIDY)
        );
    }

    #[test]
    fn wallet_signs_off_node_and_mempool_accepts() {
        use kovanica_state::KeyPair;

        let mut app = Explorer::boot();
        app.mining = false;
        let from = KeyPair::from_u64(1);
        let to = KeyPair::from_u64(9);
        let prepared = app
            .mesh
            .node("alpha")
            .unwrap()
            .prepare_transfer(from.address(), ATOM, to.address())
            .unwrap();
        let sig = from.sign(&prepared.sighash);
        let id = app
            .mesh
            .submit_signed("alpha", from.address(), ATOM, to.address(), sig)
            .unwrap();
        assert_eq!(app.mesh.node("alpha").unwrap().pending_count(), 1);
        assert!(!id.to_string().is_empty());
        app.mesh.produce("alpha").unwrap();
        app.mesh.drain(8);
        assert_eq!(
            app.mesh
                .node("alpha")
                .unwrap()
                .balance(&to.address())
                .unwrap(),
            ATOM.into()
        );
    }

    #[test]
    fn prepare_combines_two_coinbases_to_send_a_full_subsidy() {
        use kovanica_state::KeyPair;

        let mut app = Explorer::boot();
        app.mining = false;
        let from = KeyPair::from_u64(1);
        let to = KeyPair::from_u64(9);
        app.mesh.produce_empty("alpha").unwrap();
        let prepared = app
            .mesh
            .node("alpha")
            .unwrap()
            .prepare_transfer(from.address(), GENESIS_SUBSIDY, to.address())
            .unwrap();
        assert!(
            prepared.tx.inputs().len() >= 2,
            "50 KVNC + fee needs two 50-KVNC coinbases"
        );
        let sig = from.sign(&prepared.sighash);
        app.mesh
            .submit_signed("alpha", from.address(), GENESIS_SUBSIDY, to.address(), sig)
            .unwrap();
        app.mesh.produce("alpha").unwrap();
        app.mesh.drain(8);
        assert_eq!(
            app.mesh
                .node("alpha")
                .unwrap()
                .balance(&to.address())
                .unwrap(),
            u128::from(GENESIS_SUBSIDY)
        );
    }

    #[test]
    fn history_lists_credit_to_an_address() {
        let mut app = Explorer::boot();
        app.mining = false;
        app.mesh.pool("alpha", 1, ATOM, 2).unwrap();
        app.mesh.produce("alpha").unwrap();
        let addr = kovanica_state::KeyPair::from_u64(2).address().to_hex();
        let mut q = std::collections::HashMap::new();
        q.insert("address".into(), addr);
        q.insert("node".into(), "alpha".into());
        let json = history_json(&app, &q).unwrap();
        assert!(json.contains("\"kind\":\"in\""));
        assert!(json.contains(&ATOM.to_string()));
    }

    #[test]
    fn issuance_halves_each_era() {
        assert_eq!(Node::issuance_at(200 * ATOM, 0), 200 * ATOM);
        assert_eq!(Node::issuance_at(200 * ATOM, 499_999), 200 * ATOM);
        assert_eq!(Node::issuance_at(200 * ATOM, 500_000), 100 * ATOM);
        assert_eq!(Node::issuance_at(200 * ATOM, 1_000_000), (200 * ATOM) >> 2);
    }

    #[test]
    fn min_fee_scales_with_subsidy_cap() {
        let app = Explorer::boot();
        let fee = app.mesh.node("alpha").unwrap().min_fee();
        assert_eq!(fee, (GENESIS_SUBSIDY / 500_000).max(1));
        assert!(fee > 1);
    }

    #[test]
    fn p2p_off_tokens() {
        assert!(env_off("off"));
        assert!(env_off("none"));
        assert!(env_off("0"));
        assert!(!env_off(P2P_LISTEN_DEFAULT));
        assert_eq!(
            P2P_BOOTSTRAP,
            "seed.kovanica.online:9000,seed3.kovanica.online:9000"
        );
    }

    #[test]
    fn origin_pulse_increments_and_lists() {
        let mut app = Explorer::boot();
        let mut q = std::collections::HashMap::new();
        q.insert("iso3".into(), "hrv".into());
        let body = dispatch(&mut app, "origin", &q).unwrap();
        assert!(body.contains("HRV"));
        assert!(body.contains("\"pulses\":1"));
        let listed = origins_json(&app.origins);
        assert!(listed.contains("HRV"));
        let bad = dispatch(&mut app, "origin", &std::collections::HashMap::new());
        assert!(bad.is_err());
    }

    #[test]
    fn tap_action_is_removed() {
        use kovanica_state::KeyPair;

        let mut app = Explorer::boot();
        let to = KeyPair::from_u64(9);
        let mut q = std::collections::HashMap::new();
        q.insert("to".into(), to.address().to_hex());
        q.insert("amount".into(), "1".into());
        let err = dispatch(&mut app, "tap", &q).unwrap_err();
        assert!(err.contains("unknown action"));
    }

    #[test]
    fn mine_action_produces_a_block_like_produce() {
        let mut app = Explorer::boot();
        let before = app.mesh.node("alpha").unwrap().block_count().unwrap();
        let mine_body = dispatch(&mut app, "mine", &std::collections::HashMap::new()).unwrap();
        let after = app.mesh.node("alpha").unwrap().block_count().unwrap();
        assert!(mine_body.contains("\"ok\":true"));
        assert_eq!(after, before + 1, "mine must produce exactly one block");
    }

    #[test]
    fn dual_stack_binds_v4_and_v6_on_the_same_port() {
        // Skip where IPv6 is unavailable (some CI runners / containers).
        if TcpListener::bind("[::]:0").is_err() {
            return;
        }
        // Derive the port from the pid so parallel tests rarely collide.
        let port: u16 = 20000 + u16::try_from(std::process::id() % 20_000).unwrap_or(0);
        let raw = format!("0.0.0.0:{port}");
        let listeners = bind_p2p_addrs(&raw);
        assert_eq!(listeners.len(), 2, "want one v4 and one v6 listener");
        for l in &listeners {
            assert_eq!(l.local_addr().unwrap().port(), port);
        }
        // The v6 listener must genuinely be reachable on the v6 wildcard.
        let mut c =
            std::net::TcpStream::connect(format!("[::1]:{port}")).expect("v6 loopback connect");
        use std::io::Write as _;
        let _ = c.write_all(b"x"); // accepted is all we prove; write may race close
    }

    /// Core request helper: returns the raw response bytes so binary bodies
    /// (wire-format uplinks, light-sync blobs, merkle proofs) survive intact.
    fn send_req_raw(app: &mut Explorer, head: &str, body: &[u8]) -> (u16, Vec<u8>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(addr).unwrap();
        let (server_stream, _) = listener.accept().unwrap();

        client.write_all(head.as_bytes()).unwrap();
        client.write_all(body).unwrap();
        client.shutdown(std::net::Shutdown::Write).unwrap();

        let _ = handle(app, server_stream);

        let mut resp = Vec::new();
        let _ = client.read_to_end(&mut resp);

        let status = String::from_utf8_lossy(&resp)
            .lines()
            .next()
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|s| s.parse::<u16>().ok())
            .unwrap_or(0);

        let body = if let Some(pos) = resp
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .map(|p| p + 4)
        {
            resp[pos..].to_vec()
        } else {
            Vec::new()
        };
        (status, body)
    }

    fn send_req(app: &mut Explorer, req: &str) -> (u16, String) {
        let (status, body) = send_req_raw(app, req, b"");
        (status, String::from_utf8_lossy(&body).to_string())
    }

    /// Like [`send_req`], but with a binary body (the wire-format uplink).
    fn send_req_bytes(app: &mut Explorer, head: &str, body: &[u8]) -> (u16, String) {
        let (status, body) = send_req_raw(app, head, body);
        (status, String::from_utf8_lossy(&body).to_string())
    }

    #[test]
    fn test_http_mine_template_and_submit_flow() {
        let mut app = Explorer::boot();
        let (status, body) = send_req(
            &mut app,
            "GET /api/mine/template HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
        );
        assert_eq!(status, 200);
        assert!(body.contains("\"ok\":true"));
        assert!(body.contains("\"parents\""));
        assert!(body.contains("\"work\""));
        assert!(body.contains("\"timestamp_ms\""));
        assert!(body.contains("\"payload\""));

        let template_json: serde_json::Value = serde_json::from_str(&body).unwrap();
        let parents = template_json["parents"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| {
                BlockId::from_bytes(
                    hex::decode(p.as_str().unwrap())
                        .unwrap()
                        .try_into()
                        .unwrap(),
                )
            })
            .collect::<Vec<_>>();
        let work = template_json["work"].as_u64().unwrap() as u128;
        let ts = template_json["timestamp_ms"].as_u64().unwrap();
        let payload_hex = template_json["payload"].as_str().unwrap();
        let payload_bytes = hex::decode(payload_hex).unwrap();

        let template_block = Block::new(parents.clone(), work, ts, 0, payload_bytes.clone());
        let mined = kovanica_dag::pow::mine(&template_block);
        let nonce = mined.nonce();
        let block_id = mined.id();

        let submit_body = format!(
            "{{\"parents\":[{}],\"work\":{},\"timestamp_ms\":{},\"nonce\":{},\"payload\":\"{}\"}}",
            parents
                .iter()
                .map(|p| format!("\"{}\"", p.to_hex()))
                .collect::<Vec<_>>()
                .join(","),
            work,
            ts,
            nonce,
            payload_hex
        );

        let post_req = format!(
            "POST /api/mine/submit HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            submit_body.len(),
            submit_body
        );

        let (sub_status, sub_body) = send_req(&mut app, &post_req);
        assert_eq!(sub_status, 200);
        assert!(sub_body.contains("\"ok\":true"));
        assert!(sub_body.contains(&block_id.to_hex()));

        // Node DAG tips should now include the new block
        let alpha = app.mesh.node("alpha").unwrap();
        assert!(alpha.has_block(&block_id));
    }

    #[test]
    fn test_http_mine_submit_negative_cases() {
        let mut app = Explorer::boot();

        // 1. Invalid JSON
        let bad_json_req = "POST /api/mine/submit HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: 7\r\n\r\nnotjson";
        let (status, body) = send_req(&mut app, bad_json_req);
        assert_eq!(status, 400);
        assert!(body.contains("\"ok\":false"));

        // 2. Missing parents
        let missing_parents = "POST /api/mine/submit HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: 35\r\n\r\n{\"work\":1,\"nonce\":0,\"payload\":\"00\"}";
        let (status, body) = send_req(&mut app, missing_parents);
        assert_eq!(status, 400);
        assert!(body.contains("\"ok\":false"));

        // 3. Unknown node
        let unknown_node =
            "GET /api/mine/template?node=nonexistent HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
        let (status, body) = send_req(&mut app, unknown_node);
        assert_eq!(status, 400);
        assert!(body.contains("\"ok\":false"));
    }

    // ---- A1: network profile (dormant mainnet) ----

    #[test]
    fn network_profile_defaults_to_testnet() {
        // No KOVANICA_NETWORK set in tests: the default must be the live
        // testnet, never dormant, with the shipped genesis parameters.
        let profile = network_profile();
        assert_eq!(profile.id, "kovanica-testnet");
        assert!(!profile.dormant);
        assert_eq!(profile.genesis_k, 3);
        assert_eq!(profile.genesis_subsidy, GENESIS_SUBSIDY);
        assert_eq!(profile.genesis_premine, GENESIS_PREMINE);
        assert_eq!(profile.founder_seed, FOUNDER_SEED);
        assert_eq!(profile.finality_depth, TESTNET_FINALITY_DEPTH);
        assert_eq!(profile.payload_pruning_depth, TESTNET_PAYLOAD_PRUNING_DEPTH);
    }

    #[test]
    fn mainnet_profile_is_a_dormant_placeholder() {
        // The mainnet profile exists for plumbing (id, data-dir isolation,
        // faucet gating) but its genesis parameters are TBD — never invented.
        let profile = NetworkProfile::mainnet();
        assert_eq!(profile.id, "kovanica-mainnet");
        assert!(profile.dormant, "mainnet must stay dormant");
        assert_eq!(profile.genesis_k, 0, "mainnet k is TBD");
        assert_eq!(profile.genesis_subsidy, 0, "mainnet subsidy is TBD");
        assert_eq!(profile.genesis_premine, 0, "mainnet premine is TBD");
        assert_eq!(profile.finality_depth, 0, "mainnet finality depth is TBD");
        assert_eq!(
            profile.payload_pruning_depth, 0,
            "mainnet payload pruning depth is TBD"
        );
    }

    #[test]
    fn data_dirs_are_isolated_per_network() {
        // A mainnet node owns `data/kovanica-mainnet/`, never the testnet's
        // `data/` — so the ensure_network() wipe cannot cross networks.
        assert_eq!(
            data_dir_for(&NetworkProfile::testnet()),
            PathBuf::from("data")
        );
        assert_eq!(
            data_dir_for(&NetworkProfile::mainnet()),
            PathBuf::from("data/kovanica-mainnet")
        );
    }

    #[test]
    fn test_http_bootstrap_returns_light_config() {
        let mut app = Explorer::boot();
        let profile = network_profile();
        let (status, body) = send_req(
            &mut app,
            "GET /api/bootstrap HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
        );
        assert_eq!(status, 200);
        let json: serde_json::Value = serde_json::from_str(&body).expect("bootstrap JSON");

        // Existing top-level fields remain for backward compatibility.
        assert_eq!(json["network"].as_str().unwrap(), profile.id);
        assert_eq!(json["k"].as_u64().unwrap(), u64::from(profile.genesis_k));
        assert_eq!(json["subsidy"].as_u64().unwrap(), profile.genesis_subsidy);
        assert_eq!(
            json["founder_amount"].as_u64().unwrap(),
            profile.genesis_premine
        );
        assert_eq!(json["founder_seed"].as_u64().unwrap(), profile.founder_seed);
        assert_eq!(
            json["finality_depth"].as_u64().unwrap(),
            profile.finality_depth
        );
        assert_eq!(
            json["payload_pruning_depth"].as_u64().unwrap(),
            profile.payload_pruning_depth
        );

        // Nested light_config object expected by the mobile light node FFI.
        let light = &json["light_config"];
        assert!(!light.is_null(), "light_config must be present");
        assert_eq!(light["k"].as_u64().unwrap(), u64::from(profile.genesis_k));
        assert_eq!(light["subsidy"].as_u64().unwrap(), profile.genesis_subsidy);
        assert_eq!(light["premine"].as_u64().unwrap(), profile.genesis_premine);
        assert_eq!(
            light["founder_seed"].as_u64().unwrap(),
            profile.founder_seed
        );
        assert_eq!(
            light["finality_depth"].as_u64().unwrap(),
            profile.finality_depth
        );
        assert_eq!(
            light["payload_pruning_depth"].as_u64().unwrap(),
            profile.payload_pruning_depth
        );
    }

    // ---- A2: staked-block uplink on POST /api/mine/submit ----

    /// Hybrid policy for the uplink tests: every slot winnable, nominal staked
    /// work 1, no retarget pin so PoW-path blocks mine trivially.
    fn uplink_hybrid_cfg() -> HybridConfig {
        HybridConfig {
            rate_num: 1,
            rate_den: 1,
            stake_nominal_work: 1,
            retarget: None,
        }
    }

    #[test]
    fn test_http_mine_submit_accepts_staked_wire_block() {
        use kovanica_dag::vrf_keypair_from_seed;
        use kovanica_state::stake::bond_tag;
        use kovanica_state::{KeyPair, Transaction, TxOutput};

        let mut app = Explorer::boot();
        app.mining = false;
        let cfg = uplink_hybrid_cfg();
        // Alpha produces (bonded validator); beta is the submit target and
        // must run the same hybrid policy to re-admit the staked block with
        // its original id.
        app.mesh
            .node_mut("alpha")
            .unwrap()
            .enable_hybrid(cfg.clone())
            .unwrap();
        app.mesh
            .node_mut("beta")
            .unwrap()
            .enable_hybrid(cfg.clone())
            .unwrap();

        let validator_seed = [7u8; 32];
        let (_sk, vk) = vrf_keypair_from_seed(&validator_seed);
        let pk = *vk.as_bytes();
        app.mesh
            .node_mut("alpha")
            .unwrap()
            .set_validator_seed(validator_seed);

        // Bond the founder's whole coin to the validator key on alpha.
        let founder = KeyPair::from_u64(1);
        let (coin, value) = app
            .mesh
            .node("alpha")
            .unwrap()
            .utxos_of(&founder.address())
            .unwrap()
            .first()
            .map(|(op, v)| (*op, *v))
            .unwrap();
        let bond = Transaction::signed(
            &[(coin, &founder)],
            vec![TxOutput::new(value, founder.address())],
            bond_tag(&pk),
        );
        app.mesh.node_mut("alpha").unwrap().submit_tx(bond).unwrap();
        app.mesh
            .produce("alpha")
            .unwrap()
            .expect("bond block mined");

        // Sync the bond block to beta so its stake registry knows the bond.
        app.mesh.sync_headers_first("alpha", "beta").unwrap();

        // Produce a staked empty block on alpha (draw wins: 100% of bonded
        // stake) and upload it to beta in the gossip wire format.
        let staked_id = app.mesh.produce_empty("alpha").unwrap();
        let record = app
            .mesh
            .node("alpha")
            .unwrap()
            .block_record(&staked_id)
            .expect("produced block known");
        assert!(
            record.vrf.is_some(),
            "hybrid produce_empty must carry the VRF bundle"
        );
        let wire = encode_records(&[record]);

        let head = format!(
            "POST /api/mine/submit?node=beta HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n\r\n",
            wire.len()
        );
        let (status, body) = send_req_bytes(&mut app, &head, &wire);
        assert_eq!(status, 200, "staked uplink rejected: {body}");
        assert!(body.contains(&staked_id.to_hex()), "{body}");

        // The block is genuinely admitted on beta with the SAME id the
        // producer computed (identity-preserving wire path).
        assert!(app.mesh.node("beta").unwrap().has_block(&staked_id));
        assert_eq!(
            app.mesh.node("beta").unwrap().selected_tip().unwrap(),
            staked_id
        );
    }

    #[test]
    fn test_http_mine_submit_wire_rejects_ineligible_staked_block() {
        use kovanica_dag::vrf_keypair_from_seed;
        use kovanica_state::stake::bond_tag;
        use kovanica_state::{KeyPair, Transaction, TxOutput};

        let mut app = Explorer::boot();
        app.mining = false;
        // Alpha: rate 1/1 — a bonded validator wins every draw.
        app.mesh
            .node_mut("alpha")
            .unwrap()
            .enable_hybrid(uplink_hybrid_cfg())
            .unwrap();
        // Beta: rate 0/1 — the eligibility threshold is always 0, so NO
        // staked block can ever be eligible there (deterministic adversarial
        // gate, no reliance on VRF draw luck).
        let never_eligible = HybridConfig {
            rate_num: 0,
            rate_den: 1,
            stake_nominal_work: 1,
            retarget: None,
        };
        app.mesh
            .node_mut("beta")
            .unwrap()
            .enable_hybrid(never_eligible)
            .unwrap();

        // Alpha bonds and produces a valid staked block.
        let validator_seed = [7u8; 32];
        let (_sk, vk) = vrf_keypair_from_seed(&validator_seed);
        let pk = *vk.as_bytes();
        app.mesh
            .node_mut("alpha")
            .unwrap()
            .set_validator_seed(validator_seed);
        let founder = KeyPair::from_u64(1);
        let (coin, value) = app
            .mesh
            .node("alpha")
            .unwrap()
            .utxos_of(&founder.address())
            .unwrap()
            .first()
            .map(|(op, v)| (*op, *v))
            .unwrap();
        let bond = Transaction::signed(
            &[(coin, &founder)],
            vec![TxOutput::new(value, founder.address())],
            bond_tag(&pk),
        );
        app.mesh.node_mut("alpha").unwrap().submit_tx(bond).unwrap();
        app.mesh
            .produce("alpha")
            .unwrap()
            .expect("bond block mined");
        // Beta has the chain up to the bond block (so the staked block's
        // parent exists) but its own policy can never admit a staked block:
        // the uplink must reject it as ineligible — the adversarial case for
        // the slice-9d gate. (Sync BEFORE the staked block is produced, since
        // beta would reject it during sync too.)
        app.mesh.sync_headers_first("alpha", "beta").unwrap();
        let staked_id = app.mesh.produce_empty("alpha").unwrap();
        let record = app
            .mesh
            .node("alpha")
            .unwrap()
            .block_record(&staked_id)
            .unwrap();
        let wire = encode_records(&[record]);

        let head = format!(
            "POST /api/mine/submit?node=beta HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n\r\n",
            wire.len()
        );
        let (status, body) = send_req_bytes(&mut app, &head, &wire);
        assert_eq!(
            status, 400,
            "ineligible staked block must be rejected: {body}"
        );
        assert!(body.contains("\"ok\":false"), "{body}");
        assert!(
            body.contains("eligible") || body.contains("stake"),
            "expected an eligibility error, got: {body}"
        );
        assert!(!app.mesh.node("beta").unwrap().has_block(&staked_id));
    }

    #[test]
    fn test_http_mine_submit_wire_accepts_pow_block() {
        let mut app = Explorer::boot();
        app.mining = false;
        // Alpha runs plain PoW (the default profile config): a mined block
        // uploaded in the wire format must still be admitted.
        let pow_id = app.mesh.produce_empty("alpha").unwrap();
        let record = app
            .mesh
            .node("alpha")
            .unwrap()
            .block_record(&pow_id)
            .unwrap();
        assert!(record.vrf.is_none());
        let wire = encode_records(&[record]);

        let head = format!(
            "POST /api/mine/submit HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n\r\n",
            wire.len()
        );
        let (status, body) = send_req_bytes(&mut app, &head, &wire);
        assert_eq!(status, 200, "PoW wire uplink rejected: {body}");
        assert!(body.contains(&pow_id.to_hex()), "{body}");
    }

    #[test]
    fn test_http_mine_submit_wire_rejects_garbage() {
        let mut app = Explorer::boot();
        let garbage = b"\x00\x01\x02this is not a records frame at all";
        let head = format!(
            "POST /api/mine/submit HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n\r\n",
            garbage.len()
        );
        let (status, body) = send_req_bytes(&mut app, &head, garbage);
        assert_eq!(status, 400);
        assert!(body.contains("\"ok\":false"));
    }

    #[test]
    fn test_http_mine_submit_wire_rejects_empty_body() {
        let mut app = Explorer::boot();
        let head = "POST /api/mine/submit HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/octet-stream\r\nContent-Length: 0\r\n\r\n"
            .to_string();
        let (status, body) = send_req_bytes(&mut app, &head, b"");
        assert_eq!(status, 400);
        assert!(body.contains("\"ok\":false"));
    }

    // ---- A3: SPV light-sync blob endpoint ----

    /// Parse a light-sync blob into (header, filter) pairs — a local mirror of
    /// the FFI's `parse_light_sync`, so the endpoint's bytes are verified
    /// against the shipped format without depending on the FFI crate.
    fn parse_light_sync_blob(
        blob: &[u8],
    ) -> Vec<(
        kovanica_state::spv::BlockHeader,
        kovanica_state::spv::BlockFilter,
    )> {
        assert!(blob.len() >= 9, "blob too short");
        assert_eq!(&blob[..4], LIGHT_SYNC_MAGIC);
        assert_eq!(blob[4], LIGHT_SYNC_VERSION);
        let count = u32::from_be_bytes(blob[5..9].try_into().unwrap()) as usize;
        let mut off = 9usize;
        let mut out = Vec::with_capacity(count);
        for _ in 0..count {
            let get32 = |o: usize| <[u8; 32]>::try_from(&blob[o..o + 32]).unwrap();
            let header = kovanica_state::spv::BlockHeader {
                id: BlockId::from_bytes(get32(off)),
                prev_hash: BlockId::from_bytes(get32(off + 32)),
                merkle_root: get32(off + 64),
                work: u128::from_be_bytes(blob[off + 96..off + 112].try_into().unwrap()),
                timestamp_ms: u64::from_be_bytes(blob[off + 112..off + 120].try_into().unwrap()),
                nonce: u64::from_be_bytes(blob[off + 120..off + 128].try_into().unwrap()),
                blue_score: u64::from_be_bytes(blob[off + 128..off + 136].try_into().unwrap()),
                chain_blue_work: u128::from_be_bytes(
                    blob[off + 136..off + 152].try_into().unwrap(),
                ),
                height: u64::from_be_bytes(blob[off + 152..off + 160].try_into().unwrap()),
            };
            off += 160;
            let k = blob[off];
            let n = u64::from_be_bytes(blob[off + 1..off + 9].try_into().unwrap());
            let len = u32::from_be_bytes(blob[off + 9..off + 13].try_into().unwrap()) as usize;
            let data = blob[off + 13..off + 13 + len].to_vec();
            off += 13 + len;
            out.push((header, kovanica_state::spv::BlockFilter { k, n, data }));
        }
        assert_eq!(off, blob.len(), "trailing bytes in light-sync blob");
        out
    }

    #[test]
    fn test_light_sync_blob_matches_headers_and_filters() {
        let mut app = Explorer::boot();
        app.mining = false;
        // A few blocks so the selected chain is non-trivial.
        app.mesh.produce_empty("alpha").unwrap();
        app.mesh.produce_empty("alpha").unwrap();
        app.mesh.produce_empty("alpha").unwrap();

        let (status, blob) = send_req_raw(
            &mut app,
            "GET /api/light_sync HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
            b"",
        );
        assert_eq!(status, 200);
        let parsed = parse_light_sync_blob(&blob);

        let n = app.mesh.node("alpha").unwrap();
        let headers = n.export_spv_headers();
        assert_eq!(parsed.len(), headers.len());
        for (i, (h, f)) in parsed.iter().enumerate() {
            assert_eq!(&h.id, &headers[i].id);
            assert_eq!(&h.prev_hash, &headers[i].prev_hash);
            assert_eq!(&h.merkle_root, &headers[i].merkle_root);
            assert_eq!(h.work, headers[i].work);
            assert_eq!(h.timestamp_ms, headers[i].timestamp_ms);
            assert_eq!(h.nonce, headers[i].nonce);
            assert_eq!(h.blue_score, headers[i].blue_score);
            assert_eq!(h.chain_blue_work, headers[i].chain_blue_work);
            assert_eq!(h.height, headers[i].height);
            // The filter must match the node's own block_filter helper.
            let expected = n.block_filter(&h.id, LIGHT_SYNC_FILTER_K).unwrap();
            assert_eq!(f.k, expected.k);
            assert_eq!(f.n, expected.n);
            assert_eq!(f.data, expected.data);
        }
    }

    #[test]
    fn test_light_sync_from_is_incremental() {
        let mut app = Explorer::boot();
        app.mining = false;
        app.mesh.produce_empty("alpha").unwrap();
        app.mesh.produce_empty("alpha").unwrap();
        app.mesh.produce_empty("alpha").unwrap();

        let n = app.mesh.node("alpha").unwrap();
        let headers = n.export_spv_headers();
        assert!(headers.len() >= 4, "genesis + 3 blocks");
        // `from` = the second header (index 1): the blob must start at index 2.
        let from_id = headers[1].id.to_hex();
        let req = format!(
            "GET /api/light_sync?from={} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
            from_id
        );
        let (status, blob) = send_req_raw(&mut app, &req, b"");
        assert_eq!(status, 200);
        let parsed = parse_light_sync_blob(&blob);
        assert_eq!(parsed.len(), headers.len() - 2);
        assert_eq!(parsed[0].0.id, headers[2].id);
        assert_eq!(parsed.last().unwrap().0.id, headers.last().unwrap().id);

        // An unknown `from` falls back to the full blob (safe for a client
        // that drifted off-chain).
        let unknown = BlockId::from_bytes([0xabu8; 32]).to_hex();
        let req = format!(
            "GET /api/light_sync?from={} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
            unknown
        );
        let (status, blob) = send_req_raw(&mut app, &req, b"");
        assert_eq!(status, 200);
        let parsed = parse_light_sync_blob(&blob);
        assert_eq!(parsed.len(), headers.len());
    }

    #[test]
    fn test_light_proof_endpoint_verifies() {
        let mut app = Explorer::boot();
        app.mining = false;
        // A transfer so the block carries a spendable tx (not just coinbase).
        app.mesh.pool("alpha", 1, ATOM, 2).unwrap();
        app.mesh.produce("alpha").unwrap();

        let n = app.mesh.node("alpha").unwrap();
        let tip = n.selected_tip().unwrap();
        let rec = n.block_record(&tip).unwrap();
        let tx = rec.txs.iter().find(|t| !t.is_coinbase()).expect("spend tx");
        let tx_id = tx.id();

        let req = format!(
            "GET /api/light_proof?block={}&tx={} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
            tip.to_hex(),
            tx_id.to_hex()
        );
        let (status, blob) = send_req_raw(&mut app, &req, b"");
        assert_eq!(status, 200);

        // Decode the proof blob (FFI `encode_proof` layout) and verify it.
        assert!(blob.len() >= 72);
        let get32 = |o: usize| <[u8; 32]>::try_from(&blob[o..o + 32]).unwrap();
        let path_len = u32::from_be_bytes(blob[64..68].try_into().unwrap()) as usize;
        let base = 68 + path_len * 32;
        let proof = kovanica_state::spv::MerkleProof {
            tx_id: get32(0),
            merkle_root: get32(32),
            path: (0..path_len).map(|i| get32(68 + i * 32)).collect(),
            index: u64::from_be_bytes(blob[base..base + 8].try_into().unwrap()) as usize,
            tx_count: u64::from_be_bytes(blob[base + 8..base + 16].try_into().unwrap()) as usize,
        };
        assert_eq!(proof.tx_id, *tx_id.as_bytes());
        assert!(proof.verify(), "merkle proof must verify");

        // Unknown tx → 404.
        let unknown = kovanica_state::TxId::from_bytes([0x42u8; 32]).to_hex();
        let req = format!(
            "GET /api/light_proof?block={}&tx={} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
            tip.to_hex(),
            unknown
        );
        let (status, body) = send_req(&mut app, &req);
        assert_eq!(status, 404);
        assert!(body.contains("\"ok\":false"));
    }

    // ---- D1: rate limits + faucet gating ----

    #[test]
    fn rate_limit_exhausts_bucket_and_returns_429() {
        let mut app = Explorer::boot();
        app.rate_limit_rate = 0.0; // no refill
        app.rate_limit_burst = 1.0; // one request per IP
        let (s1, _) = send_req(
            &mut app,
            "GET /api/head HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
        );
        assert_eq!(s1, 200);
        let (s2, body2) = send_req(
            &mut app,
            "GET /api/head HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
        );
        assert_eq!(s2, 429);
        assert!(body2.contains("rate limit"), "{body2}");
    }

    #[test]
    fn faucet_enforces_per_address_cap() {
        let mut app = Explorer::boot();
        let to = kovanica_state::KeyPair::from_u64(9).address();
        let key = to.to_hex();
        // Pre-fill 4 KVNC so the next 1-KVNC payout hits the 5-KVNC cap.
        app.faucet_given.insert(key.clone(), 4 * ATOM);
        let mut q = std::collections::HashMap::new();
        q.insert("to".into(), key);
        q.insert("amount".into(), ATOM.to_string());
        let body = dispatch(&mut app, "faucet", &q).unwrap();
        assert!(body.contains("\"ok\":true"), "{body}");
        // At the cap now: another payout must be refused.
        let err = dispatch(&mut app, "faucet", &q).unwrap_err();
        assert!(err.contains("cap"), "{err}");
    }

    #[test]
    fn faucet_rejects_oversized_request() {
        let mut app = Explorer::boot();
        let to = kovanica_state::KeyPair::from_u64(9).address();
        let mut q = std::collections::HashMap::new();
        q.insert("to".into(), to.to_hex());
        q.insert("amount".into(), (FAUCET_MAX_PER_ADDRESS + 1).to_string());
        let err = dispatch(&mut app, "faucet", &q).unwrap_err();
        assert!(err.contains("max"), "{err}");
    }

    #[test]
    fn faucet_gate_is_testnet_only() {
        // The gate predicate: payouts only on the testnet profile. Mainnet —
        // dormant or not — never pays out.
        assert_eq!(network_profile().id, "kovanica-testnet");
        assert_ne!(NetworkProfile::mainnet().id, "kovanica-testnet");
    }

    // ---- C2: incremental sync + API pagination ----

    #[test]
    fn blocks_endpoint_paginates_from_a_block_id() {
        let mut app = Explorer::boot();
        app.mining = false;
        app.mesh.produce_empty("alpha").unwrap();
        app.mesh.produce_empty("alpha").unwrap();
        app.mesh.produce_empty("alpha").unwrap();

        let headers = app.mesh.node("alpha").unwrap().export_headers();
        assert!(headers.len() >= 3, "want at least three non-genesis blocks");
        let full = send_req_raw(
            &mut app,
            "GET /api/blocks HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
            b"",
        );
        assert_eq!(full.0, 200);
        let all_records = decode_records(&full.1).expect("decode full records");
        assert_eq!(all_records.len(), headers.len());

        // Request strictly after the second header: expect everything after it.
        let from = headers[1].id.to_hex();
        let partial = send_req_raw(
            &mut app,
            &format!(
                "GET /api/blocks?from={} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
                from
            ),
            b"",
        );
        assert_eq!(partial.0, 200, "pagination must return 200");
        let paginated = decode_records(&partial.1).expect("decode paginated records");
        assert_eq!(
            paginated.len(),
            headers.len() - 2,
            "must return blocks strictly after from"
        );

        // Unknown / off-chain id falls back to the full export.
        let unknown = BlockId::from_bytes([0xabu8; 32]).to_hex();
        let fallback = send_req_raw(
            &mut app,
            &format!(
                "GET /api/blocks?from={} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
                unknown
            ),
            b"",
        );
        assert_eq!(fallback.0, 200);
        let fallback_records = decode_records(&fallback.1).expect("decode fallback records");
        assert_eq!(fallback_records.len(), headers.len());

        // Bad hex returns 400 JSON.
        let bad = send_req(
            &mut app,
            "GET /api/blocks?from=nothex HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
        );
        assert_eq!(bad.0, 400);
        assert!(bad.1.contains("\"ok\":false"));
    }

    #[test]
    fn history_endpoint_paginates_limit_and_offset() {
        let mut app = Explorer::boot();
        app.mining = false;
        // Each pool+produce creates one transfer block; the address receives
        // one credit per block.
        let addr = kovanica_state::KeyPair::from_u64(2).address().to_hex();
        for _ in 0..3 {
            app.mesh.pool("alpha", 1, ATOM, 2).unwrap();
            app.mesh.produce("alpha").unwrap();
        }
        let body = send_req(
            &mut app,
            &format!(
                "GET /api/history?address={}&limit=2&offset=1 HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
                addr
            ),
        );
        assert_eq!(body.0, 200);
        let v: serde_json::Value = serde_json::from_str(&body.1).unwrap();
        let txs = v["txs"].as_array().unwrap();
        assert_eq!(txs.len(), 2, "limit=2 must return two txs");
        assert_eq!(v["limit"], 2);
        assert_eq!(v["offset"], 1);
        assert_eq!(v["total"], 3);
    }

    #[test]
    fn utxos_endpoint_paginates_limit_and_offset() {
        let mut app = Explorer::boot();
        app.mining = false;
        // Produce several coinbases all paid to actor 1.
        for _ in 0..3 {
            app.mesh.produce_empty("alpha").unwrap();
        }
        let addr = kovanica_state::KeyPair::from_u64(1).address().to_hex();
        let body = send_req(
            &mut app,
            &format!(
                "GET /api/utxos?address={}&limit=2&offset=1 HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
                addr
            ),
        );
        assert_eq!(body.0, 200);
        let v: serde_json::Value = serde_json::from_str(&body.1).unwrap();
        let utxos = v["utxos"].as_array().unwrap();
        assert_eq!(utxos.len(), 2, "limit=2 must return two utxos");
        assert_eq!(v["limit"], 2);
        assert_eq!(v["offset"], 1);
        assert!(v["total"].as_u64().unwrap() >= 3);
    }
}
