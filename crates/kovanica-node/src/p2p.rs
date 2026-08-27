//! Continuous in-process gossip: a mesh of named [`Node`]s, a directed peer
//! graph, and a delayed relay queue.
//!
//! [`crate::net::gossip`] is a one-shot pull-all between two nodes. This module
//! is the next slice: each node has a **peer set**; a produced block or a
//! submitted transaction is announced to those peers; receivers **relay**
//! onward, bounded by a per-node seen-set so the flood terminates; `hello`
//! messages advertise a node's current peers so missing edges close (a
//! minimal **peer discovery**). Time is discrete ([`Mesh::tick`]) so tests
//! stay deterministic — there is no thread, socket, or wall-clock wait here.
//!
//! TCP one-shot sync (the on-wire path) lives in [`crate::net`]: a seed
//! accepts on `KOVANICA_LISTEN` (default `:9000`) and writes every block;
//! a clone pulls with `KOVANICA_PEERS=explorer.kovanica.online:9000`.
//! Long-lived relay sessions are [`crate::relay`] — tests only, not the
//! explorer loop.
//!
//! **DHT Integration**: Each node in the mesh can have an associated Kademlia
//! DHT routing table ([`crate::dht::RoutingTable`]) for peer discovery without
//! hardcoded seeds. The mesh provides discrete-time simulation methods for
//! DHT bootstrap (`dht_bootstrap`), iterative node lookup (`dht_find_node`),
//! and peer pruning/replenishment (`prune_unreachable_peers`).

use std::collections::{BTreeMap, BTreeSet, HashSet};

use kovanica_dag::{Block, BlockId};
use kovanica_state::{encode_block_payload, Address, Transaction, TxId};

use crate::dht::{NodeId, PeerContact, RoutingTable};
use crate::metrics::{
    record_dht_bootstrap, record_dht_find_node, record_dht_pruned, record_dht_query_received,
    record_dht_query_sent, record_p2p_message_received, record_p2p_message_sent,
    record_peer_connected, set_peer_count,
};
use crate::node::{BlockRecord, Node, NodeError};
use crate::p2p_hardening::{P2pHardening, P2pHardeningConfig, PeerStats};

/// Why a mesh operation failed.
#[derive(Debug)]
pub enum P2pError {
    /// No node is registered under that name.
    UnknownNode(String),
    /// The underlying node rejected the operation.
    Node(NodeError),
}

impl core::fmt::Display for P2pError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            P2pError::UnknownNode(n) => write!(f, "unknown node {n}"),
            P2pError::Node(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for P2pError {}

impl From<NodeError> for P2pError {
    fn from(e: NodeError) -> Self {
        P2pError::Node(e)
    }
}

/// A delivered gossip event, for tests and logging.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GossipEvent {
    /// Discrete mesh time at delivery.
    pub at: u64,
    /// Sending node.
    pub from: String,
    /// Receiving node.
    pub to: String,
    /// What was relayed.
    pub kind: GossipKind,
}

/// The payload kind of a [`GossipEvent`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GossipKind {
    /// Peer-discovery hello (advertises the sender's current peer set).
    Hello,
    /// A block record.
    Block,
    /// A mempool transaction.
    Tx,
}

enum Envelope {
    Hello { advertised: Vec<String> },
    Block { record: BlockRecord },
    Tx { tx: Transaction },
}

struct Queued {
    due: u64,
    from: String,
    to: String,
    envelope: Envelope,
}

/// Reconstruct the content-addressed id a [`BlockRecord`] will have on insert.
/// Used as the flood seen-set key so a node relays a block at most once.
fn record_id(record: &BlockRecord) -> BlockId {
    Block::new(
        record.parents.clone(),
        record.work,
        record.timestamp_ms,
        record.nonce,
        encode_block_payload(&record.txs),
    )
    .id()
}

/// An in-process overlay of named nodes with continuous gossip.
///
/// Nodes are stored by a stable string name (BTreeMap, so iteration order is
/// deterministic). The peer graph is directed: `connect("a","b")` means `a`
/// announces to `b`. Hellos add the reverse edge and any advertised neighbours.
#[derive(Default)]
pub struct Mesh {
    nodes: BTreeMap<String, Node>,
    /// DHT routing table for each node (optional, for DHT-enabled nodes).
    dht_tables: BTreeMap<String, RoutingTable>,
    peers: BTreeMap<String, BTreeSet<String>>,
    queue: Vec<Queued>,
    seen_blocks: BTreeMap<String, HashSet<BlockId>>,
    seen_txs: BTreeMap<String, HashSet<TxId>>,
    /// Discrete time. Advanced by [`Mesh::tick`].
    now: u64,
    events: Vec<GossipEvent>,
    /// P2P hardening: rate limiting, duplicate suppression, peer scoring.
    hardening: P2pHardening,
}

impl Mesh {
    /// An empty mesh.
    pub fn new() -> Self {
        Self {
            hardening: P2pHardening::new(Default::default()),
            ..Default::default()
        }
    }

    /// Create a mesh with custom P2P hardening config.
    pub fn with_hardening_config(config: P2pHardeningConfig) -> Self {
        Self {
            hardening: P2pHardening::new(config),
            ..Default::default()
        }
    }

    /// Register `node` under `name`. Replaces any previous node of that name.
    pub fn add(&mut self, name: impl Into<String>, node: Node) {
        let name = name.into();
        self.nodes.insert(name.clone(), node);
        self.peers.entry(name.clone()).or_default();
        self.seen_blocks.entry(name.clone()).or_default();
        self.seen_txs.entry(name).or_default();
    }

    /// Register `node` under `name` with a DHT `NodeId` for peer discovery.
    /// Replaces any previous node of that name.
    pub fn add_with_dht(&mut self, name: impl Into<String>, node: Node, node_id: NodeId) {
        let name = name.into();
        self.nodes.insert(name.clone(), node);
        self.peers.entry(name.clone()).or_default();
        self.seen_blocks.entry(name.clone()).or_default();
        self.seen_txs.entry(name.clone()).or_default();
        self.dht_tables.insert(name, RoutingTable::new(node_id, 8));
    }

    /// Registered node names, sorted.
    pub fn names(&self) -> Vec<String> {
        self.nodes.keys().cloned().collect()
    }

    /// Discrete mesh time.
    pub fn now(&self) -> u64 {
        self.now
    }

    /// Envelopes waiting to be delivered.
    pub fn queued(&self) -> usize {
        self.queue.len()
    }

    /// Borrow a node by name.
    pub fn node(&self, name: &str) -> Option<&Node> {
        self.nodes.get(name)
    }

    /// Mutably borrow a node by name.
    pub fn node_mut(&mut self, name: &str) -> Option<&mut Node> {
        self.nodes.get_mut(name)
    }

    /// Get the P2P hardening manager (for monitoring/stats).
    pub fn hardening(&self) -> &P2pHardening {
        &self.hardening
    }

    /// Get mutable P2P hardening manager (for config changes).
    pub fn hardening_mut(&mut self) -> &mut P2pHardening {
        &mut self.hardening
    }

    /// Check if a peer is banned.
    pub fn is_peer_banned(&self, peer: &str) -> bool {
        self.hardening.is_banned(peer)
    }

    /// Get peer stats.
    pub fn peer_stats(&self, peer: &str) -> Option<PeerStats> {
        self.hardening.peer_stats(peer)
    }

    /// Get all peer stats.
    pub fn all_peer_stats(&self) -> BTreeMap<String, PeerStats> {
        self.hardening.all_peer_stats()
    }

    /// Manually ban a peer.
    pub fn ban_peer(&mut self, peer: &str) {
        self.hardening.ban(peer);
    }

    /// Manually unban a peer.
    pub fn unban_peer(&mut self, peer: &str) {
        self.hardening.unban(peer);
    }

    /// Directed overlay edge: `from` will announce blocks/txs/hellos to `to`.
    /// Enqueues a hello so `to` learns about `from` (and `from`'s peers).
    pub fn connect(&mut self, from: &str, to: &str) -> Result<(), P2pError> {
        self.require(from)?;
        self.require(to)?;
        if from == to {
            return Ok(());
        }
        let inserted = self
            .peers
            .entry(from.to_string())
            .or_default()
            .insert(to.to_string());
        if inserted {
            self.enqueue_hello(from, to);
            record_peer_connected();
            set_peer_count(self.total_peer_count());

            // A verified handshake exchanges NodeId and address, so both sides
            // register each other as DHT contacts (Kademlia refreshes buckets
            // on verified responses). Established contacts therefore claim
            // bucket slots before unknown newcomers — later arrivals can only
            // enter the replacement cache while the bucket stays full, which
            // is the basis of eclipse resistance in this model.
            let from_id = self.dht_tables.get(from).map(|t| t.local_id);
            let to_id = self.dht_tables.get(to).map(|t| t.local_id);
            if let (Some(from_id), Some(to_id)) = (from_id, to_id) {
                let from_addr = format!("{}:9000", from); // simulated address
                let to_addr = format!("{}:9000", to);
                if let Some(table) = self.dht_tables.get_mut(from) {
                    table.update_contact(PeerContact::new(to_id, to_addr));
                }
                if let Some(table) = self.dht_tables.get_mut(to) {
                    table.update_contact(PeerContact::new(from_id, from_addr));
                }
            }
        }
        Ok(())
    }

    /// Total number of peer connections in the mesh.
    pub fn total_peer_count(&self) -> usize {
        self.peers.values().map(|s| s.len()).sum()
    }

    /// Current peers of `name`, in sorted order.
    pub fn peers_of(&self, name: &str) -> Vec<String> {
        self.peers
            .get(name)
            .map(|s| s.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Deliver every message whose `due` time is `<= now`, then advance `now`
    /// by one. Returns how many envelopes were delivered this tick.
    pub fn tick(&mut self) -> usize {
        self.now = self.now.saturating_add(1);
        self.hardening.tick();
        let mut due = Vec::new();
        let mut rest = Vec::new();
        for q in self.queue.drain(..) {
            if q.due <= self.now {
                due.push(q);
            } else {
                rest.push(q);
            }
        }
        self.queue = rest;
        let n = due.len();
        for q in due {
            self.deliver(q);
        }
        n
    }

    /// [`tick`] until the relay queue is empty (or `limit` ticks). Returns the
    /// number of envelopes delivered. The limit is a safety valve against a
    /// buggy flood; honest meshes drain in O(diameter) ticks.
    pub fn drain(&mut self, limit: u32) -> usize {
        let mut total = 0;
        for _ in 0..limit {
            if self.queue.is_empty() {
                break;
            }
            total += self.tick();
        }
        total
    }

    /// Whether the relay queue is empty (no pending envelopes).
    pub fn is_idle(&self) -> bool {
        self.queue.is_empty()
    }

    /// Perform a headers-first sync from `from` node to `to` node in-process.
    /// Returns the number of blocks applied, or an error.
    pub fn sync_headers_first(&mut self, from: &str, to: &str) -> Result<usize, P2pError> {
        self.require(from)?;
        self.require(to)?;
        // Clone the source node's state to avoid borrow conflict
        let records: Vec<BlockRecord> = {
            let from_node = self.nodes.get(from).expect("checked");
            from_node.export()
        };
        let to_node = self.nodes.get_mut(to).expect("checked");
        let mut applied = 0;
        for record in records {
            to_node.receive_block(record).map_err(P2pError::Node)?;
            applied += 1;
        }
        Ok(applied)
    }

    /// Produce a block on `name` and announce it to that node's peers.
    pub fn produce(&mut self, name: &str) -> Result<Option<BlockId>, P2pError> {
        self.require(name)?;
        let id = self.nodes.get_mut(name).expect("checked").produce_block()?;
        if let Some(id) = id {
            if let Some(rec) = self.nodes.get(name).and_then(|n| n.block_record(&id)) {
                self.announce_block(name, rec);
            }
        }
        Ok(id)
    }

    /// Produce an empty block on `name` and announce it.
    pub fn produce_empty(&mut self, name: &str) -> Result<BlockId, P2pError> {
        self.require(name)?;
        let id = self.nodes.get_mut(name).expect("checked").produce_empty()?;
        if let Some(rec) = self.nodes.get(name).and_then(|n| n.block_record(&id)) {
            self.announce_block(name, rec);
        }
        Ok(id)
    }

    /// Immediate send on `name`, then announce the new block.
    pub fn send(
        &mut self,
        name: &str,
        from_seed: u64,
        amount: u64,
        to_seed: u64,
    ) -> Result<BlockId, P2pError> {
        self.require(name)?;
        let sent = self
            .nodes
            .get_mut(name)
            .expect("checked")
            .send(from_seed, amount, to_seed)?;
        if let Some(rec) = self
            .nodes
            .get(name)
            .and_then(|n| n.block_record(&sent.block))
        {
            self.announce_block(name, rec);
        }
        Ok(sent.block)
    }

    /// Queue a transfer in `name`'s mempool and announce the tx to peers.
    pub fn pool(
        &mut self,
        name: &str,
        from_seed: u64,
        amount: u64,
        to_seed: u64,
    ) -> Result<TxId, P2pError> {
        self.require(name)?;
        let id = self
            .nodes
            .get_mut(name)
            .expect("checked")
            .pool(from_seed, amount, to_seed)?;
        if let Some(tx) = self.nodes.get(name).and_then(|n| n.mempool_tx(&id)) {
            self.announce_tx(name, tx);
        }
        Ok(id)
    }

    /// Wallet-signed spend into `name`'s mempool, then announce the tx.
    pub fn submit_signed(
        &mut self,
        name: &str,
        from: Address,
        amount: u64,
        to: Address,
        signature: [u8; 64],
    ) -> Result<TxId, P2pError> {
        self.require(name)?;
        let id = self
            .nodes
            .get_mut(name)
            .expect("checked")
            .submit_signed(from, amount, to, signature)?;
        if let Some(tx) = self.nodes.get(name).and_then(|n| n.mempool_tx(&id)) {
            self.announce_tx(name, tx);
        }
        Ok(id)
    }

    /// Seed actor pays an arbitrary address (explorer faucet) and announces.
    pub fn send_to(
        &mut self,
        name: &str,
        from_seed: u64,
        amount: u64,
        to: Address,
    ) -> Result<BlockId, P2pError> {
        self.require(name)?;
        let sent = self
            .nodes
            .get_mut(name)
            .expect("checked")
            .send_to(from_seed, amount, to)?;
        if let Some(rec) = self
            .nodes
            .get(name)
            .and_then(|n| n.block_record(&sent.block))
        {
            self.announce_block(name, rec);
        }
        Ok(sent.block)
    }

    /// Delivered events, oldest first.
    pub fn events(&self) -> &[GossipEvent] {
        &self.events
    }

    // ========================================================================
    // DHT Integration Methods
    // ========================================================================

    /// Get the DHT routing table for a node, if it has one.
    pub fn dht_table(&self, name: &str) -> Option<&RoutingTable> {
        self.dht_tables.get(name)
    }

    /// Get mutable DHT routing table for a node, if it has one.
    pub fn dht_table_mut(&mut self, name: &str) -> Option<&mut RoutingTable> {
        self.dht_tables.get_mut(name)
    }

    /// Perform a DHT bootstrap for `from` node using `seed` node as the entry point.
    /// The `from` node will query the `seed` node for its closest peers to the `from` node's own NodeId.
    /// Returns the number of new contacts added to the routing table.
    pub fn dht_bootstrap(&mut self, from: &str, seed: &str) -> Result<usize, P2pError> {
        self.require(from)?;
        self.require(seed)?;

        let from_id = self
            .dht_tables
            .get(from)
            .map(|t| t.local_id)
            .ok_or_else(|| P2pError::UnknownNode(format!("{} has no DHT table", from)))?;

        let seed_id = self
            .dht_tables
            .get(seed)
            .map(|t| t.local_id)
            .ok_or_else(|| P2pError::UnknownNode(format!("{} has no DHT table", seed)))?;

        let start = std::time::Instant::now();

        // Get seed's closest peers to from_id (excluding from itself)
        let seed_table = self.dht_tables.get(seed).unwrap();
        let mut contacts = seed_table.closest_peers(&from_id, seed_table.k);
        // Filter out self
        contacts.retain(|c| c.node_id != from_id);

        // Add seed itself as a contact
        let seed_addr = format!("{}:9000", seed); // Simulated address
        contacts.insert(0, PeerContact::new(seed_id, seed_addr));

        // Update from's routing table
        let from_table = self.dht_tables.get_mut(from).unwrap();
        let mut added = 0;
        for contact in contacts {
            if from_table.update_contact(contact) != crate::dht::UpdateResult::Cached {
                added += 1;
            }
        }

        let duration = start.elapsed();
        record_dht_bootstrap(duration, added);
        record_dht_query_sent();
        record_dht_query_received();

        Ok(added)
    }

    /// Add DHT contacts directly to a node's routing table (for testing / bootstrap simulation).
    /// Returns the number of contacts added.
    pub fn add_dht_contacts(
        &mut self,
        name: &str,
        contacts: Vec<PeerContact>,
    ) -> Result<usize, P2pError> {
        self.require(name)?;
        let table = self
            .dht_tables
            .get_mut(name)
            .ok_or_else(|| P2pError::UnknownNode(format!("{} has no DHT table", name)))?;
        let mut added = 0;
        for contact in contacts {
            if table.update_contact(contact) != crate::dht::UpdateResult::Cached {
                added += 1;
            }
        }
        Ok(added)
    }

    /// Perform an iterative DHT node lookup from `from` node for `target` NodeId.
    /// Uses α=3 concurrency and returns the k closest nodes found.
    pub fn dht_find_node(
        &mut self,
        from: &str,
        target: &NodeId,
    ) -> Result<Vec<PeerContact>, P2pError> {
        self.require(from)?;

        let from_table = self
            .dht_tables
            .get(from)
            .ok_or_else(|| P2pError::UnknownNode(format!("{} has no DHT table", from)))?;
        let k = from_table.k;

        let start = std::time::Instant::now();

        // Create a lookup
        let mut lookup = crate::dht::NodeLookup::new(*target, k, 3);

        // Get initial candidates from local routing table
        let initial_contacts = {
            let table = self.dht_tables.get(from).unwrap();
            table.closest_peers(target, k)
        };
        lookup.add_initial(initial_contacts);

        // Iterative lookup (simulated in-process)
        let mut rounds = 0;
        while !lookup.is_complete() && rounds < 10 {
            let candidates = lookup.next_candidates();
            if candidates.is_empty() {
                break;
            }

            // For each candidate, simulate querying their routing table
            // In real network this would be over the wire; here we simulate
            // by looking up the candidate's routing table if they exist in the mesh
            let mut found_contacts = Vec::new();
            for candidate in candidates {
                record_dht_query_sent();
                // Try to find this candidate as a node in our mesh
                // In simulation, we check if any node has this NodeId
                let candidate_name = self.find_node_by_id(&candidate.node_id);
                if let Some(name) = candidate_name {
                    if let Some(table) = self.dht_tables.get(&name) {
                        record_dht_query_received();
                        let contacts = table.closest_peers(target, k);
                        found_contacts.extend(contacts);
                    }
                }
            }

            if !found_contacts.is_empty() {
                lookup.add_results(found_contacts);
            }
            rounds += 1;
        }

        let duration = start.elapsed();
        let results = lookup.closest().len();
        record_dht_find_node(duration, results);

        Ok(lookup.closest())
    }

    /// Find a node name by its NodeId in the mesh.
    fn find_node_by_id(&self, node_id: &NodeId) -> Option<String> {
        for (name, table) in &self.dht_tables {
            if table.local_id == *node_id {
                return Some(name.clone());
            }
        }
        None
    }

    /// Prune unreachable peers from all DHT routing tables.
    /// Removes contacts with 3+ failed queries.
    /// Returns the total number of peers pruned across all tables.
    pub fn prune_unreachable_peers(&mut self) -> usize {
        let mut total_pruned = 0;
        for table in self.dht_tables.values_mut() {
            let pruned = table.prune_unresponsive(3);
            total_pruned += pruned.len();
        }
        if total_pruned > 0 {
            record_dht_pruned(total_pruned);
        }
        total_pruned
    }

    /// Replenish active P2P connections from DHT routing tables.
    /// For each node with a DHT table, if its active peer count is below target,
    /// query the DHT for new peers and connect to them.
    pub fn replenish_peers_from_dht(&mut self, target_peer_count: usize) -> usize {
        let mut total_added = 0;
        let node_names: Vec<String> = self.nodes.keys().cloned().collect();

        for name in node_names {
            let existing_peers: std::collections::HashSet<String> =
                self.peers_of(&name).into_iter().collect();
            if existing_peers.len() >= target_peer_count {
                continue;
            }

            let mut needed = target_peer_count - existing_peers.len();

            if let Some(table) = self.dht_tables.get(&name) {
                let local_id = table.local_id;
                let candidate_count = table.all_contacts().len();
                let contacts = table.closest_peers(&local_id, candidate_count);

                for contact in contacts {
                    if needed == 0 {
                        break;
                    }
                    // Try to find the peer in our mesh by NodeId
                    if let Some(peer_name) = self.find_node_by_id(&contact.node_id) {
                        if peer_name != name
                            && !existing_peers.contains(&peer_name)
                            && self.connect(&name, &peer_name).is_ok()
                        {
                            total_added += 1;
                            needed -= 1;
                        }
                    }
                }
            }
        }
        total_added
    }

    fn require(&self, name: &str) -> Result<(), P2pError> {
        if self.nodes.contains_key(name) {
            Ok(())
        } else {
            Err(P2pError::UnknownNode(name.to_string()))
        }
    }

    fn enqueue_hello(&mut self, from: &str, to: &str) {
        let advertised = self.peers_of(from);
        self.enqueue(from, to, Envelope::Hello { advertised });
    }

    pub fn announce_block(&mut self, from: &str, record: BlockRecord) {
        let id = record_id(&record);
        self.seen_blocks
            .entry(from.to_string())
            .or_default()
            .insert(id);
        let peers = self.peers_of(from);
        for to in peers {
            self.enqueue(
                from,
                &to,
                Envelope::Block {
                    record: record.clone(),
                },
            );
        }
    }

    fn announce_tx(&mut self, from: &str, tx: Transaction) {
        let id = tx.id();
        self.seen_txs
            .entry(from.to_string())
            .or_default()
            .insert(id);
        let peers = self.peers_of(from);
        for to in peers {
            self.enqueue(from, &to, Envelope::Tx { tx: tx.clone() });
        }
    }

    fn enqueue(&mut self, from: &str, to: &str, envelope: Envelope) {
        if from == to {
            return;
        }
        // Estimate bytes for rate limiting
        let bytes = match &envelope {
            Envelope::Hello { advertised } => 100 + advertised.len() * 32,
            Envelope::Block { record } => {
                // Rough estimate: parents + work + timestamp + nonce + txs
                100 + record.parents.len() * 32 + record.txs.len() * 200
            }
            Envelope::Tx { .. } => 200,
        };

        // Check rate limit for the sender
        if !self.hardening.check_rate_limit(from, bytes as u64) {
            return; // Silently drop - rate limited
        }

        self.queue.push(Queued {
            due: self.now.saturating_add(1),
            from: from.to_string(),
            to: to.to_string(),
            envelope,
        });
    }

    fn deliver(&mut self, q: Queued) {
        let kind = match &q.envelope {
            Envelope::Hello { .. } => GossipKind::Hello,
            Envelope::Block { .. } => GossipKind::Block,
            Envelope::Tx { .. } => GossipKind::Tx,
        };
        // Record message sent
        let kind_str = match kind {
            GossipKind::Hello => "hello",
            GossipKind::Block => "block",
            GossipKind::Tx => "tx",
        };
        // Estimate bytes (rough)
        let bytes = match &q.envelope {
            Envelope::Hello { advertised } => 100 + advertised.len() * 32,
            Envelope::Block { record } => 100 + record.parents.len() * 32 + record.txs.len() * 200,
            Envelope::Tx { .. } => 200,
        };
        record_p2p_message_sent(kind_str, bytes);
        record_p2p_message_received(kind_str, bytes);

        self.events.push(GossipEvent {
            at: self.now,
            from: q.from.clone(),
            to: q.to.clone(),
            kind,
        });
        match q.envelope {
            Envelope::Hello { advertised } => self.on_hello(&q.to, &q.from, advertised),
            Envelope::Block { record } => self.on_block(&q.to, &q.from, record),
            Envelope::Tx { tx } => self.on_tx(&q.to, &q.from, tx),
        }
    }

    fn on_hello(&mut self, to: &str, from: &str, advertised: Vec<String>) {
        if !self.nodes.contains_key(to) {
            return;
        }
        let peers = self.peers.entry(to.to_string()).or_default();
        let new_reverse = peers.insert(from.to_string());
        let mut fresh = Vec::new();
        for p in advertised {
            if p != to && p != from && self.nodes.contains_key(&p) && peers.insert(p.clone()) {
                fresh.push(p);
            }
        }
        if new_reverse {
            self.enqueue_hello(to, from);
        }
        for p in fresh {
            self.enqueue_hello(to, &p);
        }
    }

    fn on_block(&mut self, to: &str, from: &str, record: BlockRecord) {
        let id = record_id(&record);

        // Check hardening: duplicate tracking and peer scoring
        let (is_new, banned) = self.hardening.on_block(from, &id, true);
        if !is_new || banned {
            // Duplicate or banned - don't process
            return;
        }

        let seen = self.seen_blocks.entry(to.to_string()).or_default();
        if !seen.insert(id) {
            return;
        }
        if let Some(node) = self.nodes.get_mut(to) {
            if node.receive_block(record.clone()).is_err() {
                return;
            }
        }
        let peers = self.peers_of(to);
        for nxt in peers {
            if nxt == from {
                continue;
            }
            self.enqueue(
                to,
                &nxt,
                Envelope::Block {
                    record: record.clone(),
                },
            );
        }
    }

    fn on_tx(&mut self, to: &str, from: &str, tx: Transaction) {
        let id = tx.id();

        // Check hardening: duplicate tracking and peer scoring
        let (is_new, banned) = self.hardening.on_tx(from, &id, true);
        if !is_new || banned {
            // Duplicate or banned - don't process
            return;
        }

        let seen = self.seen_txs.entry(to.to_string()).or_default();
        if !seen.insert(id) {
            return;
        }
        if let Some(node) = self.nodes.get_mut(to) {
            if node.submit_tx(tx.clone()).is_err() {
                return;
            }
        }
        let peers = self.peers_of(to);
        for nxt in peers {
            if nxt == from {
                continue;
            }
            self.enqueue(to, &nxt, Envelope::Tx { tx: tx.clone() });
        }
    }
}
