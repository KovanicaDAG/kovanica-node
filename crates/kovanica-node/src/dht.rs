//! Lightweight Kademlia-based DHT for peer routing.
//!
//! Implements a 256-bit NodeId space with XOR metric, 256 k-buckets with
//! configurable capacity (k=8 or k=20), LRU ordering with replacement cache,
//! head-probing ping eviction, 3-strike dead peer pruning, and iterative
//! node lookup (α=3 concurrency) over distance-sorted shortlists.

use std::collections::VecDeque;
use std::time::{SystemTime, UNIX_EPOCH};

use blake3;
use rand::Rng;

/// 256-bit NodeId for Kademlia routing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NodeId(pub [u8; 32]);

impl NodeId {
    /// Generate a random NodeId.
    pub fn random() -> Self {
        let mut rng = rand::thread_rng();
        let mut bytes = [0u8; 32];
        rng.fill(&mut bytes);
        Self(bytes)
    }

    /// Create a NodeId from raw bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Create a NodeId from a public key (BLAKE3 hash).
    pub fn from_public_key(pubkey: &[u8]) -> Self {
        Self(*blake3::hash(pubkey).as_bytes())
    }

    /// XOR distance between two NodeIds.
    pub fn distance(&self, other: &NodeId) -> [u8; 32] {
        let mut dist = [0u8; 32];
        for (d, (a, b)) in dist.iter_mut().zip(self.0.iter().zip(other.0.iter())) {
            *d = a ^ b;
        }
        dist
    }

    /// Bucket index for a target NodeId (leading zero bits of XOR distance).
    /// Returns None if distance is zero (self).
    pub fn bucket_index(&self, other: &NodeId) -> Option<usize> {
        let dist = self.distance(other);
        for (i, byte) in dist.iter().enumerate() {
            if *byte != 0 {
                return Some(i * 8 + byte.leading_zeros() as usize);
            }
        }
        None // distance is zero (self)
    }

    /// Get the raw bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Convert to hex string.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parse from hex string.
    pub fn from_hex(s: &str) -> Result<Self, hex::FromHexError> {
        let bytes = hex::decode(s)?;
        if bytes.len() != 32 {
            return Err(hex::FromHexError::InvalidStringLength);
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }
}

impl std::fmt::Display for NodeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// A contact in the Kademlia routing table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerContact {
    /// The peer's NodeId.
    pub node_id: NodeId,
    /// The peer's network address (IP:port).
    pub addr: String,
    /// Last time this peer was seen (Unix milliseconds).
    pub last_seen_ms: u64,
    /// Number of consecutive failed queries.
    pub failed_queries: u32,
}

impl PeerContact {
    /// Create a new peer contact.
    pub fn new(node_id: NodeId, addr: String) -> Self {
        let now = current_time_ms();
        Self {
            node_id,
            addr,
            last_seen_ms: now,
            failed_queries: 0,
        }
    }

    /// Update last seen time to now.
    pub fn touch(&mut self) {
        self.last_seen_ms = current_time_ms();
        self.failed_queries = 0;
    }

    /// Increment failed query count.
    pub fn mark_failed(&mut self) {
        self.failed_queries = self.failed_queries.saturating_add(1);
    }

    /// Check if peer is considered dead (3+ failures).
    pub fn is_dead(&self) -> bool {
        self.failed_queries >= 3
    }
}

/// A single k-bucket in the routing table.
#[derive(Clone, Debug, Default)]
pub struct KBucket {
    /// Contacts in LRU order (front = most recent, back = least recent).
    contacts: VecDeque<PeerContact>,
    /// Replacement cache for when bucket is full.
    replacement_cache: VecDeque<PeerContact>,
    /// Maximum capacity of the bucket (k).
    k: usize,
}

impl KBucket {
    /// Create a new k-bucket with capacity k.
    pub fn new(k: usize) -> Self {
        Self {
            contacts: VecDeque::new(),
            replacement_cache: VecDeque::new(),
            k,
        }
    }

    /// Get the number of contacts in the bucket.
    pub fn len(&self) -> usize {
        self.contacts.len()
    }

    /// Check if bucket is empty.
    pub fn is_empty(&self) -> bool {
        self.contacts.is_empty()
    }

    /// Check if bucket is full.
    pub fn is_full(&self) -> bool {
        self.contacts.len() >= self.k
    }

    /// Get all contacts (most recent first).
    pub fn contacts(&self) -> Vec<PeerContact> {
        self.contacts.iter().cloned().collect()
    }

    /// Update or insert a contact. Returns the update result.
    pub fn update_contact(&mut self, contact: PeerContact) -> UpdateResult {
        let node_id = contact.node_id;

        // Check if already in contacts
        if let Some(pos) = self.contacts.iter().position(|c| c.node_id == node_id) {
            let mut existing = self.contacts.remove(pos).unwrap();
            existing.addr = contact.addr;
            existing.touch();
            self.contacts.push_front(existing);
            return UpdateResult::Updated;
        }

        // Check if in replacement cache
        if let Some(pos) = self
            .replacement_cache
            .iter()
            .position(|c| c.node_id == node_id)
        {
            let mut existing = self.replacement_cache.remove(pos).unwrap();
            existing.addr = contact.addr;
            existing.touch();
            // Move to contacts if there's space
            if !self.is_full() {
                self.contacts.push_front(existing);
                return UpdateResult::Promoted;
            } else {
                // Move to front of replacement cache
                self.replacement_cache.push_front(existing);
                return UpdateResult::Cached;
            }
        }

        // New contact
        if !self.is_full() {
            self.contacts.push_front(contact);
            UpdateResult::Added
        } else {
            // Add to replacement cache (LRU)
            self.replacement_cache.push_front(contact);
            if self.replacement_cache.len() > self.k {
                self.replacement_cache.pop_back();
            }
            UpdateResult::Cached
        }
    }

    /// Get the least recently used contact (for ping eviction).
    pub fn lru_contact(&self) -> Option<PeerContact> {
        self.contacts.back().cloned()
    }

    /// Remove and return the LRU contact.
    pub fn pop_lru(&mut self) -> Option<PeerContact> {
        self.contacts.pop_back()
    }

    /// Promote a contact from replacement cache to contacts (after successful ping).
    pub fn promote_from_cache(&mut self, node_id: &NodeId) -> Option<PeerContact> {
        if let Some(pos) = self
            .replacement_cache
            .iter()
            .position(|c| c.node_id == *node_id)
        {
            let mut contact = self.replacement_cache.remove(pos).unwrap();
            contact.touch();
            if !self.is_full() {
                self.contacts.push_front(contact.clone());
                Some(contact)
            } else {
                // Should not happen if called correctly
                self.replacement_cache.push_front(contact);
                None
            }
        } else {
            None
        }
    }

    /// Mark a contact as failed. Returns the contact if it should be evicted (3 strikes).
    pub fn mark_failed(&mut self, node_id: &NodeId) -> Option<PeerContact> {
        // Check contacts
        if let Some(pos) = self.contacts.iter().position(|c| c.node_id == *node_id) {
            let mut contact = self.contacts.remove(pos).unwrap();
            contact.mark_failed();
            if contact.is_dead() {
                // If replacement candidate exists, promote it to keep bucket full
                if let Some(mut replacement) = self.replacement_cache.pop_front() {
                    replacement.touch();
                    self.contacts.push_front(replacement);
                }
                return Some(contact);
            }
            self.contacts.push_back(contact); // Move to back (least recent)
            return None;
        }
        // Check replacement cache
        if let Some(pos) = self
            .replacement_cache
            .iter()
            .position(|c| c.node_id == *node_id)
        {
            let mut contact = self.replacement_cache.remove(pos).unwrap();
            contact.mark_failed();
            if contact.is_dead() {
                return Some(contact);
            }
            self.replacement_cache.push_back(contact);
        }
        None
    }

    /// Prune all dead contacts (3+ failures).
    pub fn prune_dead(&mut self) -> Vec<PeerContact> {
        let mut dead = Vec::new();
        self.contacts.retain(|c| {
            if c.is_dead() {
                dead.push(c.clone());
                false
            } else {
                true
            }
        });
        self.replacement_cache.retain(|c| {
            if c.is_dead() {
                dead.push(c.clone());
                false
            } else {
                true
            }
        });
        while self.contacts.len() < self.k && !self.replacement_cache.is_empty() {
            if let Some(mut rep) = self.replacement_cache.pop_front() {
                rep.touch();
                self.contacts.push_front(rep);
            }
        }
        dead
    }
}

/// Result of updating a k-bucket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UpdateResult {
    /// Contact was added to the bucket.
    Added,
    /// Contact was updated (moved to front).
    Updated,
    /// Contact was promoted from replacement cache.
    Promoted,
    /// Contact was cached in replacement cache.
    Cached,
}

/// Kademlia routing table with 256 k-buckets.
#[derive(Clone, Debug)]
pub struct RoutingTable {
    /// The local node's ID.
    pub local_id: NodeId,
    /// Bucket capacity (k).
    pub k: usize,
    /// The 256 k-buckets.
    buckets: Vec<KBucket>,
}

impl RoutingTable {
    /// Create a new routing table for the given local NodeId and bucket size k.
    pub fn new(local_id: NodeId, k: usize) -> Self {
        let mut buckets = Vec::with_capacity(256);
        for _ in 0..256 {
            buckets.push(KBucket::new(k));
        }
        Self {
            local_id,
            k,
            buckets,
        }
    }

    /// Get the bucket index for a target NodeId.
    fn bucket_idx(&self, target: &NodeId) -> Option<usize> {
        self.local_id.bucket_index(target)
    }

    /// Update or insert a contact into the appropriate bucket.
    pub fn update_contact(&mut self, contact: PeerContact) -> UpdateResult {
        if contact.node_id == self.local_id {
            return UpdateResult::Updated; // Don't add self
        }
        if let Some(idx) = self.bucket_idx(&contact.node_id) {
            self.buckets[idx].update_contact(contact)
        } else {
            UpdateResult::Updated // Self contact
        }
    }

    /// Get the k closest peers to a target NodeId.
    pub fn closest_peers(&self, target: &NodeId, count: usize) -> Vec<PeerContact> {
        let mut candidates = Vec::new();

        // Determine bucket order by distance to target
        let mut bucket_order: Vec<usize> = (0..256).collect();
        bucket_order.sort_by_key(|&i| {
            // Compute approximate distance from target to this bucket's range
            // The bucket covers nodes where leading zeros of XOR distance = i
            // So bucket i is at distance roughly 2^(255-i)
            i
        });

        for idx in bucket_order {
            let bucket = &self.buckets[idx];
            for contact in bucket.contacts() {
                candidates.push(contact);
            }
            for contact in bucket.replacement_cache.iter() {
                candidates.push(contact.clone());
            }
        }

        // Sort by actual XOR distance
        candidates.sort_by_key(|c| c.node_id.distance(target));
        candidates.dedup_by_key(|c| c.node_id);
        candidates.truncate(count);
        candidates
    }

    /// Mark a contact as failed. Returns the evicted contact if it reached 3 strikes.
    pub fn mark_failed(&mut self, node_id: &NodeId) -> Option<PeerContact> {
        if let Some(idx) = self.bucket_idx(node_id) {
            self.buckets[idx].mark_failed(node_id)
        } else {
            None
        }
    }

    /// Prune all unresponsive peers (3+ failures) across all buckets.
    pub fn prune_unresponsive(&mut self, max_failed: u32) -> Vec<PeerContact> {
        let mut pruned = Vec::new();
        for bucket in &mut self.buckets {
            if max_failed >= 3 {
                pruned.extend(bucket.prune_dead());
            }
        }
        pruned
    }

    /// Get all contacts in the routing table.
    pub fn all_contacts(&self) -> Vec<PeerContact> {
        let mut contacts = Vec::new();
        for bucket in &self.buckets {
            contacts.extend(bucket.contacts());
            contacts.extend(bucket.replacement_cache.iter().cloned());
        }
        contacts
    }

    /// Get the total number of contacts.
    pub fn total_contacts(&self) -> usize {
        self.buckets.iter().map(|b| b.len()).sum()
    }

    /// Refresh a bucket by performing a lookup for a random ID in that bucket's range.
    /// Returns a target NodeId to query.
    pub fn refresh_bucket(&self, bucket_idx: usize) -> Option<NodeId> {
        if bucket_idx >= 256 {
            return None;
        }
        // Generate a random ID that falls in this bucket
        let mut bytes = self.local_id.0;
        let byte_idx = bucket_idx / 8;
        let bit_idx = bucket_idx % 8;
        // Flip the bit at this position to ensure it falls in this bucket
        bytes[byte_idx] ^= 1 << (7 - bit_idx);
        Some(NodeId(bytes))
    }
}

/// Current time in milliseconds since Unix epoch.
fn current_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// DHT wire message types.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DhtMsg {
    /// Ping request.
    Ping { sender: NodeId, nonce: u64 },
    /// Ping response.
    Pong { sender: NodeId, nonce: u64 },
    /// Find node request.
    FindNode {
        sender: NodeId,
        target: NodeId,
        nonce: u64,
    },
    /// Find node response (nodes).
    Nodes {
        sender: NodeId,
        target: NodeId,
        nonce: u64,
        nodes: Vec<PeerContact>,
    },
}

/// DHT message tags for wire protocol.
pub const TAG_DHT_PING: u8 = 0x20;
pub const TAG_DHT_PONG: u8 = 0x21;
pub const TAG_DHT_FIND_NODE: u8 = 0x22;
pub const TAG_DHT_NODES: u8 = 0x23;

impl DhtMsg {
    /// Encode a DHT message to bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        match self {
            DhtMsg::Ping { sender, nonce } => {
                buf.push(TAG_DHT_PING);
                buf.extend_from_slice(sender.as_bytes());
                buf.extend_from_slice(&nonce.to_le_bytes());
            }
            DhtMsg::Pong { sender, nonce } => {
                buf.push(TAG_DHT_PONG);
                buf.extend_from_slice(sender.as_bytes());
                buf.extend_from_slice(&nonce.to_le_bytes());
            }
            DhtMsg::FindNode {
                sender,
                target,
                nonce,
            } => {
                buf.push(TAG_DHT_FIND_NODE);
                buf.extend_from_slice(sender.as_bytes());
                buf.extend_from_slice(target.as_bytes());
                buf.extend_from_slice(&nonce.to_le_bytes());
            }
            DhtMsg::Nodes {
                sender,
                target,
                nonce,
                nodes,
            } => {
                buf.push(TAG_DHT_NODES);
                buf.extend_from_slice(sender.as_bytes());
                buf.extend_from_slice(target.as_bytes());
                buf.extend_from_slice(&nonce.to_le_bytes());
                buf.extend_from_slice(&(nodes.len() as u16).to_le_bytes());
                for node in nodes {
                    buf.extend_from_slice(node.node_id.as_bytes());
                    // Encode address as string
                    let addr_bytes = node.addr.as_bytes();
                    buf.extend_from_slice(&(addr_bytes.len() as u16).to_le_bytes());
                    buf.extend_from_slice(addr_bytes);
                    buf.extend_from_slice(&node.last_seen_ms.to_le_bytes());
                    buf.extend_from_slice(&node.failed_queries.to_le_bytes());
                }
            }
        }
        buf
    }

    /// Decode a DHT message from bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.is_empty() {
            return Err("empty frame".into());
        }
        let tag = bytes[0];
        let rest = &bytes[1..];
        match tag {
            TAG_DHT_PING => {
                if rest.len() < 40 {
                    return Err("ping truncated".into());
                }
                let sender = NodeId::from_bytes(rest[..32].try_into().unwrap());
                let nonce = u64::from_le_bytes(rest[32..40].try_into().unwrap());
                Ok(DhtMsg::Ping { sender, nonce })
            }
            TAG_DHT_PONG => {
                if rest.len() < 40 {
                    return Err("pong truncated".into());
                }
                let sender = NodeId::from_bytes(rest[..32].try_into().unwrap());
                let nonce = u64::from_le_bytes(rest[32..40].try_into().unwrap());
                Ok(DhtMsg::Pong { sender, nonce })
            }
            TAG_DHT_FIND_NODE => {
                if rest.len() < 72 {
                    return Err("find_node truncated".into());
                }
                let sender = NodeId::from_bytes(rest[..32].try_into().unwrap());
                let target = NodeId::from_bytes(rest[32..64].try_into().unwrap());
                let nonce = u64::from_le_bytes(rest[64..72].try_into().unwrap());
                Ok(DhtMsg::FindNode {
                    sender,
                    target,
                    nonce,
                })
            }
            TAG_DHT_NODES => {
                if rest.len() < 72 {
                    return Err("nodes truncated".into());
                }
                let sender = NodeId::from_bytes(rest[..32].try_into().unwrap());
                let target = NodeId::from_bytes(rest[32..64].try_into().unwrap());
                let nonce = u64::from_le_bytes(rest[64..72].try_into().unwrap());
                let mut pos = 72;
                if pos + 2 > rest.len() {
                    return Err("nodes count truncated".into());
                }
                let count = u16::from_le_bytes(rest[pos..pos + 2].try_into().unwrap()) as usize;
                pos += 2;
                let mut nodes = Vec::with_capacity(count);
                for _ in 0..count {
                    if pos + 32 > rest.len() {
                        return Err("node id truncated".into());
                    }
                    let node_id = NodeId::from_bytes(rest[pos..pos + 32].try_into().unwrap());
                    pos += 32;
                    if pos + 2 > rest.len() {
                        return Err("addr len truncated".into());
                    }
                    let addr_len =
                        u16::from_le_bytes(rest[pos..pos + 2].try_into().unwrap()) as usize;
                    pos += 2;
                    if pos + addr_len > rest.len() {
                        return Err("addr truncated".into());
                    }
                    let addr = String::from_utf8(rest[pos..pos + addr_len].to_vec())
                        .map_err(|_| "addr not utf-8")?;
                    pos += addr_len;
                    if pos + 12 > rest.len() {
                        return Err("timestamp/failed truncated".into());
                    }
                    let last_seen_ms = u64::from_le_bytes(rest[pos..pos + 8].try_into().unwrap());
                    pos += 8;
                    let failed_queries = u32::from_le_bytes(rest[pos..pos + 4].try_into().unwrap());
                    pos += 4;
                    nodes.push(PeerContact {
                        node_id,
                        addr,
                        last_seen_ms,
                        failed_queries,
                    });
                }
                Ok(DhtMsg::Nodes {
                    sender,
                    target,
                    nonce,
                    nodes,
                })
            }
            _ => Err(format!("unknown DHT tag {tag}")),
        }
    }
}

/// Iterative node lookup with α=3 concurrency.
pub struct NodeLookup {
    /// Target NodeId to find.
    target: NodeId,
    /// Set of queried NodeIds.
    queried: std::collections::HashSet<NodeId>,
    /// Shortlist of candidate nodes (distance, contact).
    shortlist: Vec<(NodeId, PeerContact)>,
    /// Number of closest nodes to return (k).
    k: usize,
    /// Concurrency factor (α).
    alpha: usize,
}

impl NodeLookup {
    /// Create a new node lookup.
    pub fn new(target: NodeId, k: usize, alpha: usize) -> Self {
        Self {
            target,
            queried: std::collections::HashSet::new(),
            shortlist: Vec::new(),
            k,
            alpha,
        }
    }

    /// Add initial candidates from the routing table.
    pub fn add_initial(&mut self, contacts: Vec<PeerContact>) {
        for contact in contacts {
            let dist = contact.node_id.distance(&self.target);
            if !self
                .shortlist
                .iter()
                .any(|(_, c)| c.node_id == contact.node_id)
            {
                self.shortlist.push((NodeId(dist), contact));
            }
        }
        // Sort by distance
        self.shortlist.sort_by_key(|(dist, _)| *dist);
    }

    /// Get the next α unqueried candidates to query.
    pub fn next_candidates(&mut self) -> Vec<PeerContact> {
        let mut candidates = Vec::new();
        for (_, contact) in &self.shortlist {
            if !self.queried.contains(&contact.node_id) && candidates.len() < self.alpha {
                candidates.push(contact.clone());
            }
        }
        for c in &candidates {
            self.queried.insert(c.node_id);
        }
        candidates
    }

    /// Add results from a query response.
    pub fn add_results(&mut self, contacts: Vec<PeerContact>) {
        for contact in contacts {
            let dist = contact.node_id.distance(&self.target);
            // Check if already in shortlist
            if let Some(pos) = self
                .shortlist
                .iter()
                .position(|(_, c)| c.node_id == contact.node_id)
            {
                if contact.last_seen_ms >= self.shortlist[pos].1.last_seen_ms {
                    self.shortlist[pos].1 = contact;
                }
            } else {
                self.shortlist.push((NodeId(dist), contact));
            }
        }
        // Re-sort by distance
        self.shortlist.sort_by_key(|(dist, _)| *dist);
    }

    /// Check if lookup is complete (no more unqueried candidates closer than current best).
    pub fn is_complete(&self) -> bool {
        // Find the k-th closest node in shortlist
        if self.shortlist.len() < self.k {
            // Not enough candidates yet, check if we have unqueried
            self.shortlist
                .iter()
                .all(|(_, c)| self.queried.contains(&c.node_id))
        } else {
            let _kth_dist = self.shortlist[self.k - 1].0;
            // Check if any unqueried candidate is closer than kth
            self.shortlist
                .iter()
                .take(self.k)
                .all(|(_, c)| self.queried.contains(&c.node_id))
        }
    }

    /// Get the k closest nodes found so far.
    pub fn closest(&self) -> Vec<PeerContact> {
        self.shortlist
            .iter()
            .take(self.k)
            .map(|(_, c)| c.clone())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_node_id_random() {
        let id1 = NodeId::random();
        let id2 = NodeId::random();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_node_id_distance() {
        let id1 = NodeId::from_bytes([0u8; 32]);
        let mut id2_bytes = [0u8; 32];
        id2_bytes[31] = 1;
        let id2 = NodeId::from_bytes(id2_bytes);
        let dist = id1.distance(&id2);
        assert_eq!(dist[31], 1);
        assert_eq!(dist[..31], [0u8; 31]);
    }

    #[test]
    fn test_node_id_bucket_index() {
        let id1 = NodeId::from_bytes([0u8; 32]);
        let mut id2_bytes = [0u8; 32];
        id2_bytes[31] = 1;
        let id2 = NodeId::from_bytes(id2_bytes);
        assert_eq!(id1.bucket_index(&id2), Some(255)); // Last bit differs

        let mut id3_bytes = [0u8; 32];
        id3_bytes[0] = 0x80;
        let id3 = NodeId::from_bytes(id3_bytes);
        assert_eq!(id1.bucket_index(&id3), Some(0)); // First bit differs
    }

    #[test]
    fn test_node_id_self_distance() {
        let id = NodeId::random();
        assert_eq!(id.bucket_index(&id), None);
    }

    #[test]
    fn test_kbucket_basic() {
        let mut bucket = KBucket::new(3);
        let id1 = NodeId::from_bytes([1u8; 32]);
        let id2 = NodeId::from_bytes([2u8; 32]);
        let id3 = NodeId::from_bytes([3u8; 32]);

        let c1 = PeerContact::new(id1, "127.0.0.1:9001".to_string());
        let c2 = PeerContact::new(id2, "127.0.0.1:9002".to_string());
        let c3 = PeerContact::new(id3, "127.0.0.1:9003".to_string());

        assert_eq!(bucket.update_contact(c1), UpdateResult::Added);
        assert_eq!(bucket.update_contact(c2), UpdateResult::Added);
        assert_eq!(bucket.update_contact(c3), UpdateResult::Added);
        assert!(bucket.is_full());

        // Adding a fourth should go to replacement cache
        let id4 = NodeId::from_bytes([4u8; 32]);
        let c4 = PeerContact::new(id4, "127.0.0.1:9004".to_string());
        assert_eq!(bucket.update_contact(c4), UpdateResult::Cached);
    }

    #[test]
    fn test_kbucket_lru_eviction() {
        let mut bucket = KBucket::new(2);
        let id1 = NodeId::from_bytes([1u8; 32]);
        let id2 = NodeId::from_bytes([2u8; 32]);
        let id3 = NodeId::from_bytes([3u8; 32]);

        let c1 = PeerContact::new(id1, "127.0.0.1:9001".to_string());
        let c2 = PeerContact::new(id2, "127.0.0.1:9002".to_string());
        let _c3 = PeerContact::new(id3, "127.0.0.1:9003".to_string());

        bucket.update_contact(c1);
        bucket.update_contact(c2);
        assert!(bucket.is_full());

        // Touch c1 to make it most recent
        bucket.update_contact(PeerContact::new(id1, "127.0.0.1:9001".to_string()));

        // LRU should be c2
        let lru = bucket.lru_contact().unwrap();
        assert_eq!(lru.node_id, id2);
    }

    #[test]
    fn test_kbucket_failure_eviction() {
        let mut bucket = KBucket::new(3);
        let id1 = NodeId::from_bytes([1u8; 32]);
        let c1 = PeerContact::new(id1, "127.0.0.1:9001".to_string());
        bucket.update_contact(c1);

        // Mark failed 3 times
        for _ in 0..3 {
            if let Some(evicted) = bucket.mark_failed(&id1) {
                assert_eq!(evicted.node_id, id1);
            }
        }
        assert!(bucket.is_empty());
    }

    #[test]
    fn test_routing_table_basic() {
        let local = NodeId::from_bytes([0u8; 32]);
        let mut table = RoutingTable::new(local, 8);

        let id1 = NodeId::from_bytes([1u8; 32]);
        let c1 = PeerContact::new(id1, "127.0.0.1:9001".to_string());
        table.update_contact(c1);

        assert_eq!(table.total_contacts(), 1);
    }

    #[test]
    fn test_routing_table_closest_peers() {
        let local = NodeId::from_bytes([0u8; 32]);
        let mut table = RoutingTable::new(local, 8);

        // Add contacts at various distances
        for i in 1..10 {
            let mut bytes = [0u8; 32];
            bytes[31] = i;
            let id = NodeId::from_bytes(bytes);
            let contact = PeerContact::new(id, format!("127.0.0.1:{}", 9000 + i as u16));
            table.update_contact(contact);
        }

        let target = NodeId::from_bytes([0u8; 32]);
        let closest = table.closest_peers(&target, 5);
        assert_eq!(closest.len(), 5);
        // Should be sorted by distance (lexicographically since XOR distance is byte array)
        for i in 1..closest.len() {
            let prev_dist = closest[i - 1].node_id.distance(&target);
            let curr_dist = closest[i].node_id.distance(&target);
            assert!(
                prev_dist <= curr_dist,
                "prev_dist {:?} > curr_dist {:?}",
                prev_dist,
                curr_dist
            );
        }
    }

    #[test]
    fn test_dht_msg_roundtrip() {
        let sender = NodeId::random();
        let target = NodeId::random();
        let nonce = 12345u64;

        let ping = DhtMsg::Ping { sender, nonce };
        let encoded = ping.encode();
        let decoded = DhtMsg::decode(&encoded).unwrap();
        assert_eq!(ping, decoded);

        let pong = DhtMsg::Pong { sender, nonce };
        let encoded = pong.encode();
        let decoded = DhtMsg::decode(&encoded).unwrap();
        assert_eq!(pong, decoded);

        let find_node = DhtMsg::FindNode {
            sender,
            target,
            nonce,
        };
        let encoded = find_node.encode();
        let decoded = DhtMsg::decode(&encoded).unwrap();
        assert_eq!(find_node, decoded);

        let nodes = DhtMsg::Nodes {
            sender,
            target,
            nonce,
            nodes: vec![PeerContact::new(
                NodeId::random(),
                "127.0.0.1:9000".to_string(),
            )],
        };
        let encoded = nodes.encode();
        let decoded = DhtMsg::decode(&encoded).unwrap();
        assert_eq!(nodes, decoded);
    }

    #[test]
    fn test_node_lookup() {
        let target = NodeId::random();
        let mut lookup = NodeLookup::new(target, 8, 3);

        // Add some initial contacts
        let mut contacts = Vec::new();
        for i in 0..10 {
            let mut bytes = target.0;
            bytes[31] = i as u8;
            let id = NodeId::from_bytes(bytes);
            contacts.push(PeerContact::new(
                id,
                format!("127.0.0.1:{}", 9000 + i as u16),
            ));
        }
        lookup.add_initial(contacts);

        // Get first candidates
        let candidates = lookup.next_candidates();
        assert_eq!(candidates.len(), 3);

        // Simulate response with closer nodes
        let mut new_contacts = Vec::new();
        for i in 10..15 {
            let mut bytes = target.0;
            bytes[31] = i as u8;
            let id = NodeId::from_bytes(bytes);
            new_contacts.push(PeerContact::new(
                id,
                format!("127.0.0.1:{}", 9000 + i as u16),
            ));
        }
        lookup.add_results(new_contacts);

        // Should have more candidates
        let more = lookup.next_candidates();
        assert!(!more.is_empty());
    }

    #[test]
    fn test_kbucket_prune_dead_promotes_replacement() {
        let mut bucket = KBucket::new(2);
        let id1 = NodeId::from_bytes([1u8; 32]);
        let id2 = NodeId::from_bytes([2u8; 32]);
        let id3 = NodeId::from_bytes([3u8; 32]);

        let mut c1 = PeerContact::new(id1, "127.0.0.1:9001".to_string());
        c1.failed_queries = 3; // Dead
        let c2 = PeerContact::new(id2, "127.0.0.1:9002".to_string());
        let c3 = PeerContact::new(id3, "127.0.0.1:9003".to_string());

        assert_eq!(bucket.update_contact(c1), UpdateResult::Added);
        assert_eq!(bucket.update_contact(c2), UpdateResult::Added);
        assert!(bucket.is_full());

        // c3 goes into replacement cache
        assert_eq!(bucket.update_contact(c3), UpdateResult::Cached);

        // Pruning dead peers should evict c1 and promote c3 from replacement cache
        let dead = bucket.prune_dead();
        assert_eq!(dead.len(), 1);
        assert_eq!(dead[0].node_id, id1);

        // Bucket should remain at capacity 2
        assert_eq!(bucket.len(), 2);
        let contacts = bucket.contacts();
        assert!(contacts.iter().any(|c| c.node_id == id2));
        assert!(contacts.iter().any(|c| c.node_id == id3));
    }

    #[test]
    fn test_node_lookup_add_results_updates_existing_contact() {
        let target = NodeId::random();
        let mut lookup = NodeLookup::new(target, 8, 3);

        let id = NodeId::from_bytes([42u8; 32]);
        let c1 = PeerContact {
            node_id: id,
            addr: "127.0.0.1:9001".to_string(),
            last_seen_ms: 100,
            failed_queries: 0,
        };
        lookup.add_initial(vec![c1]);

        // Add updated contact with newer timestamp and new address
        let c2 = PeerContact {
            node_id: id,
            addr: "127.0.0.1:9099".to_string(),
            last_seen_ms: 200,
            failed_queries: 0,
        };
        lookup.add_results(vec![c2]);

        let closest = lookup.closest();
        assert_eq!(closest.len(), 1);
        assert_eq!(closest[0].addr, "127.0.0.1:9099");
        assert_eq!(closest[0].last_seen_ms, 200);
    }
}
