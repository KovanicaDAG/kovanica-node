//! Block identity and the block type.
//!
//! A [`Block`] is the unit of the DAG. Unlike a linear chain, a block may
//! reference **multiple** parents (the tips its miner observed), which is what
//! lets the ledger admit parallel blocks and, in turn, high block throughput.
//!
//! A [`BlockId`] is the BLAKE3 hash of the block's canonical encoding, so it is
//! a stable, collision-resistant identifier that every node derives identically.

use core::fmt;

/// 32-byte BLAKE3 digest identifying a block.
///
/// Ordering is defined over the raw bytes so that consensus tie-breaks (which
/// fall back to the id) are deterministic across nodes.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BlockId([u8; 32]);

impl BlockId {
    /// Construct a `BlockId` from raw bytes (mainly for tests and decoding).
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The raw 32 bytes of the digest.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Lowercase hex rendering of the full digest.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Debug for BlockId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Short prefix keeps DAG dumps readable; full id via `to_hex`.
        write!(f, "BlockId({}…)", &self.to_hex()[..8])
    }
}

impl fmt::Display for BlockId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// A block: a vertex of the DAG.
///
/// Consensus (GHOSTDAG) interprets `parents`, `work`, and `timestamp_ms`
/// (the last two feed difficulty retargeting and its enforcement — see
/// [`crate::difficulty`]); `nonce` is the field a miner varies to make the
/// block's id meet its proof-of-work target (see [`crate::pow`]); `payload` is
/// opaque bytes (transactions, in a full ledger) and only affects the id.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Block {
    /// Ids of the parent blocks this block references. Empty only for genesis.
    parents: Vec<BlockId>,
    /// The block's own work/difficulty weight; contributes to blue work.
    work: u128,
    /// The block's timestamp, in milliseconds. Used by difficulty retargeting
    /// and, where enforced, must not precede any parent's timestamp.
    timestamp_ms: u64,
    /// The proof-of-work nonce: the value a miner searches over so the block's
    /// id meets its `work` target (see [`crate::pow`]). Folded into the id, so
    /// changing it changes the hash — which is what mining explores. Not
    /// interpreted by GHOSTDAG; `0` for a block that was never mined.
    nonce: u64,
    /// Opaque application payload; not interpreted by consensus.
    payload: Vec<u8>,
}

impl Block {
    /// Create a block referencing `parents` with the given `work`,
    /// `timestamp_ms`, `nonce`, and `payload`.
    ///
    /// Parents are de-duplicated and sorted so the id is independent of the
    /// order in which a miner happened to list them.
    pub fn new(
        mut parents: Vec<BlockId>,
        work: u128,
        timestamp_ms: u64,
        nonce: u64,
        payload: Vec<u8>,
    ) -> Self {
        parents.sort_unstable();
        parents.dedup();
        Self {
            parents,
            work,
            timestamp_ms,
            nonce,
            payload,
        }
    }

    /// The canonical genesis block: no parents, the given work, timestamp,
    /// nonce, and payload.
    pub fn genesis(work: u128, timestamp_ms: u64, nonce: u64, payload: Vec<u8>) -> Self {
        Self {
            parents: Vec::new(),
            work,
            timestamp_ms,
            nonce,
            payload,
        }
    }

    /// The block's parents (sorted, de-duplicated).
    pub fn parents(&self) -> &[BlockId] {
        &self.parents
    }

    /// The block's work weight.
    pub fn work(&self) -> u128 {
        self.work
    }

    /// The block's timestamp, in milliseconds.
    pub fn timestamp_ms(&self) -> u64 {
        self.timestamp_ms
    }

    /// The proof-of-work nonce (see [`crate::pow`]).
    pub fn nonce(&self) -> u64 {
        self.nonce
    }

    /// Return a copy of this block with the nonce set to `nonce`. Used by the
    /// miner ([`crate::pow::mine`]) to search nonces without rebuilding the rest
    /// of the block.
    pub fn with_nonce(&self, nonce: u64) -> Self {
        Self {
            nonce,
            ..self.clone()
        }
    }

    /// The opaque application payload.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Deterministic BLAKE3 id over the canonical encoding.
    ///
    /// Encoding (all integers little-endian): `parents.len()` as u64, each
    /// parent's 32 bytes in sorted order, `work` as u128, `timestamp_ms` as u64,
    /// `nonce` as u64, `payload.len()` as u64, then the payload bytes. Length
    /// prefixes make the encoding unambiguous (no two distinct blocks share an
    /// encoding). The nonce is folded in so that varying it changes the id —
    /// which is precisely what proof-of-work mining searches over.
    pub fn id(&self) -> BlockId {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&(self.parents.len() as u64).to_le_bytes());
        for parent in &self.parents {
            hasher.update(parent.as_bytes());
        }
        hasher.update(&self.work.to_le_bytes());
        hasher.update(&self.timestamp_ms.to_le_bytes());
        hasher.update(&self.nonce.to_le_bytes());
        hasher.update(&(self.payload.len() as u64).to_le_bytes());
        hasher.update(&self.payload);
        BlockId(*hasher.finalize().as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_is_deterministic() {
        let b = Block::new(vec![], 1, 0, 0, b"a".to_vec());
        assert_eq!(b.id(), b.id());
    }

    #[test]
    fn id_independent_of_parent_order() {
        let p1 = Block::genesis(1, 0, 0, b"p1".to_vec()).id();
        let p2 = Block::new(vec![p1], 1, 1, 0, b"p2".to_vec()).id();
        let a = Block::new(vec![p1, p2], 1, 2, 0, b"c".to_vec());
        let b = Block::new(vec![p2, p1], 1, 2, 0, b"c".to_vec());
        assert_eq!(a.id(), b.id());
    }

    #[test]
    fn distinct_payload_distinct_id() {
        let a = Block::new(vec![], 1, 0, 0, b"a".to_vec());
        let b = Block::new(vec![], 1, 0, 0, b"b".to_vec());
        assert_ne!(a.id(), b.id());
    }

    #[test]
    fn distinct_timestamp_distinct_id() {
        let a = Block::new(vec![], 1, 10, 0, b"a".to_vec());
        let b = Block::new(vec![], 1, 11, 0, b"a".to_vec());
        assert_ne!(a.id(), b.id());
        assert_eq!(a.timestamp_ms(), 10);
    }

    #[test]
    fn distinct_nonce_distinct_id() {
        let a = Block::new(vec![], 1, 0, 7, b"a".to_vec());
        let b = Block::new(vec![], 1, 0, 8, b"a".to_vec());
        assert_ne!(a.id(), b.id());
        assert_eq!(a.nonce(), 7);
        assert_eq!(a.with_nonce(8).id(), b.id());
    }
}
