//! Block identity and the block type.
//!
//! A [`Block`] is the unit of the DAG. Unlike a linear chain, a block may
//! reference **multiple** parents (the tips its miner observed), which is what
//! lets the ledger admit parallel blocks and, in turn, high block throughput.
//!
//! A [`BlockId`] is the BLAKE3 hash of the block's canonical encoding, so it is
//! a stable, collision-resistant identifier that every node derives identically.
//!
//! ## Payload pruning
//!
//! The block's `payload` field is `Option<Vec<u8>>` rather than a mandatory
//! `Vec<u8>`. This enables **DAG-level payload pruning**: once a block is
//! sufficiently finalized (beyond a configurable blue-score depth), its payload
//! can be evicted to bound memory and disk usage. The block's identity (id) and
//! consensus fields (`parents`, `work`, `timestamp_ms`, `nonce`) are always
//! retained — only the opaque payload bytes are optional.
//!
//! The reachability oracle ([`crate::reachability`]) answers ancestor queries
//! from the selected-parent tree and future-covering sets, which depend only on
//! the block's position in the DAG (its parents and selected parent). It never
//! inspects the payload, so `is_ancestor`, mergeset computation, and all other
//! reachability queries remain correct even when payloads are `None`. The block's
//! id is computed over the *original* payload at insertion time; when a pruned
//! block is re-encoded (e.g. for a snapshot), an empty payload is used, which
//! produces the same id because the id commits to the payload length and bytes
//! at insertion time — the pruning happens *after* insertion, so the stored id is
//! the authoritative one.

use core::fmt;

use crate::vrf::{VrfOutput, VrfProof, VrfPublicKey};

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
///
/// **VRF fields** (Stage 3): `vrf_public_key` identifies the block producer;
/// `vrf_proof` and `vrf_output` constitute a verifiable random function
/// evaluation over the block's parent tips, providing leader eligibility
/// (the output determines if this producer was eligible to produce a block
/// at this height) and a randomness beacon.
///
/// The payload is `Option<Vec<u8>>` to support **DAG-level payload pruning**:
/// once a block is sufficiently finalized (beyond `payload_pruning_depth` blue
/// score below the selected tip), its payload can be set to `None` to reclaim
/// memory. The block's id, computed at insertion time over the original payload,
/// is stored in the `id` field and never changes. All consensus logic works
/// correctly with `payload = None` because it uses the stored `id`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Block {
    /// The block's BLAKE3 id, computed at creation over the original payload.
    /// This is the authoritative identifier and never changes, even if the
    /// payload is later pruned.
    id: BlockId,
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
    /// VRF public key of the block producer (for VRF proof verification).
    /// `None` for blocks produced before VRF activation.
    vrf_public_key: Option<VrfPublicKey>,
    /// VRF proof: verifiable proof that `vrf_output` was correctly computed
    /// from `vrf_public_key` and the VRF input (derived from parent tips).
    /// `None` if VRF is not used for this block.
    vrf_proof: Option<VrfProof>,
    /// VRF output: 32 bytes of verifiable randomness derived from the proof.
    /// Used for leader eligibility (e.g., `output < threshold` means eligible)
    /// and as a randomness beacon.
    vrf_output: Option<VrfOutput>,
    /// Opaque application payload; not interpreted by consensus.
    /// `None` indicates the payload has been pruned.
    payload: Option<Vec<u8>>,
}

impl Block {
    /// Create a block referencing `parents` with the given `work`,
    /// `timestamp_ms`, `nonce`, and `payload`.
    ///
    /// Parents are de-duplicated and sorted so the id is independent of the
    /// order in which a miner happened to list them.
    ///
    /// VRF fields are initialized to `None` (legacy block without VRF).
    pub fn new(
        mut parents: Vec<BlockId>,
        work: u128,
        timestamp_ms: u64,
        nonce: u64,
        payload: Vec<u8>,
    ) -> Self {
        parents.sort_unstable();
        parents.dedup();
        let mut block = Self {
            id: BlockId([0; 32]),
            parents,
            work,
            timestamp_ms,
            nonce,
            vrf_public_key: None,
            vrf_proof: None,
            vrf_output: None,
            payload: Some(payload),
        };
        block.id = block.compute_id();
        block
    }

    /// Create a block with full VRF fields.
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_vrf(
        mut parents: Vec<BlockId>,
        work: u128,
        timestamp_ms: u64,
        nonce: u64,
        vrf_public_key: VrfPublicKey,
        vrf_proof: VrfProof,
        vrf_output: VrfOutput,
        payload: Vec<u8>,
    ) -> Self {
        parents.sort_unstable();
        parents.dedup();
        let mut block = Self {
            id: BlockId([0; 32]),
            parents,
            work,
            timestamp_ms,
            nonce,
            vrf_public_key: Some(vrf_public_key),
            vrf_proof: Some(vrf_proof),
            vrf_output: Some(vrf_output),
            payload: Some(payload),
        };
        block.id = block.compute_id();
        block
    }

    /// Create a block with an explicitly `None` payload (used when reconstructing
    /// a pruned block from a snapshot). The `id` must be provided explicitly
    /// since the payload is not available for hashing.
    pub fn new_pruned(
        mut parents: Vec<BlockId>,
        work: u128,
        timestamp_ms: u64,
        nonce: u64,
        id: BlockId,
    ) -> Self {
        parents.sort_unstable();
        parents.dedup();
        Self {
            id,
            parents,
            work,
            timestamp_ms,
            nonce,
            vrf_public_key: None,
            vrf_proof: None,
            vrf_output: None,
            payload: None,
        }
    }

    /// Create a pruned block with full VRF fields.
    #[allow(clippy::too_many_arguments)]
    pub fn new_pruned_with_vrf(
        mut parents: Vec<BlockId>,
        work: u128,
        timestamp_ms: u64,
        nonce: u64,
        vrf_public_key: Option<VrfPublicKey>,
        vrf_proof: Option<VrfProof>,
        vrf_output: Option<VrfOutput>,
        id: BlockId,
    ) -> Self {
        parents.sort_unstable();
        parents.dedup();
        Self {
            id,
            parents,
            work,
            timestamp_ms,
            nonce,
            vrf_public_key,
            vrf_proof,
            vrf_output,
            payload: None,
        }
    }

    /// The canonical genesis block: no parents, the given work, timestamp,
    /// nonce, and payload.
    pub fn genesis(work: u128, timestamp_ms: u64, nonce: u64, payload: Vec<u8>) -> Self {
        let mut block = Self {
            id: BlockId([0; 32]),
            parents: Vec::new(),
            work,
            timestamp_ms,
            nonce,
            vrf_public_key: None,
            vrf_proof: None,
            vrf_output: None,
            payload: Some(payload),
        };
        block.id = block.compute_id();
        block
    }

    /// The canonical genesis block with a pruned payload.
    pub fn genesis_pruned(work: u128, timestamp_ms: u64, nonce: u64, id: BlockId) -> Self {
        Self {
            id,
            parents: Vec::new(),
            work,
            timestamp_ms,
            nonce,
            vrf_public_key: None,
            vrf_proof: None,
            vrf_output: None,
            payload: None,
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

    /// The VRF public key of the block producer.
    pub fn vrf_public_key(&self) -> Option<&VrfPublicKey> {
        self.vrf_public_key.as_ref()
    }

    /// The VRF proof.
    pub fn vrf_proof(&self) -> Option<&VrfProof> {
        self.vrf_proof.as_ref()
    }

    /// The VRF output (32 bytes of verifiable randomness).
    pub fn vrf_output(&self) -> Option<&VrfOutput> {
        self.vrf_output.as_ref()
    }

    /// Whether this block has VRF fields (produced with VRF enabled).
    pub fn has_vrf(&self) -> bool {
        self.vrf_public_key.is_some()
    }

    /// The block's stored BLAKE3 id (computed at creation, never changes).
    pub fn id(&self) -> BlockId {
        self.id
    }

    /// Compute the BLAKE3 id from the block's current fields.
    /// Used at creation time and when nonce changes (mining).
    fn compute_id(&self) -> BlockId {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&(self.parents.len() as u64).to_le_bytes());
        for parent in &self.parents {
            hasher.update(parent.as_bytes());
        }
        hasher.update(&self.work.to_le_bytes());
        hasher.update(&self.timestamp_ms.to_le_bytes());
        hasher.update(&self.nonce.to_le_bytes());
        // VRF fields (included in id for blocks that have them)
        if let Some(pk) = &self.vrf_public_key {
            hasher.update(&[1u8]); // has_vrf flag
            hasher.update(pk.as_bytes());
        } else {
            hasher.update(&[0u8]);
        }
        if let Some(proof) = &self.vrf_proof {
            hasher.update(&proof.to_bytes());
        }
        if let Some(output) = &self.vrf_output {
            hasher.update(output.as_bytes());
        }
        let payload = self.payload.as_deref().unwrap_or(&[]);
        hasher.update(&(payload.len() as u64).to_le_bytes());
        hasher.update(payload);
        BlockId(*hasher.finalize().as_bytes())
    }

    /// Return a copy of this block with the nonce set to `nonce`. Used by the
    /// miner ([`crate::pow::mine`]) to search nonces without rebuilding the rest
    /// of the block. Recomputes the id since nonce is part of the hash.
    pub fn with_nonce(&self, nonce: u64) -> Self {
        let mut block = Self {
            nonce,
            ..self.clone()
        };
        block.id = block.compute_id();
        block
    }

    /// Set the payload to `None`, marking this block as pruned. Used by
    /// [`Dag::prune_old_payloads`] to reclaim memory. The block's id is NOT
    /// changed — it remains the original id computed at creation time.
    pub fn prune_payload(&mut self) {
        self.payload = None;
    }

    /// The opaque application payload. Returns an empty slice if the payload has
    /// been pruned.
    pub fn payload(&self) -> &[u8] {
        self.payload.as_deref().unwrap_or(&[])
    }

    /// Whether this block's payload has been pruned.
    pub fn is_pruned(&self) -> bool {
        self.payload.is_none()
    }

    /// Returns the length of the block's encoded form (as produced by
    /// `kovanica_dag::encode_block`), used for skipping during checkpoint decode.
    pub fn encoded_len(&self) -> usize {
        // id (32) + parents.len() (8) + each parent (32) + work (16) + timestamp (8) + nonce (8) +
        // vrf_has_flag (1) + [vrf_pk (32) + vrf_proof (96) + vrf_output (32)] if has_vrf + payload.len (8) + payload
        let mut len = 32 + 8 + self.parents.len() * 32 + 16 + 8 + 8 + 1;
        if self.vrf_public_key.is_some() {
            len += 32 + 96 + 32; // pk + proof + output
        }
        len += 8 + self.payload.as_deref().unwrap_or(&[]).len();
        len
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

    #[test]
    fn pruned_block_has_empty_payload() {
        let b = Block::new_pruned(vec![], 1, 0, 0, BlockId([0; 32]));
        assert!(b.is_pruned());
        assert_eq!(b.payload(), &[]);
        assert_eq!(b.payload().len(), 0);
    }

    #[test]
    fn pruned_block_id_uses_empty_payload() {
        let a = Block::new(vec![], 1, 0, 0, b"payload".to_vec());
        let b = Block::new_pruned(vec![], 1, 0, 0, BlockId([1; 32]));
        // Pruned block has explicit ID, different from full payload block
        assert_ne!(a.id(), b.id());
        // But two pruned blocks with same explicit ID have same id
        let c = Block::new_pruned(vec![], 1, 0, 0, BlockId([1; 32]));
        assert_eq!(b.id(), c.id());
    }

    #[test]
    fn prune_payload_clears_payload() {
        let mut b = Block::new(vec![], 1, 0, 0, b"payload".to_vec());
        assert!(!b.is_pruned());
        b.prune_payload();
        assert!(b.is_pruned());
        assert_eq!(b.payload(), &[]);
    }
}
