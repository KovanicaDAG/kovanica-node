//! SPV (Simplified Payment Verification) for light clients.
//!
//! This module provides the data structures and verification logic for light
//! clients to verify transaction inclusion and block validity without
//! downloading the full DAG. The approach follows Bitcoin SPV but adapted
//! for the GHOSTDAG linearized chain.
//!
//! ## Architecture
//!
//! - **Header chain**: Only the selected (heaviest) chain blocks are stored
//!   as headers. Each header commits to the full block payload via a Merkle
//!   root of the transaction list.
//! - **Merkle proofs**: A light client can verify a transaction was included
//!   in a specific block by checking the Merkle path from the tx to the
//!   block's Merkle root (stored in the header).
//! - **Chain proof**: A sequence of headers from a trusted checkpoint to the
//!   target block proves the block is on the selected chain.
//!
//! ## Trust model
//!
//! The light client trusts a **checkpoint header** (obtained out-of-band or
//! from a trusted source). From there, it verifies the header chain by
//! checking:
//! 1. Each header's `prev_hash` links correctly
//! 2. Each header's `work` meets the difficulty target (if PoW enforced)
//! 3. Each header's `merkle_root` is well-formed
//! 4. The total work is the heaviest known chain
//!
//! Transaction inclusion is then verified via Merkle proof against the
//! block's Merkle root.

use std::collections::HashMap;

use blake3::Hasher;
use kovanica_dag::{meets_target, Block, BlockId, Retarget, TimedWork};

/// A block header: the minimal data a light client needs to verify the
/// selected chain and transaction inclusion.
///
/// The full block payload (transactions) is NOT stored — only the Merkle
/// root of the transaction list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockHeader {
    /// The block's own id (BLAKE3 hash of full block).
    pub id: BlockId,
    /// Hash of the previous block in the selected chain.
    pub prev_hash: BlockId,
    /// Merkle root of the block's transaction list.
    pub merkle_root: [u8; 32],
    /// The block's work weight (for difficulty/PoW verification).
    pub work: u128,
    /// The block's timestamp (ms since UNIX epoch).
    pub timestamp_ms: u64,
    /// The block's nonce (for PoW verification).
    pub nonce: u64,
    /// Blue score of this block (selected chain height in GHOSTDAG terms).
    pub blue_score: u64,
    /// Total blue work of the selected chain up to this block.
    pub chain_blue_work: u128,
    /// Height in the selected chain (0 = genesis).
    pub height: u64,
}

impl BlockHeader {
    /// Create a header from a full block and its selected-chain context.
    pub fn from_block(
        block: &Block,
        prev_hash: BlockId,
        blue_score: u64,
        chain_blue_work: u128,
        height: u64,
        txs: &[crate::Transaction],
    ) -> Self {
        let merkle_root = merkle_root(txs);
        Self {
            id: block.id(),
            prev_hash,
            merkle_root,
            work: block.work(),
            timestamp_ms: block.timestamp_ms(),
            nonce: block.nonce(),
            blue_score,
            chain_blue_work,
            height,
        }
    }

    /// Verify this header's proof-of-work (if `require_pow`).
    pub fn verify_pow(&self, require_pow: bool) -> bool {
        if !require_pow {
            return true;
        }
        meets_target(&self.id, self.work)
    }

    /// Verify this header's work matches the difficulty target implied by
    /// the previous `window + 1` headers (if `retarget` is provided).
    pub fn verify_difficulty(&self, retarget: &Retarget, prev_headers: &[&BlockHeader]) -> bool {
        if prev_headers.len() < retarget.window + 1 {
            // Not enough history — require minimum work
            return self.work >= retarget.min_work;
        }
        let samples: Vec<TimedWork> = prev_headers
            .iter()
            .map(|h| TimedWork::new(h.timestamp_ms, h.work))
            .collect();
        let expected = retarget.next_work(&samples);
        self.work == expected
    }

    /// Verify the header chain from `trusted` (exclusive) to `self` (inclusive).
    /// Returns true if all links, work, and timestamps are valid.
    pub fn verify_chain(
        &self,
        trusted: &BlockHeader,
        headers: &[&BlockHeader],
        require_pow: bool,
        retarget: Option<&Retarget>,
    ) -> bool {
        // Check we're in the same chain (work should be increasing)
        if self.chain_blue_work <= trusted.chain_blue_work {
            return false;
        }
        if self.height <= trusted.height {
            return false;
        }

        // Check each header in the provided slice
        let mut prev = trusted;
        for h in headers {
            // Link check
            if h.prev_hash != prev.id {
                return false;
            }
            // Height monotonic
            if h.height != prev.height + 1 {
                return false;
            }
            // Timestamp monotonic
            if h.timestamp_ms < prev.timestamp_ms {
                return false;
            }
            // Work accumulating
            if h.chain_blue_work <= prev.chain_blue_work {
                return false;
            }
            // PoW
            if !h.verify_pow(require_pow) {
                return false;
            }
            // Difficulty
            if let Some(retarget) = retarget {
                // Collect window before this header
                let start = if headers.len() > retarget.window + 1 {
                    headers.len() - (retarget.window + 1)
                } else {
                    0
                };
                let window_headers: Vec<_> = headers[start..].to_vec();
                if !h.verify_difficulty(retarget, &window_headers) {
                    return false;
                }
            }
            prev = h;
        }
        // Final check: self matches last header
        if headers.last().map(|h| h.id) != Some(self.id) {
            return false;
        }
        true
    }
}

/// Compute the Merkle root of a list of transactions.
pub fn merkle_root(txs: &[crate::Transaction]) -> [u8; 32] {
    let leaves: Vec<[u8; 32]> = txs.iter().map(|tx| *tx.id().as_bytes()).collect();
    if leaves.is_empty() {
        return [0u8; 32];
    }
    merkle_root_from_leaves(&leaves)
}

/// Compute Merkle root from pre-hashed leaves.
fn merkle_root_from_leaves(leaves: &[[u8; 32]]) -> [u8; 32] {
    let mut current = leaves.to_vec();
    while current.len() > 1 {
        let mut next = Vec::with_capacity(current.len().div_ceil(2));
        for chunk in current.chunks(2) {
            if chunk.len() == 2 {
                let mut hasher = Hasher::new();
                hasher.update(&chunk[0]);
                hasher.update(&chunk[1]);
                next.push(*hasher.finalize().as_bytes());
            } else {
                // Odd count: duplicate last
                let mut hasher = Hasher::new();
                hasher.update(&chunk[0]);
                hasher.update(&chunk[0]);
                next.push(*hasher.finalize().as_bytes());
            }
        }
        current = next;
    }
    current[0]
}

/// A Merkle proof that a transaction is included in a block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MerkleProof {
    /// The transaction id being proved.
    pub tx_id: [u8; 32],
    /// The block's Merkle root.
    pub merkle_root: [u8; 32],
    /// The sibling hashes along the path from leaf to root.
    /// Ordered from leaf towards root.
    pub path: Vec<[u8; 32]>,
    /// The index of the transaction in the block's tx list.
    pub index: usize,
    /// Total number of transactions in the block.
    pub tx_count: usize,
}

impl MerkleProof {
    /// Verify this Merkle proof.
    pub fn verify(&self) -> bool {
        let mut current = self.tx_id;
        let mut idx = self.index;
        for sibling in &self.path {
            let mut hasher = Hasher::new();
            if idx % 2 == 0 {
                hasher.update(&current);
                hasher.update(sibling);
            } else {
                hasher.update(sibling);
                hasher.update(&current);
            }
            current = *hasher.finalize().as_bytes();
            idx /= 2;
        }
        current == self.merkle_root
    }
}

/// Generate a Merkle proof for a transaction at `index` in `txs`.
pub fn generate_merkle_proof(txs: &[crate::Transaction], index: usize) -> Option<MerkleProof> {
    if index >= txs.len() {
        return None;
    }
    let leaves: Vec<[u8; 32]> = txs.iter().map(|tx| *tx.id().as_bytes()).collect();
    let merkle_root = merkle_root_from_leaves(&leaves);
    let mut path = Vec::new();
    let mut idx = index;
    let mut current_level = leaves;
    while current_level.len() > 1 {
        let mut next_level = Vec::with_capacity(current_level.len().div_ceil(2));
        for chunk in current_level.chunks(2) {
            if chunk.len() == 2 {
                let sibling = if idx % 2 == 0 { chunk[1] } else { chunk[0] };
                if (idx / 2) == next_level.len() {
                    // This is our pair
                    path.push(sibling);
                }
                let mut hasher = Hasher::new();
                hasher.update(&chunk[0]);
                hasher.update(&chunk[1]);
                next_level.push(*hasher.finalize().as_bytes());
            } else {
                // Odd count: duplicate last
                if idx == current_level.len() - 1 && idx / 2 == next_level.len() {
                    path.push(chunk[0]);
                }
                let mut hasher = Hasher::new();
                hasher.update(&chunk[0]);
                hasher.update(&chunk[0]);
                next_level.push(*hasher.finalize().as_bytes());
            }
        }
        current_level = next_level;
        idx /= 2;
    }
    Some(MerkleProof {
        tx_id: *txs[index].id().as_bytes(),
        merkle_root,
        path,
        index,
        tx_count: txs.len(),
    })
}

/// A compact filter for a block: Golomb-Rice coded set of output addresses.
/// Allows light clients to quickly check if a block might contain transactions
/// for their addresses without downloading full block payload.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BlockFilter {
    /// Golomb-Rice parameter (k). Higher = denser, larger filter.
    pub k: u8,
    /// Number of elements.
    pub n: u64,
    /// Filter data bytes.
    pub data: Vec<u8>,
}

impl BlockFilter {
    /// Create a filter from a block's output addresses.
    pub fn from_addresses(addresses: &[[u8; 32]], k: u8) -> Self {
        let n = addresses.len().max(1) as u64;
        let m = 1u64 << k;
        let max_val = n * m;
        let mut hashes: Vec<u64> = addresses
            .iter()
            .map(|addr| {
                let mut hasher = Hasher::new();
                hasher.update(addr);
                let h = hasher.finalize();
                let raw = u64::from_be_bytes(h.as_bytes()[..8].try_into().unwrap());
                // Map to [0, N * M] to keep diffs small for Golomb-Rice
                ((raw as u128 * max_val as u128) >> 64) as u64
            })
            .collect();
        hashes.sort_unstable();

        let mut data = Vec::new();
        let mut bit_len = 0;
        let mut prev = 0u64;
        for h in hashes {
            let diff = h.wrapping_sub(prev);
            prev = h;
            golomb_rice_encode(&mut data, &mut bit_len, diff, k);
        }
        Self { k, n, data }
    }

    /// Check if an address might be in this filter (false positives possible).
    pub fn contains(&self, address: &[u8; 32]) -> bool {
        let mut hasher = Hasher::new();
        hasher.update(address);
        let h = hasher.finalize();
        let raw = u64::from_be_bytes(h.as_bytes()[..8].try_into().unwrap());
        let max_val = self.n * (1u64 << self.k);
        let target = ((raw as u128 * max_val as u128) >> 64) as u64;

        // Decode and check
        let mut bits = self
            .data
            .iter()
            .flat_map(|b| (0..8).map(move |i| (b >> i) & 1));
        let mut prev = 0u64;
        while let Some(val) = golomb_rice_decode(&mut bits, self.k) {
            prev = prev.wrapping_add(val);
            if prev == target {
                return true;
            }
            if prev > target {
                return false; // Past it in sorted order
            }
        }
        false
    }
}

/// Golomb-Rice encode a value into a bit stream.
fn golomb_rice_encode(data: &mut Vec<u8>, bit_len: &mut usize, val: u64, k: u8) {
    let q = val >> k;
    let r = val & ((1u64 << k) - 1);
    // Unary for quotient
    for _ in 0..q {
        push_bit(data, bit_len, 1);
    }
    push_bit(data, bit_len, 0); // Terminator
                                // Binary for remainder
    for i in (0..k).rev() {
        push_bit(data, bit_len, (r >> i) & 1);
    }
}

fn push_bit(data: &mut Vec<u8>, bit_len: &mut usize, bit: u64) {
    let byte_idx = *bit_len / 8;
    let bit_idx = *bit_len % 8;
    if byte_idx >= data.len() {
        data.push(0);
    }
    if bit == 1 {
        data[byte_idx] |= 1 << bit_idx;
    }
    *bit_len += 1;
}

/// Decode next Golomb-Rice value from bit iterator.
fn golomb_rice_decode<I: Iterator<Item = u8>>(bits: &mut I, k: u8) -> Option<u64> {
    // Read unary quotient
    let mut q = 0u64;
    loop {
        match bits.next() {
            Some(1) => q += 1,
            Some(0) => break,
            _ => return None,
        }
    }
    // Read binary remainder
    let mut r = 0u64;
    for i in (0..k).rev() {
        {
            let b = bits.next()?;
            r |= (b as u64) << i
        }
    }
    Some((q << k) | r)
}

/// SPV client state: the header chain it has verified.
#[derive(Clone, Debug, Default)]
pub struct SpvClient {
    /// Verified headers, indexed by height.
    headers: HashMap<u64, BlockHeader>,
    /// The highest verified header (tip of the SPV chain).
    tip: Option<BlockHeader>,
    /// The trusted checkpoint header (genesis or later).
    /// Retained for introspection; verification uses `headers`.
    #[allow(dead_code)]
    checkpoint: Option<BlockHeader>,
    /// Whether PoW verification is required.
    require_pow: bool,
    /// Difficulty retarget policy (if any).
    retarget: Option<Retarget>,
}

impl SpvClient {
    /// Create a new SPV client with a trusted checkpoint.
    pub fn new(checkpoint: BlockHeader, require_pow: bool, retarget: Option<Retarget>) -> Self {
        let mut headers = HashMap::new();
        headers.insert(checkpoint.height, checkpoint.clone());
        let mut s = Self {
            checkpoint: Some(checkpoint.clone()),
            headers,
            tip: Some(checkpoint),
            require_pow,
            ..Self::default()
        };
        s.retarget = retarget;
        s
    }

    /// Add a new header to the SPV chain.
    /// Returns true if accepted and becomes new tip.
    pub fn add_header(&mut self, header: BlockHeader) -> Result<bool, SpvError> {
        // Must extend the current tip
        let Some(tip) = &self.tip else {
            return Err(SpvError::NoCheckpoint);
        };
        if header.height != tip.height + 1 {
            return Err(SpvError::HeightMismatch);
        }
        if header.prev_hash != tip.id {
            return Err(SpvError::PrevHashMismatch);
        }
        if header.timestamp_ms < tip.timestamp_ms {
            return Err(SpvError::TimestampNotMonotonic);
        }
        if header.chain_blue_work <= tip.chain_blue_work {
            return Err(SpvError::WorkNotIncreasing);
        }
        if !header.verify_pow(self.require_pow) {
            return Err(SpvError::InsufficientPoW);
        }
        if let Some(retarget) = self.retarget {
            // Need window headers for difficulty check
            let mut window = Vec::new();
            let mut cur_height = tip.height;
            while window.len() < retarget.window + 1 {
                if let Some(h) = self.headers.get(&cur_height) {
                    window.push(h);
                }
                if cur_height == 0 {
                    break;
                }
                cur_height -= 1;
            }
            window.reverse();
            if !header.verify_difficulty(&retarget, &window) {
                return Err(SpvError::DifficultyMismatch);
            }
        }

        // Accept
        self.headers.insert(header.height, header.clone());
        self.tip = Some(header);
        Ok(true)
    }

    /// Get the current tip header.
    pub fn tip(&self) -> Option<&BlockHeader> {
        self.tip.as_ref()
    }

    /// Get a header by height.
    pub fn header(&self, height: u64) -> Option<&BlockHeader> {
        self.headers.get(&height)
    }

    /// Verify a Merkle proof against a header in our chain.
    pub fn verify_tx_inclusion(&self, proof: &MerkleProof, height: u64) -> bool {
        if let Some(header) = self.headers.get(&height) {
            proof.merkle_root == header.merkle_root && proof.verify()
        } else {
            false
        }
    }

    /// Verify a transaction is in the chain: check proof and that the block
    /// is in the verified header chain.
    pub fn verify_transaction(&self, proof: &MerkleProof, height: u64) -> bool {
        self.verify_tx_inclusion(proof, height)
    }

    /// Get the chain work up to the tip.
    pub fn chain_work(&self) -> u128 {
        self.tip.as_ref().map(|t| t.chain_blue_work).unwrap_or(0)
    }
}

/// Errors from SPV operations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SpvError {
    NoCheckpoint,
    HeightMismatch,
    PrevHashMismatch,
    TimestampNotMonotonic,
    WorkNotIncreasing,
    InsufficientPoW,
    DifficultyMismatch,
}

impl std::fmt::Display for SpvError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SpvError::NoCheckpoint => f.write_str("no checkpoint set"),
            SpvError::HeightMismatch => f.write_str("height mismatch"),
            SpvError::PrevHashMismatch => f.write_str("prev_hash mismatch"),
            SpvError::TimestampNotMonotonic => f.write_str("timestamp not monotonic"),
            SpvError::WorkNotIncreasing => f.write_str("chain work not increasing"),
            SpvError::InsufficientPoW => f.write_str("insufficient proof-of-work"),
            SpvError::DifficultyMismatch => f.write_str("difficulty mismatch"),
        }
    }
}

impl std::error::Error for SpvError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{encode_block_payload, Address, KeyPair, OutPoint, Transaction, TxId, TxOutput};
    use kovanica_dag::{pow::mine, Block, Retarget};

    fn tx(addr: Address, value: u64, tag: &[u8]) -> Transaction {
        let kp = KeyPair::from_u64(1);
        let op = OutPoint::new(TxId::from_bytes([1u8; 32]), 0);
        Transaction::signed(&[(op, &kp)], vec![TxOutput::new(value, addr)], tag.to_vec())
    }

    fn header_chain(n: usize) -> (Vec<BlockHeader>, Vec<Vec<Transaction>>) {
        let mut headers = Vec::new();
        let mut all_txs = Vec::new();
        let mut prev_hash = BlockId::from_bytes([0u8; 32]);
        let mut blue_work = 0u128;
        let mut blue_score = 0u64;

        for i in 0..n {
            let kp = KeyPair::from_u64(i as u64 + 1);
            let tx = if i == 0 {
                Transaction::coinbase(vec![TxOutput::new(1000, kp.address())], b"genesis".to_vec())
            } else {
                tx(kp.address(), 100, &format!("b{}", i).into_bytes())
            };
            let txs = vec![tx];
            let block = if i == 0 {
                Block::genesis(1, 0, 0, encode_block_payload(&txs))
            } else {
                let mut b = Block::new(
                    vec![prev_hash],
                    1,
                    (i as u64) * 1000,
                    0,
                    encode_block_payload(&txs),
                );
                b = mine(&b); // Mine to meet work
                b
            };
            blue_work += block.work();
            blue_score += 1;
            let header =
                BlockHeader::from_block(&block, prev_hash, blue_score, blue_work, i as u64, &txs);
            prev_hash = block.id();
            headers.push(header);
            all_txs.push(txs);
        }
        (headers, all_txs)
    }

    #[test]
    fn header_chain_verification() {
        let (headers, _) = header_chain(5);
        let retarget = Retarget {
            window: 2,
            target_interval_ms: 1000,
            max_factor: 4,
            min_work: 1,
        };

        let mut client = SpvClient::new(headers[0].clone(), true, Some(retarget));

        for h in &headers[1..] {
            client.add_header(h.clone()).unwrap();
        }
        assert_eq!(client.tip().unwrap().height, 4);
    }

    #[test]
    fn merkle_proof_verification() {
        let kp = KeyPair::from_u64(1);
        let tx1 = tx(kp.address(), 100, b"tx1");
        let tx2 = tx(kp.address(), 200, b"tx2");
        let txs = vec![tx1.clone(), tx2.clone()];

        let proof = generate_merkle_proof(&txs, 0).unwrap();
        assert!(proof.verify());
        assert_eq!(proof.tx_id, *tx1.id().as_bytes());

        let proof2 = generate_merkle_proof(&txs, 1).unwrap();
        assert!(proof2.verify());
        assert_eq!(proof2.tx_id, *tx2.id().as_bytes());
    }

    #[test]
    fn spv_verify_tx_inclusion() {
        let (headers, all_txs) = header_chain(3);
        let retarget = Retarget {
            window: 2,
            target_interval_ms: 1000,
            max_factor: 4,
            min_work: 1,
        };

        let mut client = SpvClient::new(headers[0].clone(), true, Some(retarget));

        for h in &headers[1..] {
            client.add_header(h.clone()).unwrap();
        }

        // Verify tx in block 1
        let proof = generate_merkle_proof(&all_txs[1], 0).unwrap();
        // We need to check against the header at height 1
        assert!(client.verify_tx_inclusion(&proof, 1));
    }

    #[test]
    fn block_filter_basic() {
        let kp = KeyPair::from_u64(1);
        let addr = kp.address();
        let filter = BlockFilter::from_addresses(&[*addr.as_bytes()], 8);
        assert!(filter.contains(addr.as_bytes()));
    }
}
