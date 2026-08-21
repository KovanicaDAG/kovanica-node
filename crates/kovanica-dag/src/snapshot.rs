//! Persistence: encode a [`Dag`] to bytes and rebuild it.
//!
//! The snapshot is a **replay log**, not a dump of derived state. It stores only
//! the GHOSTDAG parameter `k` and the blocks themselves, in a topological order
//! (genesis first, every block after its parents). Loading replays the blocks
//! through [`Dag::insert`], so all consensus data — the reachability oracle,
//! colouring, blue scores, tips — is recomputed deterministically and the rebuilt DAG is
//! identical to the original. Nothing derived is trusted from disk, which keeps
//! the format small and immune to consensus-logic changes: a snapshot written by
//! one version reloads correctly under any version with the same insert rules.
//!
//! ```
//! use kovanica_dag::{Block, Dag};
//!
//! let genesis = Block::genesis(1, 0, 0, b"genesis".to_vec());
//! let mut dag = Dag::new(3, genesis);
//! let g = dag.genesis();
//! let a = dag.insert(Block::new(vec![g], 1, 1, 0, b"a".to_vec())).unwrap();
//! dag.insert(Block::new(vec![a], 1, 2, 0, b"b".to_vec())).unwrap();
//!
//! let bytes = dag.write_snapshot();
//! let restored = Dag::read_snapshot(&bytes).unwrap();
//! assert_eq!(restored.linearize(), dag.linearize());
//! assert_eq!(restored.tips(), dag.tips());
//! ```

use core::fmt;

use crate::block::{Block, BlockId};
use crate::dag::{Dag, DagError, KParam};

/// Magic prefix identifying a Kovanica DAG snapshot (`"KVDG"`).
const MAGIC: [u8; 4] = *b"KVDG";
/// Snapshot format version. Bump on any incompatible framing change.
/// v2 added the per-block `timestamp_ms` field; v3 added the `nonce` field.
const VERSION: u16 = 3;

/// Why a snapshot could not be decoded or replayed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SnapshotError {
    /// The bytes did not start with the expected magic prefix.
    BadMagic,
    /// The snapshot version is not supported by this build.
    UnsupportedVersion(u16),
    /// The input ended before a fully-formed value could be read.
    UnexpectedEof,
    /// Bytes remained after the declared blocks were decoded.
    TrailingBytes,
    /// Replaying a block through `insert` failed (a corrupt or inconsistent
    /// snapshot — e.g. a child before its parent, or a duplicate).
    Rebuild(DagError),
}

impl fmt::Display for SnapshotError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SnapshotError::BadMagic => f.write_str("not a kovanica DAG snapshot"),
            SnapshotError::UnsupportedVersion(v) => write!(f, "unsupported snapshot version {v}"),
            SnapshotError::UnexpectedEof => f.write_str("unexpected end of snapshot"),
            SnapshotError::TrailingBytes => f.write_str("trailing bytes after snapshot"),
            SnapshotError::Rebuild(e) => write!(f, "replaying snapshot failed: {e}"),
        }
    }
}

impl std::error::Error for SnapshotError {}

/// A decoded snapshot: the DAG parameter and its blocks in topological order
/// (`blocks[0]` is genesis). Exposed so higher layers (e.g. a ledger) can
/// rebuild their own state by replaying the same blocks.
#[derive(Clone, Debug)]
pub struct DagSnapshot {
    /// The GHOSTDAG `k` parameter.
    pub k: KParam,
    /// Blocks in a valid insert order: genesis first, each after its parents.
    pub blocks: Vec<Block>,
}

impl Dag {
    /// Serialise the DAG to a self-contained snapshot (see the module docs).
    pub fn write_snapshot(&self) -> Vec<u8> {
        let order = self.linearize(); // topological: genesis first, parents before children
        let mut buf = Vec::new();
        buf.extend_from_slice(&MAGIC);
        buf.extend_from_slice(&VERSION.to_le_bytes());
        buf.extend_from_slice(&self.k().to_le_bytes());
        buf.extend_from_slice(&(order.len() as u64).to_le_bytes());
        for id in &order {
            encode_block(self.block(id).expect("linearized id is present"), &mut buf);
        }
        buf
    }

    /// Rebuild a DAG from a snapshot by replaying its blocks. No validator is
    /// installed on the restored DAG; use [`Dag::set_validator`] afterwards if
    /// insert-time validation is wanted for subsequent blocks.
    pub fn read_snapshot(bytes: &[u8]) -> Result<Dag, SnapshotError> {
        let snapshot = decode_snapshot(bytes)?;
        let mut blocks = snapshot.blocks.into_iter();
        let genesis = blocks.next().ok_or(SnapshotError::UnexpectedEof)?;
        let mut dag = Dag::new(snapshot.k, genesis);
        for block in blocks {
            dag.insert(block).map_err(SnapshotError::Rebuild)?;
        }
        Ok(dag)
    }
}

/// Decode a snapshot's framing into `k` and its ordered blocks, without
/// rebuilding a [`Dag`]. `blocks[0]` is genesis.
pub fn decode_snapshot(bytes: &[u8]) -> Result<DagSnapshot, SnapshotError> {
    let mut reader = Reader::new(bytes);
    if reader.read_array::<4>()? != MAGIC {
        return Err(SnapshotError::BadMagic);
    }
    let version = reader.read_u16()?;
    if version != VERSION {
        return Err(SnapshotError::UnsupportedVersion(version));
    }
    let k = reader.read_u16()?;
    // Each block is at least 8 (parents len) + 16 (work) + 8 (timestamp) +
    // 8 (nonce) + 8 (payload len) = 48.
    let count = reader.read_count(48)?;
    let mut blocks = Vec::with_capacity(count);
    for _ in 0..count {
        blocks.push(reader.read_block()?);
    }
    if reader.remaining() != 0 {
        return Err(SnapshotError::TrailingBytes);
    }
    Ok(DagSnapshot { k, blocks })
}

/// Encode a block's reconstruction data: parents, work, timestamp, nonce,
/// payload (length-prefixed, little-endian). Not the id encoding — this is what
/// rebuilds the `Block`. Used by the whole-DAG snapshot and the incremental
/// append-only log.
pub fn encode_block(block: &Block, buf: &mut Vec<u8>) {
    buf.extend_from_slice(&(block.parents().len() as u64).to_le_bytes());
    for parent in block.parents() {
        buf.extend_from_slice(parent.as_bytes());
    }
    buf.extend_from_slice(&block.work().to_le_bytes());
    buf.extend_from_slice(&block.timestamp_ms().to_le_bytes());
    buf.extend_from_slice(&block.nonce().to_le_bytes());
    buf.extend_from_slice(&(block.payload().len() as u64).to_le_bytes());
    buf.extend_from_slice(block.payload());
}

/// Decode one block from the stored (snapshot / log) encoding.
pub fn decode_block(bytes: &[u8]) -> Result<Block, SnapshotError> {
    let mut reader = Reader::new(bytes);
    let block = reader.read_block()?;
    if reader.remaining() != 0 {
        return Err(SnapshotError::TrailingBytes);
    }
    Ok(block)
}

/// A minimal, bounds-checked cursor over snapshot bytes.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], SnapshotError> {
        if self.remaining() < N {
            return Err(SnapshotError::UnexpectedEof);
        }
        let mut out = [0u8; N];
        out.copy_from_slice(&self.buf[self.pos..self.pos + N]);
        self.pos += N;
        Ok(out)
    }

    fn read_u16(&mut self) -> Result<u16, SnapshotError> {
        Ok(u16::from_le_bytes(self.read_array::<2>()?))
    }

    fn read_u64(&mut self) -> Result<u64, SnapshotError> {
        Ok(u64::from_le_bytes(self.read_array::<8>()?))
    }

    fn read_u128(&mut self) -> Result<u128, SnapshotError> {
        Ok(u128::from_le_bytes(self.read_array::<16>()?))
    }

    /// Read a length prefix, rejecting counts too large to fit even at
    /// `min_element_bytes` each.
    fn read_count(&mut self, min_element_bytes: usize) -> Result<usize, SnapshotError> {
        let n = self.read_u64()? as usize;
        if min_element_bytes > 0 && n > self.remaining() / min_element_bytes {
            return Err(SnapshotError::UnexpectedEof);
        }
        Ok(n)
    }

    fn read_bytes(&mut self, len: usize) -> Result<Vec<u8>, SnapshotError> {
        if self.remaining() < len {
            return Err(SnapshotError::UnexpectedEof);
        }
        let out = self.buf[self.pos..self.pos + len].to_vec();
        self.pos += len;
        Ok(out)
    }

    fn read_block(&mut self) -> Result<Block, SnapshotError> {
        let n_parents = self.read_count(32)?; // each parent id is 32 bytes
        let mut parents = Vec::with_capacity(n_parents);
        for _ in 0..n_parents {
            parents.push(BlockId::from_bytes(self.read_array::<32>()?));
        }
        let work = self.read_u128()?;
        let timestamp_ms = self.read_u64()?;
        let nonce = self.read_u64()?;
        let payload_len = self.read_count(1)?;
        let payload = self.read_bytes(payload_len)?;
        // Block::new de-duplicates and sorts parents; the stored ids already are,
        // so the reconstructed block's id matches the original.
        Ok(Block::new(parents, work, timestamp_ms, nonce, payload))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build() -> Dag {
        let genesis = Block::genesis(1, 0, 0, b"kovanica-genesis".to_vec());
        let mut dag = Dag::new(2, genesis);
        let g = dag.genesis();
        let a = dag
            .insert(Block::new(vec![g], 1, 1, 0, b"a".to_vec()))
            .unwrap();
        let b = dag
            .insert(Block::new(vec![g], 1, 1, 0, b"b".to_vec()))
            .unwrap();
        let _m = dag
            .insert(Block::new(vec![a, b], 3, 2, 0, b"m".to_vec()))
            .unwrap();
        dag
    }

    #[test]
    fn roundtrip_preserves_the_dag() {
        let dag = build();
        let restored = Dag::read_snapshot(&dag.write_snapshot()).unwrap();

        assert_eq!(restored.k(), dag.k());
        assert_eq!(restored.genesis(), dag.genesis());
        assert_eq!(restored.len(), dag.len());
        assert_eq!(restored.tips(), dag.tips());
        assert_eq!(restored.linearize(), dag.linearize());
        for id in dag.linearize() {
            let a = dag.ghostdag(&id).unwrap();
            let b = restored.ghostdag(&id).unwrap();
            assert_eq!(a.blue_score, b.blue_score);
            assert_eq!(a.blue_work, b.blue_work);
            assert_eq!(a.selected_parent, b.selected_parent);
        }
    }

    #[test]
    fn genesis_only_roundtrips() {
        let dag = Dag::new(1, Block::genesis(5, 0, 0, b"only".to_vec()));
        let restored = Dag::read_snapshot(&dag.write_snapshot()).unwrap();
        assert_eq!(restored.linearize(), dag.linearize());
        assert_eq!(restored.k(), 1);
    }

    #[test]
    fn bad_magic_is_rejected() {
        // `Dag` has no `Debug`, so match rather than `unwrap_err`.
        assert!(matches!(
            Dag::read_snapshot(b"nope"),
            Err(SnapshotError::BadMagic)
        ));
    }

    #[test]
    fn truncated_snapshot_is_rejected() {
        let bytes = build().write_snapshot();
        assert!(matches!(
            Dag::read_snapshot(&bytes[..bytes.len() - 1]),
            Err(SnapshotError::UnexpectedEof)
        ));
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        let mut bytes = build().write_snapshot();
        bytes.push(0);
        assert!(matches!(
            Dag::read_snapshot(&bytes),
            Err(SnapshotError::TrailingBytes)
        ));
    }
}
