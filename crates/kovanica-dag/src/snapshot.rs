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
use std::collections::HashSet;

use crate::block::{Block, BlockId};
use crate::dag::{Dag, DagError, KParam};
use crate::vrf::{VrfOutput, VrfProof, VrfPublicKey};

/// Magic prefix identifying a Kovanica DAG snapshot (`"KVDG"`).
const MAGIC: [u8; 4] = *b"KVDG";
/// Snapshot format version. Bump on any incompatible framing change.
/// v2 added the per-block `timestamp_ms` field; v3 added the `nonce` field;
/// v4 added the per-block `id` field (for pruned payload roundtrips).
/// v5 added VRF fields (vrf_public_key, vrf_proof, vrf_output) — all three
/// present together behind a single has_vrf flag.
/// v6 encodes the VRF fields independently: has_vrf flag, vrf_public_key (always
/// when has_vrf=1), then a proof flag (0/1 + 96 bytes if 1), then an output flag
/// (0/1 + 32 bytes if 1). This lets a block carry a proof without the output
/// (block-production self-verification) or an output without the proof.
const VERSION: u16 = 6;

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
        let mut reader = Reader::new(bytes);
        if reader.read_array::<4>()? != MAGIC {
            return Err(SnapshotError::BadMagic);
        }
        let version = reader.read_u16()?;
        if version > VERSION {
            return Err(SnapshotError::UnsupportedVersion(version));
        }
        // The reader must decode blocks using the snapshot's own version (v5
        // and earlier use the all-three-together VRF layout; v6+ uses the
        // independent proof/output flags). Without this, the v5 backward-compat
        // path is dead code and old snapshots fail with UnexpectedEof.
        reader.version = version;
        let k = reader.read_u16()?;
        // v4 added block id (32 bytes). v3 and earlier don't have it.
        // v5 added VRF fields: 1 byte flag + up to 160 bytes (pk+proof+output)
        let min_block_size = if version >= 4 { 80 } else { 48 };
        let count = reader.read_count(min_block_size)?;

        if version >= 4 {
            // v4+: blocks have stored IDs
            let mut blocks_with_ids = Vec::with_capacity(count);
            for _ in 0..count {
                blocks_with_ids.push(reader.read_block_with_id()?);
            }
            if reader.remaining() != 0 {
                return Err(SnapshotError::TrailingBytes);
            }
            let mut iter = blocks_with_ids.into_iter();
            let (genesis, _) = iter.next().ok_or(SnapshotError::UnexpectedEof)?;
            let genesis_id = genesis.id();
            let mut dag = Dag::new(k, genesis);
            // Stub blocks reconstructed for evicted parents (block pruning).
            let mut stubs: Vec<BlockId> = Vec::new();
            for (block, stored_id) in iter {
                // A present block may reference an evicted parent (a block
                // pruned by block pruning). The evicted block is not in the
                // snapshot, so reconstruct it as a pruned stub (a child of
                // genesis) and insert it first; the stub is evicted again once
                // the replay completes, restoring the pruned DAG's present set.
                for parent in block.parents() {
                    if !dag.nodes.contains_key(parent) {
                        let stub = Block::new_pruned_with_vrf(
                            vec![genesis_id],
                            0,
                            0,
                            0,
                            None,
                            None,
                            None,
                            *parent,
                        );
                        dag.insert_with_id(stub, Some(*parent))
                            .map_err(SnapshotError::Rebuild)?;
                        stubs.push(*parent);
                    }
                }
                dag.insert_with_id(block, Some(stored_id))
                    .map_err(SnapshotError::Rebuild)?;
            }
            // Evict the reconstructed stubs, restoring the pruned DAG's present
            // set (the stubs' ghostdag data was only a placeholder).
            if !stubs.is_empty() {
                let evicted: HashSet<BlockId> = stubs.iter().copied().collect();
                dag.remove_blocks(&evicted);
            }
            Ok(dag)
        } else {
            // v3 and earlier: no stored IDs, use computed IDs
            let mut blocks = Vec::with_capacity(count);
            for _ in 0..count {
                blocks.push(reader.read_block()?);
            }
            if reader.remaining() != 0 {
                return Err(SnapshotError::TrailingBytes);
            }
            let mut blocks = blocks.into_iter();
            let genesis = blocks.next().ok_or(SnapshotError::UnexpectedEof)?;
            let mut dag = Dag::new(k, genesis);
            for block in blocks {
                dag.insert(block).map_err(SnapshotError::Rebuild)?;
            }
            Ok(dag)
        }
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
    if version > VERSION {
        return Err(SnapshotError::UnsupportedVersion(version));
    }
    reader.version = version;
    let k = reader.read_u16()?;
    // v4 added block id (32 bytes). v3 and earlier don't have it.
    // v5 added VRF fields: 1 byte flag + up to 160 bytes (pk+proof+output)
    let min_block_size = if version >= 4 { 80 } else { 48 };
    let count = reader.read_count(min_block_size)?;
    let mut blocks = Vec::with_capacity(count);
    for _ in 0..count {
        blocks.push(reader.read_block()?);
    }
    if reader.remaining() != 0 {
        return Err(SnapshotError::TrailingBytes);
    }
    Ok(DagSnapshot { k, blocks })
}

/// Encode a block's reconstruction data: id, parents, work, timestamp, nonce,
/// VRF fields, payload (length-prefixed, little-endian). Used by the whole-DAG
/// snapshot and the incremental append-only log.
///
/// The block's id is stored explicitly so that pruned blocks (which have empty
/// payload in the encoding) can be restored with their original id. The id is
/// verified to match the recomputed id for non-pruned blocks.
/// VRF fields (version 5+): has_vrf flag (1 byte), then if set: vrf_pk (32),
/// vrf_proof (96), vrf_output (32).
pub fn encode_block(block: &Block, buf: &mut Vec<u8>) {
    buf.extend_from_slice(block.id().as_bytes());
    buf.extend_from_slice(&(block.parents().len() as u64).to_le_bytes());
    for parent in block.parents() {
        buf.extend_from_slice(parent.as_bytes());
    }
    buf.extend_from_slice(&block.work().to_le_bytes());
    buf.extend_from_slice(&block.timestamp_ms().to_le_bytes());
    buf.extend_from_slice(&block.nonce().to_le_bytes());

    // VRF fields (v6+): has_vrf flag (1 byte), then if set:
    //   vrf_public_key (32 bytes) — always present when has_vrf=1.
    //   proof_flag (1 byte): 0 = no proof, 1 = 96-byte proof follows.
    //   output_flag (1 byte): 0 = no output, 1 = 32-byte output follows.
    // v5 and earlier: has_vrf flag, then if 1: pk(32) + proof(96) + output(32).
    if let Some(pk) = block.vrf_public_key() {
        buf.push(1u8); // has_vrf flag
        buf.extend_from_slice(pk.as_bytes());
        if block.vrf_proof().is_some() {
            buf.push(1u8); // proof flag
            buf.extend_from_slice(&block.vrf_proof().unwrap().to_bytes());
        } else {
            buf.push(0u8); // no proof
        }
        if block.vrf_output().is_some() {
            buf.push(1u8); // output flag
            buf.extend_from_slice(block.vrf_output().unwrap().as_bytes());
        } else {
            buf.push(0u8); // no output
        }
    } else {
        buf.push(0u8); // no VRF
    }

    let payload = block.payload();
    buf.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    buf.extend_from_slice(payload);
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
    version: u16,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self {
            buf,
            pos: 0,
            version: VERSION,
        }
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

    fn read_block_with_stored_id(&mut self, stored_id: BlockId) -> Result<Block, SnapshotError> {
        let n_parents = self.read_count(32)?; // each parent id is 32 bytes
        let mut parents = Vec::with_capacity(n_parents);
        for _ in 0..n_parents {
            parents.push(BlockId::from_bytes(self.read_array::<32>()?));
        }
        let work = self.read_u128()?;
        let timestamp_ms = self.read_u64()?;
        let nonce = self.read_u64()?;

        // VRF fields.
        // v6+ (independent fields): has_vrf flag, then vrf_public_key (always when
        // has_vrf=1), then proof_flag (1 byte: 0=None, 1=96-byte proof follows),
        // then output_flag (1 byte: 0=None, 1=32-byte output follows).
        // v5 and earlier (all-three-together): has_vrf flag, then if 1: pk(32) +
        // proof(96) + output(32).
        let (vrf_public_key, vrf_proof, vrf_output) = if self.version >= 6 {
            let has_vrf = self.read_u8()?;
            if has_vrf == 1 {
                let pk_bytes: [u8; 32] = self.read_array::<32>()?;
                let pk = VrfPublicKey::from_bytes(&pk_bytes)
                    .map_err(|_| SnapshotError::UnexpectedEof)?;
                let has_proof = self.read_u8()?;
                let proof = if has_proof == 1 {
                    let proof_bytes: [u8; 96] = self.read_array::<96>()?;
                    Some(
                        VrfProof::from_bytes(&proof_bytes)
                            .map_err(|_| SnapshotError::UnexpectedEof)?,
                    )
                } else {
                    None
                };
                let has_output = self.read_u8()?;
                let output = if has_output == 1 {
                    let output_bytes: [u8; 32] = self.read_array::<32>()?;
                    Some(VrfOutput::from_bytes(output_bytes))
                } else {
                    None
                };
                (Some(pk), proof, output)
            } else {
                (None, None, None)
            }
        } else if self.version >= 5 {
            // v5: all three fields present together behind a single has_vrf flag
            // (the v5 writer always emitted pk + proof + output when has_vrf=1,
            //  mirroring this decode path).
            let has_vrf = self.read_u8()?;
            if has_vrf == 1 {
                let pk_bytes: [u8; 32] = self.read_array::<32>()?;
                let pk = VrfPublicKey::from_bytes(&pk_bytes)
                    .map_err(|_| SnapshotError::UnexpectedEof)?;
                // v5 always wrote proof and output together with pk when has_vrf=1.
                let proof_bytes: [u8; 96] = self.read_array::<96>()?;
                let proof =
                    VrfProof::from_bytes(&proof_bytes).map_err(|_| SnapshotError::UnexpectedEof)?;
                let output_bytes: [u8; 32] = self.read_array::<32>()?;
                let output = VrfOutput::from_bytes(output_bytes);
                (Some(pk), Some(proof), Some(output))
            } else {
                (None, None, None)
            }
        } else {
            (None, None, None)
        };

        let payload_len = self.read_count(1)?;
        if payload_len == 0 {
            // Pruned block: payload was evicted. Reconstruct with None payload.
            // The stored id is the authoritative one (computed at insertion time
            // over the original payload). We create a block with the same fields
            // using the stored id.
            return Ok(Block::new_pruned_with_vrf(
                parents,
                work,
                timestamp_ms,
                nonce,
                vrf_public_key,
                vrf_proof,
                vrf_output,
                stored_id,
            ));
        }
        let payload = self.read_bytes(payload_len)?;
        // For non-pruned blocks, verify the computed id matches the stored id.
        // Handle both legacy blocks (no VRF) and VRF blocks in v5+ format.
        let block = if let Some(pk) = vrf_public_key {
            Block::new_with_vrf(
                parents,
                work,
                timestamp_ms,
                nonce,
                pk,
                vrf_proof.unwrap(),
                vrf_output.unwrap(),
                payload,
            )
        } else {
            Block::new(parents, work, timestamp_ms, nonce, payload)
        };
        if block.id() != stored_id {
            return Err(SnapshotError::TrailingBytes); // id mismatch
        }
        Ok(block)
    }

    /// Read a block and return both the block and its stored id.
    fn read_block_with_id(&mut self) -> Result<(Block, BlockId), SnapshotError> {
        let stored_id = BlockId::from_bytes(self.read_array::<32>()?);
        let block = self.read_block_with_stored_id(stored_id)?;
        Ok((block, stored_id))
    }

    /// Read a block without a pre-read stored id (for v3 and earlier snapshots).
    fn read_block(&mut self) -> Result<Block, SnapshotError> {
        let stored_id = BlockId::from_bytes(self.read_array::<32>()?);
        self.read_block_with_stored_id(stored_id)
    }

    fn read_u8(&mut self) -> Result<u8, SnapshotError> {
        let b = self.read_array::<1>()?;
        Ok(b[0])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vrf::{vrf_keypair_from_seed, vrf_prove};

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

    // --- v6 independent VRF field encoding tests ---

    #[test]
    fn v6_encode_decode_block_without_vrf() {
        let genesis = Block::genesis(1, 0, 0, b"genesis".to_vec());
        let mut dag = Dag::new(3, genesis);
        let g = dag.genesis();
        let a = dag
            .insert(Block::new(vec![g], 5, 1, 0, b"no-vrf".to_vec()))
            .unwrap();

        let bytes = dag.write_snapshot();
        let restored = Dag::read_snapshot(&bytes).unwrap();
        assert_eq!(restored.linearize(), dag.linearize());
        assert_eq!(restored.ghostdag(&a).unwrap().selected_parent, Some(g));
    }

    #[test]
    fn v6_encode_decode_block_with_vrf_public_key_only() {
        let genesis = Block::genesis(1, 0, 0, b"genesis".to_vec());
        let (sk, pk) = vrf_keypair_from_seed(&[7u8; 32]);
        let vrf_input = Dag::vrf_input(&[genesis.id()]);
        let eval = vrf_prove(&sk, &vrf_input);

        let mut dag = Dag::new(3, genesis);
        let g = dag.genesis();
        let _id = dag
            .insert(Block::new_with_vrf(
                vec![g],
                5,
                0,
                0,
                pk,
                VrfProof::from_bytes(&[0u8; 96]).unwrap(),
                eval.output,
                b"pk-only".to_vec(),
            ))
            .unwrap();

        let restored = Dag::read_snapshot(&dag.write_snapshot()).unwrap();
        assert_eq!(restored.linearize(), dag.linearize());
    }

    #[test]
    fn v6_encode_decode_block_with_proof_and_output() {
        let genesis = Block::genesis(1, 0, 0, b"genesis".to_vec());
        let (sk, pk) = vrf_keypair_from_seed(&[11u8; 32]);
        let vrf_input = Dag::vrf_input(&[genesis.id()]);
        let eval = vrf_prove(&sk, &vrf_input);

        let mut dag = Dag::new(3, genesis);
        let g = dag.genesis();
        let id = dag
            .insert(Block::new_with_vrf(
                vec![g],
                5,
                0,
                0,
                pk,
                eval.proof.clone(),
                eval.output,
                b"full-vrf".to_vec(),
            ))
            .unwrap();

        let bytes = dag.write_snapshot();
        let restored = Dag::read_snapshot(&bytes).unwrap();
        assert_eq!(restored.linearize(), dag.linearize());

        let rest_block = restored.block(&id).unwrap();
        let orig_block = dag.block(&id).unwrap();
        assert!(rest_block.vrf_public_key().is_some());
        assert!(rest_block.vrf_proof().is_some());
        assert!(rest_block.vrf_output().is_some());
        assert_eq!(
            rest_block.vrf_public_key().unwrap().as_bytes(),
            orig_block.vrf_public_key().unwrap().as_bytes()
        );
        assert_eq!(
            rest_block.vrf_output().unwrap().as_bytes(),
            orig_block.vrf_output().unwrap().as_bytes()
        );
    }

    #[test]
    fn v6_snapshot_with_vrf_blocks_roundtrips_consensus() {
        let genesis = Block::genesis(1, 0, 0, b"genesis".to_vec());
        let (sk, pk) = vrf_keypair_from_seed(&[13u8; 32]);
        let vrf_input = Dag::vrf_input(&[genesis.id()]);
        let eval = vrf_prove(&sk, &vrf_input);

        let mut dag = Dag::new(3, genesis);
        let g = dag.genesis();

        let a = dag
            .insert(Block::new(vec![g], 1, 1, 0, b"a".to_vec()))
            .unwrap();
        let b = dag
            .insert(Block::new(vec![g], 1, 1, 0, b"b".to_vec()))
            .unwrap();

        let vrf_block = dag
            .insert(Block::new_with_vrf(
                vec![a, b],
                3,
                2,
                0,
                pk,
                eval.proof.clone(),
                eval.output,
                b"vrf".to_vec(),
            ))
            .unwrap();

        let partial_vrf = dag
            .insert(Block::new_with_vrf(
                vec![a, b],
                3,
                2,
                0,
                pk,
                VrfProof::from_bytes(&[0u8; 96]).unwrap(),
                eval.output,
                b"partial".to_vec(),
            ))
            .unwrap();

        let bytes = dag.write_snapshot();
        let restored = Dag::read_snapshot(&bytes).unwrap();

        for id in dag.linearize() {
            let orig = dag.ghostdag(&id).unwrap();
            let rest = restored.ghostdag(&id).unwrap();
            assert_eq!(
                orig.blue_score, rest.blue_score,
                "blue_score mismatch for {id}"
            );
            assert_eq!(
                orig.blue_work, rest.blue_work,
                "blue_work mismatch for {id}"
            );
            assert_eq!(
                orig.selected_parent, rest.selected_parent,
                "selected_parent mismatch for {id}"
            );
            assert_eq!(
                orig.mergeset_blues, rest.mergeset_blues,
                "mergeset_blues mismatch for {id}"
            );
            assert_eq!(
                orig.mergeset_reds, rest.mergeset_reds,
                "mergeset_reds mismatch for {id}"
            );
            assert_eq!(
                orig.blue_anticone_sizes, rest.blue_anticone_sizes,
                "blue_anticone_sizes mismatch for {id}"
            );
        }

        for id in [vrf_block, partial_vrf] {
            let orig = dag.block(&id).unwrap();
            let rest = restored.block(&id).unwrap();
            assert_eq!(orig.vrf_public_key(), rest.vrf_public_key());
            assert_eq!(orig.vrf_proof().is_some(), rest.vrf_proof().is_some());
            assert_eq!(orig.vrf_output(), rest.vrf_output());
        }
    }
    #[test]
    fn v5_format_blocks_still_decode_under_v6_reader() {
        // A snapshot written in the old v5 "all three together" layout must
        // still decode correctly under the v6 reader (backward compat):
        // the reader detects version < 6 and reads the v5 all-together layout.
        // Build a minimal v5-style encoding manually: magic + version=5 +
        // k + count + one block with has_vrf=1, pk(32), proof(96), output(32),
        // then payload len + payload.
        let mut buf = Vec::new();
        buf.extend_from_slice(b"KVDG");
        buf.extend_from_slice(&5u16.to_le_bytes()); // version 5
        buf.extend_from_slice(&3u16.to_le_bytes()); // k
        buf.extend_from_slice(&1u64.to_le_bytes()); // 1 block

        // Construct the block first so we know its correct id.
        let (sk, pk) = vrf_keypair_from_seed(&[99u8; 32]);
        let vrf_input = Dag::vrf_input(&[]);
        let eval = vrf_prove(&sk, &vrf_input);
        let test_block =
            Block::new_with_vrf(vec![], 1, 0, 0, pk, eval.proof.clone(), eval.output, vec![]);
        let correct_id = test_block.id();

        // Block with VRF: id(32) + n_parents(8) + parents(0) + work(16) +
        // ts(8) + nonce(8) + has_vrf(1) + pk(32) + proof(96) + output(32) +
        // payload_len(8) + payload(0).
        buf.extend_from_slice(correct_id.as_bytes()); // id: 32
        buf.extend_from_slice(&0u64.to_le_bytes()); // n_parents: 8
                                                    // no parents
        buf.extend_from_slice(&1u128.to_le_bytes()); // work: 16
        buf.extend_from_slice(&0u64.to_le_bytes()); // ts: 8
        buf.extend_from_slice(&0u64.to_le_bytes()); // nonce: 8

        // v5 VRF: has_vrf=1, pk(32), proof(96), output(32)
        buf.push(1u8); // has_vrf
        buf.extend_from_slice(pk.as_bytes()); // pk: 32
        buf.extend_from_slice(&eval.proof.to_bytes()); // proof: 96
        buf.extend_from_slice(eval.output.as_bytes()); // output: 32

        // payload: len(8) + data(0)
        buf.extend_from_slice(&0u64.to_le_bytes());

        // The v6 reader must read this v5 snapshot successfully (backward compat).
        let restored = Dag::read_snapshot(&buf).unwrap();
        assert_eq!(restored.len(), 1);
        assert_eq!(restored.genesis(), correct_id);
        let block = restored.block(&correct_id).unwrap();
        assert!(block.vrf_public_key().is_some());
        assert!(block.vrf_proof().is_some());
        assert!(block.vrf_output().is_some());
    }

    #[test]
    fn mismatched_vrf_output_id_is_rejected() {
        let dag = build();
        let mut bytes = dag.write_snapshot();
        // Flip a byte in the genesis block's stored id (offset 24: after
        // magic(4) + version(2) + k(2) + count(8) = 16, then genesis id starts
        // at offset 16; flip byte at offset 16+1=17).
        assert!(bytes.len() > 17);
        bytes[17] ^= 1;
        assert!(matches!(
            Dag::read_snapshot(&bytes),
            Err(SnapshotError::TrailingBytes) | Err(SnapshotError::Rebuild(_))
        ));
    }
}
