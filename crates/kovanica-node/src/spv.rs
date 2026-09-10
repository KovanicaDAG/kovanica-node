//! SPV (Simplified Payment Verification) light client wire sync and proof verification.
//!
//! Provides helper functions for light clients to connect to full nodes over
//! persistent [`RelaySession`] connections, request and validate block header chains,
//! and verify Merkle transaction inclusion proofs without downloading full DAG blocks.

use kovanica_dag::BlockId;
pub use kovanica_state::spv::{
    generate_merkle_proof, merkle_root, BlockFilter, BlockHeader, MerkleProof, SpvClient, SpvError,
};
use kovanica_state::TxId;

use crate::net::NetError;
use crate::node::MerkleBlock;
use crate::relay::{RelayMsg, RelaySession};

/// Generate a block locator hashes list (newest first, exponential spacing)
/// to locate the common ancestor with a full node peer.
pub fn build_locator(client: &SpvClient) -> Vec<BlockId> {
    let Some(tip) = client.tip() else {
        return Vec::new();
    };
    let mut locator = Vec::new();
    let mut step = 1u64;
    let mut cur_height = tip.height;

    while let Some(h) = client.header(cur_height) {
        locator.push(h.id);
        if cur_height == 0 {
            break;
        }
        if locator.len() >= 10 {
            step = step.saturating_mul(2);
        }
        cur_height = cur_height.saturating_sub(step);
    }

    if let Some(genesis_hdr) = client.header(0) {
        if locator.last() != Some(&genesis_hdr.id) {
            locator.push(genesis_hdr.id);
        }
    }
    locator
}

/// Synchronize SPV block headers from a full node over an active [`RelaySession`].
///
/// Sends a `GetHeaders` request with the client's current block locator and
/// processes the received `Headers` response, validating and inserting each header
/// into `client`. Returns the number of new headers accepted.
pub fn sync_headers_via_relay(
    session: &mut RelaySession,
    client: &mut SpvClient,
    stop_hash: Option<BlockId>,
) -> Result<usize, NetError> {
    sync_headers_via_relay_with_clock(session, client, stop_hash, None)
}

/// Like [`sync_headers_via_relay`], but with an optional clock override for deterministic
/// wall-clock future drift checking.
pub fn sync_headers_via_relay_with_clock(
    session: &mut RelaySession,
    client: &mut SpvClient,
    stop_hash: Option<BlockId>,
    now_ms_override: Option<u64>,
) -> Result<usize, NetError> {
    let locator = build_locator(client);
    let req = RelayMsg::GetHeaders {
        locator,
        stop_hash,
        max_count: 2000,
    };
    session.send(&req)?;
    let resp = session.recv()?;
    match resp {
        RelayMsg::Headers { headers } => {
            let mut accepted = 0;
            for header in headers {
                if let Some(now_ms) = now_ms_override {
                    const MAX_FUTURE_DRIFT_MS: u64 = 2 * 60 * 60 * 1000;
                    if header.timestamp_ms > now_ms.saturating_add(MAX_FUTURE_DRIFT_MS) {
                        return Err(NetError::Apply(format!(
                            "header timestamp {} exceeds wall-clock future drift limit (now={})",
                            header.timestamp_ms, now_ms
                        )));
                    }
                }
                client
                    .add_header(header)
                    .map_err(|e| NetError::Apply(e.to_string()))?;
                accepted += 1;
            }
            Ok(accepted)
        }
        other => Err(NetError::Decode(format!(
            "expected Headers response, got {:?}",
            other
        ))),
    }
}

/// Request a `MerkleBlock` for transaction `tx_id` in block `block_id` from a full node over [`RelaySession`].
pub fn request_merkle_block(
    session: &mut RelaySession,
    block_id: BlockId,
    tx_id: TxId,
) -> Result<MerkleBlock, NetError> {
    let req = RelayMsg::GetMerkleProof { block_id, tx_id };
    session.send(&req)?;
    let resp = session.recv()?;
    match resp {
        RelayMsg::MerkleBlock {
            block_id: b_id,
            merkle_root,
            tx_count,
            proof,
            matched_tx,
        } => {
            if b_id != block_id {
                return Err(NetError::Decode("response block_id mismatch".into()));
            }
            Ok(MerkleBlock {
                block_id: b_id,
                merkle_root,
                tx_count,
                proof,
                matched_tx,
            })
        }
        other => Err(NetError::Decode(format!(
            "expected MerkleBlock response, got {:?}",
            other
        ))),
    }
}

/// Verify that a `MerkleBlock` contains a valid transaction inclusion proof matching
/// a header verified by `client`.
///
/// Returns `Ok(true)` if the proof is valid and matches the header in `client`,
/// `Ok(false)` if the proof or header is invalid/mismatched, or `Err` if no headers exist.
pub fn verify_merkle_block(client: &SpvClient, mb: &MerkleBlock) -> Result<bool, SpvError> {
    let (Some(proof), Some(matched_tx)) = (&mb.proof, &mb.matched_tx) else {
        return Ok(false);
    };

    // Check that matched_tx id matches proof tx_id
    if *matched_tx.id().as_bytes() != proof.tx_id {
        return Ok(false);
    }

    // Check proof self-consistency and root match
    if proof.merkle_root != mb.merkle_root || !proof.verify() {
        return Ok(false);
    }

    // Find the header matching block_id in client
    let tip = client.tip().ok_or(SpvError::NoCheckpoint)?;
    let mut found_header = None;
    for h in 0..=tip.height {
        if let Some(header) = client.header(h) {
            if header.id == mb.block_id {
                found_header = Some(header);
                break;
            }
        }
    }

    let Some(header) = found_header else {
        return Ok(false);
    };

    if header.merkle_root != mb.merkle_root {
        return Ok(false);
    }

    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::Node;

    #[test]
    fn test_locator_generation() {
        let mut node = Node::new();
        node.genesis(3, 1000, 1000, 1).unwrap();
        let genesis_hdr = node.spv_header(&node.genesis_id().unwrap()).unwrap();
        let client = SpvClient::new(genesis_hdr.clone(), false, None);

        let loc = build_locator(&client);
        assert_eq!(loc.len(), 1);
        assert_eq!(loc[0], genesis_hdr.id);
    }

    #[test]
    fn test_merkle_block_verification() {
        let mut node = Node::new();
        node.genesis(3, 1000, 1000, 1).unwrap();
        let sent = node.send(1, 200, 2).unwrap();

        let genesis_hdr = node.spv_header(&node.genesis_id().unwrap()).unwrap();
        let mut client = SpvClient::new(genesis_hdr, false, None);

        let block_hdr = node.spv_header(&sent.block).unwrap();
        client.add_header(block_hdr).unwrap();

        let mb = node.merkle_block(&sent.block, &sent.tx).unwrap();
        assert!(verify_merkle_block(&client, &mb).unwrap());
    }
}
