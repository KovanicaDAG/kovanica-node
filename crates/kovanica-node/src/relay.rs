//! Long-lived TCP relay: the same envelopes as [`crate::p2p::Mesh`] (hello,
//! block, tx) framed on a **persistent** connection, plus SPV wire messages.
//!
//! [`crate::net::serve_blocks`] / [`crate::net::pull_blocks`] write every
//! block and close. A [`RelaySession`] stays open: the caller sends and
//! receives messages for as long as the socket lives. `Node` is not `Send`, so
//! the session itself is only I/O — apply received messages on the thread that
//! owns the node ([`apply_relay`] or [`handle_relay_query`]).

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::time::Duration;

use kovanica_dag::BlockId;
use kovanica_state::{
    decode_block_payload, encode_block_payload,
    spv::{BlockHeader as SpvHeader, MerkleProof},
    Transaction, TxId,
};

use crate::dht::{
    NodeId, PeerContact, TAG_DHT_FIND_NODE, TAG_DHT_NODES, TAG_DHT_PING, TAG_DHT_PONG,
};
use crate::net::{decode_one_record, encode_record, NetError};
use crate::node::{BlockRecord, Node};

pub const TAG_HELLO: u8 = 0;
pub const TAG_BLOCK: u8 = 1;
pub const TAG_TX: u8 = 2;
pub const TAG_HEADERS: u8 = 0x11;
pub const TAG_GETHEADERS: u8 = 0x12;
pub const TAG_GETBLOCKS: u8 = 0x13;
pub const TAG_GET_MERKLE_PROOF: u8 = 0x15;
pub const TAG_MERKLEBLOCK: u8 = 0x16;

/// Refuse a single frame larger than this (defence against a bogus length).
pub const MAX_FRAME: usize = 4 * 1024 * 1024;
pub const MAX_HEADERS: usize = 10_000;
pub const MAX_LOCATOR_IDS: usize = 1_000;
pub const MAX_MERKLE_PATH: usize = 64;

/// One message on a [`RelaySession`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RelayMsg {
    /// Peer-discovery hello: who we are and who we currently peer with.
    Hello {
        /// Sender's overlay name.
        from: String,
        /// Names the sender currently peers with.
        advertised: Vec<String>,
    },
    /// A block record, same payload as one-shot gossip.
    Block(BlockRecord),
    /// A mempool transaction.
    Tx(Transaction),
    /// SPV Request: Request headers along the selected chain matching locator.
    GetHeaders {
        /// Locator block hashes, newest first (exponential backoff).
        locator: Vec<BlockId>,
        /// Stop block hash (None / [0;32] means sync up to the tip).
        stop_hash: Option<BlockId>,
        /// Maximum number of headers to return.
        max_count: u32,
    },
    /// SPV Response: Batch of block headers for the light client.
    Headers { headers: Vec<SpvHeader> },
    /// SPV / Node Request: Request blocks or inventory starting from locator.
    GetBlocks {
        locator: Vec<BlockId>,
        stop_hash: Option<BlockId>,
    },
    /// SPV Request: Request transaction inclusion proof for a block.
    GetMerkleProof { block_id: BlockId, tx_id: TxId },
    /// SPV Response: Merkle root, transaction count, sibling proof path, and matched transaction.
    MerkleBlock {
        block_id: BlockId,
        merkle_root: [u8; 32],
        tx_count: u32,
        proof: Option<MerkleProof>,
        matched_tx: Option<Transaction>,
    },
    /// DHT Ping request.
    DhtPing { sender: NodeId, nonce: u64 },
    /// DHT Ping response.
    DhtPong { sender: NodeId, nonce: u64 },
    /// DHT FindNode request.
    DhtFindNode {
        sender: NodeId,
        target: NodeId,
        nonce: u64,
    },
    /// DHT FindNode response (closest nodes).
    DhtNodes {
        sender: NodeId,
        target: NodeId,
        nonce: u64,
        nodes: Vec<PeerContact>,
    },
}

/// A bidirectional, long-lived TCP session carrying [`RelayMsg`]s.
pub struct RelaySession {
    stream: TcpStream,
}

impl RelaySession {
    /// Accept one incoming connection and take it as a relay session.
    pub fn accept(listener: &TcpListener) -> Result<Self, NetError> {
        let (stream, _) = listener.accept().map_err(io)?;
        stream.set_nodelay(true).map_err(io)?;
        Ok(Self { stream })
    }

    /// Dial a peer that is [`accept`](Self::accept)ing.
    pub fn connect<A: ToSocketAddrs>(addr: A) -> Result<Self, NetError> {
        let stream = TcpStream::connect(addr).map_err(io)?;
        stream.set_nodelay(true).map_err(io)?;
        Ok(Self { stream })
    }

    /// Bound a blocking [`recv`](Self::recv) so tests (and polite peers) cannot hang forever.
    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> Result<(), NetError> {
        self.stream.set_read_timeout(timeout).map_err(io)
    }

    /// Bound a blocking [`send`](Self::send) write operation.
    pub fn set_write_timeout(&self, timeout: Option<Duration>) -> Result<(), NetError> {
        self.stream.set_write_timeout(timeout).map_err(io)
    }

    /// Write one message. The connection stays open.
    pub fn send(&mut self, msg: &RelayMsg) -> Result<(), NetError> {
        let payload = encode_msg(msg);
        let len = payload.len() as u32;
        self.stream.write_all(&len.to_le_bytes()).map_err(io)?;
        self.stream.write_all(&payload).map_err(io)?;
        self.stream.flush().map_err(io)?;
        Ok(())
    }

    /// Block until the next message arrives.
    pub fn recv(&mut self) -> Result<RelayMsg, NetError> {
        let mut len_buf = [0u8; 4];
        self.stream.read_exact(&mut len_buf).map_err(io)?;
        let len = u32::from_le_bytes(len_buf) as usize;
        if len > MAX_FRAME {
            return Err(NetError::Decode("frame too large".into()));
        }
        let mut payload = vec![0u8; len];
        self.stream.read_exact(&mut payload).map_err(io)?;
        decode_msg(&payload)
    }
}

/// Apply a received relay message to `node`. Hellos, SPV, and DHT messages are passed
/// through to the caller.
pub fn apply_relay(node: &mut Node, msg: RelayMsg) -> Result<Option<RelayMsg>, NetError> {
    match msg {
        hello @ RelayMsg::Hello { .. } => Ok(Some(hello)),
        RelayMsg::Block(record) => {
            node.receive_block(record)
                .map_err(|e| NetError::Apply(e.to_string()))?;
            Ok(None)
        }
        RelayMsg::Tx(tx) => {
            node.submit_tx(tx)
                .map_err(|e| NetError::Apply(e.to_string()))?;
            Ok(None)
        }
        spv @ (RelayMsg::GetHeaders { .. }
        | RelayMsg::Headers { .. }
        | RelayMsg::GetBlocks { .. }
        | RelayMsg::GetMerkleProof { .. }
        | RelayMsg::MerkleBlock { .. }) => Ok(Some(spv)),
        dht @ (RelayMsg::DhtPing { .. }
        | RelayMsg::DhtPong { .. }
        | RelayMsg::DhtFindNode { .. }
        | RelayMsg::DhtNodes { .. }) => Ok(Some(dht)),
    }
}

/// Handle query-type relay messages that require an immediate response back over the wire.
/// Returns `Some(response)` for queries (`GetHeaders`, `GetBlocks`, `GetMerkleProof`, `DhtPing`, `DhtFindNode`),
/// or `None` for push/stateful messages (`Hello`, `Block`, `Tx`, `Headers`, `MerkleBlock`, `DhtPong`, `DhtNodes`).
pub fn handle_relay_query(node: &Node, msg: &RelayMsg) -> Option<RelayMsg> {
    match msg {
        RelayMsg::GetHeaders {
            locator,
            stop_hash,
            max_count,
        } => {
            let limit = if *max_count == 0 {
                2000
            } else {
                *max_count as usize
            };
            let headers = node
                .headers_from(locator, *stop_hash, limit)
                .unwrap_or_default();
            Some(RelayMsg::Headers { headers })
        }
        RelayMsg::GetBlocks { locator, stop_hash } => {
            let headers = node
                .headers_from(locator, *stop_hash, 2000)
                .unwrap_or_default();
            Some(RelayMsg::Headers { headers })
        }
        RelayMsg::GetMerkleProof { block_id, tx_id } => {
            if let Ok(mb) = node.merkle_block(block_id, tx_id) {
                Some(RelayMsg::MerkleBlock {
                    block_id: mb.block_id,
                    merkle_root: mb.merkle_root,
                    tx_count: mb.tx_count,
                    proof: mb.proof,
                    matched_tx: mb.matched_tx,
                })
            } else {
                None
            }
        }
        RelayMsg::DhtPing { sender, nonce } => Some(RelayMsg::DhtPong {
            sender: *sender,
            nonce: *nonce,
        }),
        RelayMsg::DhtFindNode {
            sender,
            target,
            nonce,
        } => {
            // Use Node's DHT routing table if available
            if let Some(table) = node.dht_routing_table() {
                let nodes = table.closest_peers(target, table.k);
                Some(RelayMsg::DhtNodes {
                    sender: *sender,
                    target: *target,
                    nonce: *nonce,
                    nodes,
                })
            } else {
                // Node doesn't have DHT routing table; return empty nodes
                Some(RelayMsg::DhtNodes {
                    sender: *sender,
                    target: *target,
                    nonce: *nonce,
                    nodes: Vec::new(),
                })
            }
        }
        _ => None,
    }
}

fn io(e: std::io::Error) -> NetError {
    NetError::Io(e.to_string())
}

/// Binary encode a [`RelayMsg`].
pub fn encode_msg(msg: &RelayMsg) -> Vec<u8> {
    let mut buf = Vec::new();
    match msg {
        RelayMsg::Hello { from, advertised } => {
            buf.push(TAG_HELLO);
            push_str(&mut buf, from);
            buf.extend_from_slice(&(advertised.len() as u16).to_le_bytes());
            for name in advertised {
                push_str(&mut buf, name);
            }
        }
        RelayMsg::Block(record) => {
            buf.push(TAG_BLOCK);
            encode_record(record, &mut buf);
        }
        RelayMsg::Tx(tx) => {
            buf.push(TAG_TX);
            let payload = encode_block_payload(std::slice::from_ref(tx));
            buf.extend_from_slice(&(payload.len() as u32).to_le_bytes());
            buf.extend_from_slice(&payload);
        }
        RelayMsg::GetHeaders {
            locator,
            stop_hash,
            max_count,
        } => {
            buf.push(TAG_GETHEADERS);
            buf.extend_from_slice(&(locator.len() as u64).to_le_bytes());
            for id in locator {
                buf.extend_from_slice(id.as_bytes());
            }
            match stop_hash {
                Some(stop) => {
                    buf.push(1u8);
                    buf.extend_from_slice(stop.as_bytes());
                }
                None => {
                    buf.push(0u8);
                }
            }
            buf.extend_from_slice(&max_count.to_le_bytes());
        }
        RelayMsg::Headers { headers } => {
            buf.push(TAG_HEADERS);
            buf.extend_from_slice(&(headers.len() as u64).to_le_bytes());
            for h in headers {
                buf.extend_from_slice(h.id.as_bytes());
                buf.extend_from_slice(h.prev_hash.as_bytes());
                buf.extend_from_slice(&h.merkle_root);
                buf.extend_from_slice(&h.work.to_le_bytes());
                buf.extend_from_slice(&h.timestamp_ms.to_le_bytes());
                buf.extend_from_slice(&h.nonce.to_le_bytes());
                buf.extend_from_slice(&h.blue_score.to_le_bytes());
                buf.extend_from_slice(&h.chain_blue_work.to_le_bytes());
                buf.extend_from_slice(&h.height.to_le_bytes());
            }
        }
        RelayMsg::GetBlocks { locator, stop_hash } => {
            buf.push(TAG_GETBLOCKS);
            buf.extend_from_slice(&(locator.len() as u64).to_le_bytes());
            for id in locator {
                buf.extend_from_slice(id.as_bytes());
            }
            match stop_hash {
                Some(stop) => {
                    buf.push(1u8);
                    buf.extend_from_slice(stop.as_bytes());
                }
                None => {
                    buf.push(0u8);
                }
            }
        }
        RelayMsg::GetMerkleProof { block_id, tx_id } => {
            buf.push(TAG_GET_MERKLE_PROOF);
            buf.extend_from_slice(block_id.as_bytes());
            buf.extend_from_slice(tx_id.as_bytes());
        }
        RelayMsg::MerkleBlock {
            block_id,
            merkle_root,
            tx_count,
            proof,
            matched_tx,
        } => {
            buf.push(TAG_MERKLEBLOCK);
            buf.extend_from_slice(block_id.as_bytes());
            buf.extend_from_slice(merkle_root);
            buf.extend_from_slice(&tx_count.to_le_bytes());
            match proof {
                Some(p) => {
                    buf.push(1u8);
                    buf.extend_from_slice(&p.tx_id);
                    buf.extend_from_slice(&p.merkle_root);
                    buf.extend_from_slice(&(p.path.len() as u64).to_le_bytes());
                    for sibling in &p.path {
                        buf.extend_from_slice(sibling);
                    }
                    buf.extend_from_slice(&(p.index as u64).to_le_bytes());
                    buf.extend_from_slice(&(p.tx_count as u64).to_le_bytes());
                }
                None => {
                    buf.push(0u8);
                }
            }
            match matched_tx {
                Some(tx) => {
                    buf.push(1u8);
                    let tx_payload = encode_block_payload(std::slice::from_ref(tx));
                    buf.extend_from_slice(&(tx_payload.len() as u32).to_le_bytes());
                    buf.extend_from_slice(&tx_payload);
                }
                None => {
                    buf.push(0u8);
                }
            }
        }
        RelayMsg::DhtPing { sender, nonce } => {
            buf.push(TAG_DHT_PING);
            buf.extend_from_slice(sender.as_bytes());
            buf.extend_from_slice(&nonce.to_le_bytes());
        }
        RelayMsg::DhtPong { sender, nonce } => {
            buf.push(TAG_DHT_PONG);
            buf.extend_from_slice(sender.as_bytes());
            buf.extend_from_slice(&nonce.to_le_bytes());
        }
        RelayMsg::DhtFindNode {
            sender,
            target,
            nonce,
        } => {
            buf.push(TAG_DHT_FIND_NODE);
            buf.extend_from_slice(sender.as_bytes());
            buf.extend_from_slice(target.as_bytes());
            buf.extend_from_slice(&nonce.to_le_bytes());
        }
        RelayMsg::DhtNodes {
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

/// Binary decode a [`RelayMsg`].
pub fn decode_msg(bytes: &[u8]) -> Result<RelayMsg, NetError> {
    if bytes.is_empty() {
        return Err(NetError::Decode("empty frame".into()));
    }
    let tag = bytes[0];
    let rest = &bytes[1..];
    match tag {
        TAG_HELLO => {
            let mut r = Cursor { buf: rest, pos: 0 };
            let from = r.read_str()?;
            if r.remaining() < 2 {
                return Err(NetError::Decode("hello truncated".into()));
            }
            let n = u16::from_le_bytes(r.read_array::<2>()?) as usize;
            let mut advertised = Vec::with_capacity(n);
            for _ in 0..n {
                advertised.push(r.read_str()?);
            }
            if r.remaining() != 0 {
                return Err(NetError::Decode("hello trailing bytes".into()));
            }
            Ok(RelayMsg::Hello { from, advertised })
        }
        TAG_BLOCK => Ok(RelayMsg::Block(decode_one_record(rest)?)),
        TAG_TX => {
            if rest.len() < 4 {
                return Err(NetError::Decode("tx truncated".into()));
            }
            let n = u32::from_le_bytes(rest[..4].try_into().expect("4")) as usize;
            if rest.len() != 4 + n {
                return Err(NetError::Decode("tx length mismatch".into()));
            }
            let mut txs =
                decode_block_payload(&rest[4..]).map_err(|e| NetError::Decode(e.to_string()))?;
            if txs.len() != 1 {
                return Err(NetError::Decode(
                    "tx frame must hold one transaction".into(),
                ));
            }
            Ok(RelayMsg::Tx(txs.remove(0)))
        }
        TAG_GETHEADERS => {
            let mut r = Cursor { buf: rest, pos: 0 };
            let locator_count = r.read_count(32)?;
            if locator_count > MAX_LOCATOR_IDS {
                return Err(NetError::Decode("locator count too large".into()));
            }
            let mut locator = Vec::with_capacity(locator_count);
            for _ in 0..locator_count {
                locator.push(BlockId::from_bytes(r.read_array::<32>()?));
            }
            let has_stop = r.read_array::<1>()?[0];
            let stop_hash = match has_stop {
                0 => None,
                1 => Some(BlockId::from_bytes(r.read_array::<32>()?)),
                _ => return Err(NetError::Decode("invalid has_stop flag".into())),
            };
            let max_count = u32::from_le_bytes(r.read_array::<4>()?);
            if r.remaining() != 0 {
                return Err(NetError::Decode("trailing bytes in getheaders".into()));
            }
            Ok(RelayMsg::GetHeaders {
                locator,
                stop_hash,
                max_count,
            })
        }
        TAG_HEADERS => {
            let mut r = Cursor { buf: rest, pos: 0 };
            let header_count = r.read_count(160)?;
            if header_count > MAX_HEADERS {
                return Err(NetError::Decode("headers count too large".into()));
            }
            let mut headers = Vec::with_capacity(header_count);
            for _ in 0..header_count {
                let id = BlockId::from_bytes(r.read_array::<32>()?);
                let prev_hash = BlockId::from_bytes(r.read_array::<32>()?);
                let merkle_root = r.read_array::<32>()?;
                let work = u128::from_le_bytes(r.read_array::<16>()?);
                let timestamp_ms = u64::from_le_bytes(r.read_array::<8>()?);
                let nonce = u64::from_le_bytes(r.read_array::<8>()?);
                let blue_score = u64::from_le_bytes(r.read_array::<8>()?);
                let chain_blue_work = u128::from_le_bytes(r.read_array::<16>()?);
                let height = u64::from_le_bytes(r.read_array::<8>()?);
                headers.push(SpvHeader {
                    id,
                    prev_hash,
                    merkle_root,
                    work,
                    timestamp_ms,
                    nonce,
                    blue_score,
                    chain_blue_work,
                    height,
                });
            }
            if r.remaining() != 0 {
                return Err(NetError::Decode("trailing bytes in headers".into()));
            }
            Ok(RelayMsg::Headers { headers })
        }
        TAG_GETBLOCKS => {
            let mut r = Cursor { buf: rest, pos: 0 };
            let locator_count = r.read_count(32)?;
            if locator_count > MAX_LOCATOR_IDS {
                return Err(NetError::Decode("locator count too large".into()));
            }
            let mut locator = Vec::with_capacity(locator_count);
            for _ in 0..locator_count {
                locator.push(BlockId::from_bytes(r.read_array::<32>()?));
            }
            let has_stop = r.read_array::<1>()?[0];
            let stop_hash = match has_stop {
                0 => None,
                1 => Some(BlockId::from_bytes(r.read_array::<32>()?)),
                _ => return Err(NetError::Decode("invalid has_stop flag".into())),
            };
            if r.remaining() != 0 {
                return Err(NetError::Decode("trailing bytes in getblocks".into()));
            }
            Ok(RelayMsg::GetBlocks { locator, stop_hash })
        }
        TAG_GET_MERKLE_PROOF => {
            let mut r = Cursor { buf: rest, pos: 0 };
            let block_id = BlockId::from_bytes(r.read_array::<32>()?);
            let tx_id = TxId::from_bytes(r.read_array::<32>()?);
            if r.remaining() != 0 {
                return Err(NetError::Decode(
                    "trailing bytes in get_merkle_proof".into(),
                ));
            }
            Ok(RelayMsg::GetMerkleProof { block_id, tx_id })
        }
        TAG_MERKLEBLOCK => {
            let mut r = Cursor { buf: rest, pos: 0 };
            let block_id = BlockId::from_bytes(r.read_array::<32>()?);
            let merkle_root = r.read_array::<32>()?;
            let tx_count = u32::from_le_bytes(r.read_array::<4>()?);
            let has_proof = r.read_array::<1>()?[0];
            let proof = match has_proof {
                0 => None,
                1 => {
                    let tx_id = r.read_array::<32>()?;
                    let proof_merkle_root = r.read_array::<32>()?;
                    let path_len = r.read_count(32)?;
                    if path_len > MAX_MERKLE_PATH {
                        return Err(NetError::Decode("merkle path too long".into()));
                    }
                    let mut path = Vec::with_capacity(path_len);
                    for _ in 0..path_len {
                        path.push(r.read_array::<32>()?);
                    }
                    let index = u64::from_le_bytes(r.read_array::<8>()?) as usize;
                    let proof_tx_count = u64::from_le_bytes(r.read_array::<8>()?) as usize;
                    Some(MerkleProof {
                        tx_id,
                        merkle_root: proof_merkle_root,
                        path,
                        index,
                        tx_count: proof_tx_count,
                    })
                }
                _ => return Err(NetError::Decode("invalid has_proof flag".into())),
            };
            let has_matched_tx = r.read_array::<1>()?[0];
            let matched_tx = match has_matched_tx {
                0 => None,
                1 => {
                    let tx_payload_len = u32::from_le_bytes(r.read_array::<4>()?) as usize;
                    if tx_payload_len > MAX_FRAME {
                        return Err(NetError::Decode("matched tx payload too large".into()));
                    }
                    let slice = r.read_slice(tx_payload_len)?;
                    let mut txs =
                        decode_block_payload(slice).map_err(|e| NetError::Decode(e.to_string()))?;
                    if txs.len() != 1 {
                        return Err(NetError::Decode(
                            "expected 1 tx in matched_tx payload".into(),
                        ));
                    }
                    Some(txs.remove(0))
                }
                _ => return Err(NetError::Decode("invalid has_matched_tx flag".into())),
            };
            if r.remaining() != 0 {
                return Err(NetError::Decode("trailing bytes in merkleblock".into()));
            }
            Ok(RelayMsg::MerkleBlock {
                block_id,
                merkle_root,
                tx_count,
                proof,
                matched_tx,
            })
        }
        TAG_DHT_PING => {
            if rest.len() < 40 {
                return Err(NetError::Decode("dht ping truncated".into()));
            }
            let sender = NodeId::from_bytes(rest[..32].try_into().unwrap());
            let nonce = u64::from_le_bytes(rest[32..40].try_into().unwrap());
            Ok(RelayMsg::DhtPing { sender, nonce })
        }
        TAG_DHT_PONG => {
            if rest.len() < 40 {
                return Err(NetError::Decode("dht pong truncated".into()));
            }
            let sender = NodeId::from_bytes(rest[..32].try_into().unwrap());
            let nonce = u64::from_le_bytes(rest[32..40].try_into().unwrap());
            Ok(RelayMsg::DhtPong { sender, nonce })
        }
        TAG_DHT_FIND_NODE => {
            if rest.len() < 72 {
                return Err(NetError::Decode("dht find_node truncated".into()));
            }
            let sender = NodeId::from_bytes(rest[..32].try_into().unwrap());
            let target = NodeId::from_bytes(rest[32..64].try_into().unwrap());
            let nonce = u64::from_le_bytes(rest[64..72].try_into().unwrap());
            Ok(RelayMsg::DhtFindNode {
                sender,
                target,
                nonce,
            })
        }
        TAG_DHT_NODES => {
            if rest.len() < 72 {
                return Err(NetError::Decode("dht nodes truncated".into()));
            }
            let sender = NodeId::from_bytes(rest[..32].try_into().unwrap());
            let target = NodeId::from_bytes(rest[32..64].try_into().unwrap());
            let nonce = u64::from_le_bytes(rest[64..72].try_into().unwrap());
            let mut pos = 72;
            if pos + 2 > rest.len() {
                return Err(NetError::Decode("dht nodes count truncated".into()));
            }
            let count = u16::from_le_bytes(rest[pos..pos + 2].try_into().unwrap()) as usize;
            pos += 2;
            let mut nodes = Vec::with_capacity(count);
            for _ in 0..count {
                if pos + 32 > rest.len() {
                    return Err(NetError::Decode("dht node id truncated".into()));
                }
                let node_id = NodeId::from_bytes(rest[pos..pos + 32].try_into().unwrap());
                pos += 32;
                if pos + 2 > rest.len() {
                    return Err(NetError::Decode("dht addr len truncated".into()));
                }
                let addr_len = u16::from_le_bytes(rest[pos..pos + 2].try_into().unwrap()) as usize;
                pos += 2;
                if pos + addr_len > rest.len() {
                    return Err(NetError::Decode("dht addr truncated".into()));
                }
                let addr = String::from_utf8(rest[pos..pos + addr_len].to_vec())
                    .map_err(|_| NetError::Decode("dht addr not utf-8".into()))?;
                pos += addr_len;
                if pos + 12 > rest.len() {
                    return Err(NetError::Decode("dht timestamp/failed truncated".into()));
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
            if pos != rest.len() {
                return Err(NetError::Decode("trailing bytes in dht nodes".into()));
            }
            Ok(RelayMsg::DhtNodes {
                sender,
                target,
                nonce,
                nodes,
            })
        }
        other => Err(NetError::Decode(format!("unknown tag {other}"))),
    }
}

fn push_str(buf: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    buf.extend_from_slice(&(bytes.len() as u16).to_le_bytes());
    buf.extend_from_slice(bytes);
}

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], NetError> {
        if self.remaining() < N {
            return Err(NetError::Decode("unexpected end".into()));
        }
        let mut out = [0u8; N];
        out.copy_from_slice(&self.buf[self.pos..self.pos + N]);
        self.pos += N;
        Ok(out)
    }

    fn read_slice(&mut self, len: usize) -> Result<&'a [u8], NetError> {
        if self.remaining() < len {
            return Err(NetError::Decode("unexpected end".into()));
        }
        let out = &self.buf[self.pos..self.pos + len];
        self.pos += len;
        Ok(out)
    }

    fn read_count(&mut self, min_element_bytes: usize) -> Result<usize, NetError> {
        let n = u64::from_le_bytes(self.read_array::<8>()?) as usize;
        if min_element_bytes > 0 && n > self.remaining() / min_element_bytes {
            return Err(NetError::Decode("count too large".into()));
        }
        Ok(n)
    }

    fn read_str(&mut self) -> Result<String, NetError> {
        let n = u16::from_le_bytes(self.read_array::<2>()?) as usize;
        if self.remaining() < n {
            return Err(NetError::Decode("string truncated".into()));
        }
        let bytes = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        String::from_utf8(bytes.to_vec()).map_err(|_| NetError::Decode("name not utf-8".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kovanica_state::{KeyPair, OutPoint, TxOutput};

    #[test]
    fn test_hello_roundtrip() {
        let msg = RelayMsg::Hello {
            from: "node-1".into(),
            advertised: vec!["node-2".into(), "node-3".into()],
        };
        let encoded = encode_msg(&msg);
        let decoded = decode_msg(&encoded).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_getheaders_roundtrip() {
        let msg = RelayMsg::GetHeaders {
            locator: vec![
                BlockId::from_bytes([1u8; 32]),
                BlockId::from_bytes([2u8; 32]),
            ],
            stop_hash: Some(BlockId::from_bytes([3u8; 32])),
            max_count: 500,
        };
        let encoded = encode_msg(&msg);
        let decoded = decode_msg(&encoded).unwrap();
        assert_eq!(msg, decoded);

        let msg_no_stop = RelayMsg::GetHeaders {
            locator: vec![BlockId::from_bytes([4u8; 32])],
            stop_hash: None,
            max_count: 2000,
        };
        let encoded = encode_msg(&msg_no_stop);
        let decoded = decode_msg(&encoded).unwrap();
        assert_eq!(msg_no_stop, decoded);
    }

    #[test]
    fn test_headers_roundtrip() {
        let h1 = SpvHeader {
            id: BlockId::from_bytes([1u8; 32]),
            prev_hash: BlockId::from_bytes([0u8; 32]),
            merkle_root: [10u8; 32],
            work: 100,
            timestamp_ms: 1000,
            nonce: 42,
            blue_score: 0,
            chain_blue_work: 100,
            height: 0,
        };
        let h2 = SpvHeader {
            id: BlockId::from_bytes([2u8; 32]),
            prev_hash: BlockId::from_bytes([1u8; 32]),
            merkle_root: [20u8; 32],
            work: 200,
            timestamp_ms: 2000,
            nonce: 84,
            blue_score: 1,
            chain_blue_work: 300,
            height: 1,
        };
        let msg = RelayMsg::Headers {
            headers: vec![h1, h2],
        };
        let encoded = encode_msg(&msg);
        let decoded = decode_msg(&encoded).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_getblocks_roundtrip() {
        let msg = RelayMsg::GetBlocks {
            locator: vec![BlockId::from_bytes([1u8; 32])],
            stop_hash: Some(BlockId::from_bytes([2u8; 32])),
        };
        let encoded = encode_msg(&msg);
        let decoded = decode_msg(&encoded).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_get_merkle_proof_roundtrip() {
        let msg = RelayMsg::GetMerkleProof {
            block_id: BlockId::from_bytes([1u8; 32]),
            tx_id: TxId::from_bytes([2u8; 32]),
        };
        let encoded = encode_msg(&msg);
        let decoded = decode_msg(&encoded).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_merkle_block_roundtrip() {
        let kp = KeyPair::from_u64(1);
        let op = OutPoint::new(TxId::from_bytes([1u8; 32]), 0);
        let tx = Transaction::signed(&[(op, &kp)], vec![TxOutput::new(100, kp.address())], vec![]);

        let proof = MerkleProof {
            tx_id: *tx.id().as_bytes(),
            merkle_root: [5u8; 32],
            path: vec![[6u8; 32], [7u8; 32]],
            index: 1,
            tx_count: 4,
        };

        let msg = RelayMsg::MerkleBlock {
            block_id: BlockId::from_bytes([8u8; 32]),
            merkle_root: [5u8; 32],
            tx_count: 4,
            proof: Some(proof),
            matched_tx: Some(tx),
        };
        let encoded = encode_msg(&msg);
        let decoded = decode_msg(&encoded).unwrap();
        assert_eq!(msg, decoded);

        let msg_none = RelayMsg::MerkleBlock {
            block_id: BlockId::from_bytes([8u8; 32]),
            merkle_root: [5u8; 32],
            tx_count: 0,
            proof: None,
            matched_tx: None,
        };
        let encoded_none = encode_msg(&msg_none);
        let decoded_none = decode_msg(&encoded_none).unwrap();
        assert_eq!(msg_none, decoded_none);
    }

    #[test]
    fn test_decode_bounds_and_errors() {
        assert!(decode_msg(&[]).is_err());
        assert!(decode_msg(&[255]).is_err());

        // Truncated GetMerkleProof
        let mut buf = vec![TAG_GET_MERKLE_PROOF];
        buf.extend_from_slice(&[0u8; 31]);
        assert!(decode_msg(&buf).is_err());
    }

    #[test]
    fn test_handle_relay_query() {
        let mut node = Node::new();
        node.genesis(3, 1000, 1000, 1).unwrap();
        let sent = node.send(1, 200, 2).unwrap();

        // Query GetHeaders
        let q_headers = RelayMsg::GetHeaders {
            locator: vec![],
            stop_hash: None,
            max_count: 10,
        };
        let resp = handle_relay_query(&node, &q_headers).unwrap();
        if let RelayMsg::Headers { headers } = resp {
            assert_eq!(headers.len(), 2);
        } else {
            panic!("expected Headers response");
        }

        // Query GetMerkleProof
        let q_proof = RelayMsg::GetMerkleProof {
            block_id: sent.block,
            tx_id: sent.tx,
        };
        let resp = handle_relay_query(&node, &q_proof).unwrap();
        if let RelayMsg::MerkleBlock {
            proof, matched_tx, ..
        } = resp
        {
            assert!(proof.is_some());
            assert!(matched_tx.is_some());
        } else {
            panic!("expected MerkleBlock response");
        }
    }

    #[test]
    fn test_dht_ping_roundtrip() {
        let sender = NodeId::from_bytes([1u8; 32]);
        let nonce = 12345u64;
        let msg = RelayMsg::DhtPing { sender, nonce };
        let encoded = encode_msg(&msg);
        let decoded = decode_msg(&encoded).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_dht_pong_roundtrip() {
        let sender = NodeId::from_bytes([2u8; 32]);
        let nonce = 54321u64;
        let msg = RelayMsg::DhtPong { sender, nonce };
        let encoded = encode_msg(&msg);
        let decoded = decode_msg(&encoded).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_dht_find_node_roundtrip() {
        let sender = NodeId::from_bytes([3u8; 32]);
        let target = NodeId::from_bytes([4u8; 32]);
        let nonce = 99999u64;
        let msg = RelayMsg::DhtFindNode {
            sender,
            target,
            nonce,
        };
        let encoded = encode_msg(&msg);
        let decoded = decode_msg(&encoded).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_dht_nodes_roundtrip() {
        let sender = NodeId::from_bytes([5u8; 32]);
        let target = NodeId::from_bytes([6u8; 32]);
        let nonce = 11111u64;
        let nodes = vec![
            PeerContact::new(NodeId::from_bytes([7u8; 32]), "127.0.0.1:9001".to_string()),
            PeerContact::new(NodeId::from_bytes([8u8; 32]), "127.0.0.1:9002".to_string()),
        ];
        let msg = RelayMsg::DhtNodes {
            sender,
            target,
            nonce,
            nodes,
        };
        let encoded = encode_msg(&msg);
        let decoded = decode_msg(&encoded).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_handle_relay_query_dht_ping() {
        let mut node = Node::new();
        node.genesis(3, 1000, 1000, 1).unwrap();

        let sender = NodeId::from_bytes([1u8; 32]);
        let nonce = 12345u64;
        let q_ping = RelayMsg::DhtPing { sender, nonce };
        let resp = handle_relay_query(&node, &q_ping).unwrap();
        if let RelayMsg::DhtPong {
            sender: s,
            nonce: n,
        } = resp
        {
            assert_eq!(s, sender);
            assert_eq!(n, nonce);
        } else {
            panic!("expected DhtPong response");
        }
    }

    #[test]
    fn test_handle_relay_query_dht_find_node() {
        let mut node = Node::new();
        node.genesis(3, 1000, 1000, 1).unwrap();

        let sender = NodeId::from_bytes([1u8; 32]);
        let target = NodeId::from_bytes([2u8; 32]);
        let nonce = 54321u64;
        let q_find = RelayMsg::DhtFindNode {
            sender,
            target,
            nonce,
        };
        let resp = handle_relay_query(&node, &q_find).unwrap();
        if let RelayMsg::DhtNodes {
            sender: s,
            target: t,
            nonce: n,
            nodes,
        } = resp
        {
            assert_eq!(s, sender);
            assert_eq!(t, target);
            assert_eq!(n, nonce);
            assert!(nodes.is_empty());
        } else {
            panic!("expected DhtNodes response");
        }
    }
}
