//! Long-lived TCP relay: the same envelopes as [`crate::p2p::Mesh`] (hello,
//! block, tx) framed on a **persistent** connection.
//!
//! [`crate::net::serve_blocks`] / [`crate::net::pull_blocks`] write every
//! block and close. A [`RelaySession`] stays open: the caller sends and
//! receives messages for as long as the socket lives. `Node` is not `Send`, so
//! the session itself is only I/O — apply received messages on the thread that
//! owns the node ([`apply_relay`]).

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::time::Duration;

use kovanica_state::{decode_block_payload, encode_block_payload, Transaction};

use crate::net::{decode_one_record, encode_record, NetError};
use crate::node::{BlockRecord, Node};

const TAG_HELLO: u8 = 0;
const TAG_BLOCK: u8 = 1;
const TAG_TX: u8 = 2;
/// Refuse a single frame larger than this (defence against a bogus length).
const MAX_FRAME: usize = 4 * 1024 * 1024;

/// One message on a [`RelaySession`].
#[derive(Clone, Debug)]
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

    /// Bound a blocking [`recv`] so tests (and polite peers) cannot hang forever.
    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> Result<(), NetError> {
        self.stream.set_read_timeout(timeout).map_err(io)
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

/// Apply a received relay message to `node`. Hellos are ignored here — the
/// overlay (not the ledger) owns the peer set; return them to the caller.
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
    }
}

fn io(e: std::io::Error) -> NetError {
    NetError::Io(e.to_string())
}

fn encode_msg(msg: &RelayMsg) -> Vec<u8> {
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
    }
    buf
}

fn decode_msg(bytes: &[u8]) -> Result<RelayMsg, NetError> {
    if bytes.is_empty() {
        return Err(NetError::Decode("empty frame".into()));
    }
    let tag = bytes[0];
    let rest = &bytes[1..];
    match tag {
        TAG_HELLO => {
            let mut r = StrCursor { buf: rest, pos: 0 };
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
        other => Err(NetError::Decode(format!("unknown tag {other}"))),
    }
}

fn push_str(buf: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    buf.extend_from_slice(&(bytes.len() as u16).to_le_bytes());
    buf.extend_from_slice(bytes);
}

struct StrCursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> StrCursor<'a> {
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
