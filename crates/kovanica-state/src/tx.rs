//! Transactions: the payload a block carries, and the unit the ledger applies.
//!
//! The ledger follows the **UTXO** model (as GHOSTDAG's reference system, Kaspa,
//! does). A [`Transaction`] consumes existing unspent outputs by reference
//! ([`OutPoint`]) and creates new ones ([`TxOutput`]). Each spend is authorised
//! by an ed25519 signature (see [`crate::keys`]) carried on its [`TxInput`].
//!
//! A transaction with **no inputs** is a *coinbase* (issuance) transaction: it
//! mints new value under the ledger's subsidy/fee rules (see [`crate::ledger`])
//! rather than consuming existing outputs. Its [`Transaction::tag`] should be
//! unique (e.g. the producing block's height/label) so distinct coinbases have
//! distinct ids.
//!
//! ## Canonical encoding
//!
//! Everything is length-prefixed and little-endian so the encoding is
//! unambiguous and identical on every node (mirroring `kovanica_dag::Block`).
//! A block's payload is a length-prefixed list of transactions — see
//! [`encode_block_payload`] / [`decode_block_payload`], which bridge the ledger
//! to `kovanica_dag`'s opaque block payloads.

use core::fmt;

use crate::keys::{Address, KeyPair};

/// 32-byte BLAKE3 digest identifying a transaction.
///
/// Ordering is over the raw bytes for deterministic tie-breaks.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TxId([u8; 32]);

impl TxId {
    /// Construct a `TxId` from raw bytes (decoding / tests).
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

impl fmt::Debug for TxId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TxId({}…)", &self.to_hex()[..8])
    }
}

impl fmt::Display for TxId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// A reference to one specific output of a previous transaction: the funding
/// transaction's id plus the output's index within it.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct OutPoint {
    /// Id of the transaction that created the referenced output.
    pub tx: TxId,
    /// Index of the output within that transaction.
    pub index: u32,
}

impl OutPoint {
    /// Construct an outpoint.
    pub const fn new(tx: TxId, index: u32) -> Self {
        Self { tx, index }
    }
}

/// A raw 64-byte ed25519 signature. Newtyped so it can carry a readable `Debug`
/// (fixed arrays larger than 32 bytes have none) and a clear domain meaning.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Sig([u8; 64]);

impl Sig {
    /// Wrap raw signature bytes.
    pub const fn from_bytes(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    /// The raw 64 signature bytes.
    pub const fn to_bytes(self) -> [u8; 64] {
        self.0
    }

    /// The all-zero placeholder used before an input is signed.
    pub const fn zero() -> Self {
        Self([0u8; 64])
    }
}

impl fmt::Debug for Sig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Sig({}…)", &hex::encode(self.0)[..8])
    }
}

/// A spend: which previous output is being consumed, and the signature
/// authorising it. The signature is over the transaction's [`Transaction::sighash`]
/// and must verify against the spent output's owning [`Address`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TxInput {
    /// The previous output being spent.
    pub outpoint: OutPoint,
    /// Signature authorising the spend.
    pub signature: Sig,
}

/// A newly created output: an amount and the address that may later spend it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TxOutput {
    /// The value locked in this output.
    pub value: u64,
    /// The address that owns (may spend) this output.
    pub owner: Address,
}

impl TxOutput {
    /// Construct an output.
    pub const fn new(value: u64, owner: Address) -> Self {
        Self { value, owner }
    }
}

/// A transaction: it spends the outputs named by `inputs` and creates `outputs`.
///
/// An empty `inputs` marks a coinbase (issuance) transaction. `tag` is extra
/// committed bytes — for a coinbase it also disambiguates the id (see the module
/// docs) and can carry the producing block's height/label.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Transaction {
    inputs: Vec<TxInput>,
    outputs: Vec<TxOutput>,
    tag: Vec<u8>,
}

impl Transaction {
    /// A coinbase (issuance) transaction: no inputs, the given outputs and tag.
    ///
    /// The `tag` should be unique per coinbase (e.g. the block height/label) so
    /// two coinbases do not collide on id.
    pub fn coinbase(outputs: Vec<TxOutput>, tag: Vec<u8>) -> Self {
        Self {
            inputs: Vec::new(),
            outputs,
            tag,
        }
    }

    /// Build a signed transaction spending `spends` (each an outpoint plus the
    /// keypair that owns it) to produce `outputs`.
    ///
    /// The signature hash covers the inputs' outpoints, the outputs, and the tag
    /// — but not the signatures themselves — so signing has no circular
    /// dependency and every input signs the same hash.
    pub fn signed(spends: &[(OutPoint, &KeyPair)], outputs: Vec<TxOutput>, tag: Vec<u8>) -> Self {
        let inputs = spends
            .iter()
            .map(|(outpoint, _)| TxInput {
                outpoint: *outpoint,
                signature: Sig::zero(),
            })
            .collect();
        let mut tx = Self {
            inputs,
            outputs,
            tag,
        };
        let sighash = tx.sighash();
        for (i, (_, keypair)) in spends.iter().enumerate() {
            tx.inputs[i].signature = Sig::from_bytes(keypair.sign(&sighash));
        }
        tx
    }

    /// An unsigned spend: signatures are zeroed. The wallet signs
    /// [`sighash`](Self::sighash) and attaches the result with
    /// [`attach_signature`](Self::attach_signature).
    pub fn unsigned(outpoints: &[OutPoint], outputs: Vec<TxOutput>, tag: Vec<u8>) -> Self {
        Self {
            inputs: outpoints
                .iter()
                .map(|outpoint| TxInput {
                    outpoint: *outpoint,
                    signature: Sig::zero(),
                })
                .collect(),
            outputs,
            tag,
        }
    }

    /// Attach a signature to input `index`. Used by a wallet that signed
    /// [`sighash`](Self::sighash) off-node.
    pub fn attach_signature(&mut self, index: usize, signature: Sig) {
        if let Some(input) = self.inputs.get_mut(index) {
            input.signature = signature;
        }
    }

    /// The transaction's inputs (empty for a coinbase).
    pub fn inputs(&self) -> &[TxInput] {
        &self.inputs
    }

    /// The transaction's outputs.
    pub fn outputs(&self) -> &[TxOutput] {
        &self.outputs
    }

    /// The transaction's tag bytes.
    pub fn tag(&self) -> &[u8] {
        &self.tag
    }

    /// Whether this is a coinbase (issuance) transaction — it has no inputs.
    pub fn is_coinbase(&self) -> bool {
        self.inputs.is_empty()
    }

    /// Serialise into `buf`. With `with_signatures` the per-input signatures are
    /// included (used for the id); without, the result is the signature preimage
    /// (used for the sighash).
    fn encode_into(&self, buf: &mut Vec<u8>, with_signatures: bool) {
        buf.extend_from_slice(&(self.inputs.len() as u64).to_le_bytes());
        for input in &self.inputs {
            buf.extend_from_slice(input.outpoint.tx.as_bytes());
            buf.extend_from_slice(&input.outpoint.index.to_le_bytes());
            if with_signatures {
                buf.extend_from_slice(&input.signature.0);
            }
        }
        buf.extend_from_slice(&(self.outputs.len() as u64).to_le_bytes());
        for output in &self.outputs {
            buf.extend_from_slice(&output.value.to_le_bytes());
            buf.extend_from_slice(output.owner.as_bytes());
        }
        buf.extend_from_slice(&(self.tag.len() as u64).to_le_bytes());
        buf.extend_from_slice(&self.tag);
    }

    /// The canonical byte encoding (including signatures).
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.encode_into(&mut buf, true);
        buf
    }

    /// The signature hash: BLAKE3 over the signature-free encoding. Inputs sign
    /// this, and it is what [`crate::keys::verify`] checks each spend against.
    pub fn sighash(&self) -> [u8; 32] {
        let mut buf = Vec::new();
        self.encode_into(&mut buf, false);
        *blake3::hash(&buf).as_bytes()
    }

    /// The transaction id: BLAKE3 over the full (signed) encoding.
    pub fn id(&self) -> TxId {
        TxId(*blake3::hash(&self.encode()).as_bytes())
    }
}

/// Errors from decoding a block payload back into transactions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// The input ended before a fully-formed value could be read.
    UnexpectedEof,
    /// Bytes remained after decoding the declared number of transactions.
    TrailingBytes,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecodeError::UnexpectedEof => f.write_str("unexpected end of payload"),
            DecodeError::TrailingBytes => f.write_str("trailing bytes after payload"),
        }
    }
}

impl std::error::Error for DecodeError {}

/// Encode a list of transactions as a block payload: a length prefix followed by
/// each transaction's canonical encoding. Feed the result to
/// `kovanica_dag::Block`'s opaque `payload`.
pub fn encode_block_payload(txs: &[Transaction]) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&(txs.len() as u64).to_le_bytes());
    for tx in txs {
        tx.encode_into(&mut buf, true);
    }
    buf
}

/// Decode a block payload produced by [`encode_block_payload`].
pub fn decode_block_payload(bytes: &[u8]) -> Result<Vec<Transaction>, DecodeError> {
    let mut reader = Reader::new(bytes);
    // Smallest transaction encoding is three empty length prefixes = 24 bytes.
    let count = reader.read_count(24)?;
    let mut txs = Vec::with_capacity(count);
    for _ in 0..count {
        txs.push(reader.read_transaction()?);
    }
    if reader.remaining() != 0 {
        return Err(DecodeError::TrailingBytes);
    }
    Ok(txs)
}

/// A minimal, bounds-checked cursor over the payload bytes.
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

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
        if self.remaining() < N {
            return Err(DecodeError::UnexpectedEof);
        }
        let mut out = [0u8; N];
        out.copy_from_slice(&self.buf[self.pos..self.pos + N]);
        self.pos += N;
        Ok(out)
    }

    fn read_u32(&mut self) -> Result<u32, DecodeError> {
        Ok(u32::from_le_bytes(self.read_array::<4>()?))
    }

    fn read_u64(&mut self) -> Result<u64, DecodeError> {
        Ok(u64::from_le_bytes(self.read_array::<8>()?))
    }

    /// Read a length prefix, rejecting counts that cannot fit even at
    /// `min_element_bytes` each — so malformed input can't request a giant
    /// allocation before the bytes run out.
    fn read_count(&mut self, min_element_bytes: usize) -> Result<usize, DecodeError> {
        let n = self.read_u64()? as usize;
        if min_element_bytes > 0 && n > self.remaining() / min_element_bytes {
            return Err(DecodeError::UnexpectedEof);
        }
        Ok(n)
    }

    fn read_transaction(&mut self) -> Result<Transaction, DecodeError> {
        // Each input is 32 (tx) + 4 (index) + 64 (sig) = 100 bytes.
        let n_inputs = self.read_count(100)?;
        let mut inputs = Vec::with_capacity(n_inputs);
        for _ in 0..n_inputs {
            let tx = TxId::from_bytes(self.read_array::<32>()?);
            let index = self.read_u32()?;
            let signature = Sig::from_bytes(self.read_array::<64>()?);
            inputs.push(TxInput {
                outpoint: OutPoint { tx, index },
                signature,
            });
        }
        // Each output is 8 (value) + 32 (owner) = 40 bytes.
        let n_outputs = self.read_count(40)?;
        let mut outputs = Vec::with_capacity(n_outputs);
        for _ in 0..n_outputs {
            let value = self.read_u64()?;
            let owner = Address::from_bytes(self.read_array::<32>()?);
            outputs.push(TxOutput { value, owner });
        }
        let tag_len = self.read_count(1)?;
        let tag = self.read_array_dyn(tag_len)?;
        Ok(Transaction {
            inputs,
            outputs,
            tag,
        })
    }

    fn read_array_dyn(&mut self, len: usize) -> Result<Vec<u8>, DecodeError> {
        if self.remaining() < len {
            return Err(DecodeError::UnexpectedEof);
        }
        let out = self.buf[self.pos..self.pos + len].to_vec();
        self.pos += len;
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(seed: u64) -> Address {
        KeyPair::from_u64(seed).address()
    }

    #[test]
    fn id_and_sighash_are_deterministic() {
        let kp = KeyPair::from_u64(1);
        let op = OutPoint::new(TxId::from_bytes([9u8; 32]), 0);
        let tx = Transaction::signed(&[(op, &kp)], vec![TxOutput::new(5, addr(2))], b"t".to_vec());
        assert_eq!(tx.id(), tx.id());
        assert_eq!(tx.sighash(), tx.sighash());
    }

    #[test]
    fn sighash_ignores_signatures() {
        // Two transactions identical but for their signatures must share a
        // sighash (signatures sign the sighash, not vice-versa) yet differ in id.
        let op = OutPoint::new(TxId::from_bytes([1u8; 32]), 0);
        let a = Transaction::signed(&[(op, &KeyPair::from_u64(1))], vec![], b"x".to_vec());
        // Re-sign the same logical spend with a different key: same sighash input.
        let b = Transaction::signed(&[(op, &KeyPair::from_u64(2))], vec![], b"x".to_vec());
        assert_eq!(a.sighash(), b.sighash());
    }

    #[test]
    fn payload_roundtrips() {
        let kp = KeyPair::from_u64(1);
        let op = OutPoint::new(TxId::from_bytes([7u8; 32]), 3);
        let coinbase = Transaction::coinbase(vec![TxOutput::new(50, addr(1))], b"h0".to_vec());
        let transfer = Transaction::signed(
            &[(op, &kp)],
            vec![TxOutput::new(20, addr(2)), TxOutput::new(30, addr(3))],
            Vec::new(),
        );
        let txs = vec![coinbase, transfer];
        let bytes = encode_block_payload(&txs);
        assert_eq!(decode_block_payload(&bytes).unwrap(), txs);
    }

    #[test]
    fn empty_payload_roundtrips() {
        let bytes = encode_block_payload(&[]);
        assert_eq!(
            decode_block_payload(&bytes).unwrap(),
            Vec::<Transaction>::new()
        );
    }

    #[test]
    fn truncated_payload_is_rejected() {
        let tx = Transaction::coinbase(vec![TxOutput::new(1, addr(1))], b"h".to_vec());
        let mut bytes = encode_block_payload(&[tx]);
        bytes.truncate(bytes.len() - 1);
        assert_eq!(
            decode_block_payload(&bytes),
            Err(DecodeError::UnexpectedEof)
        );
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        let mut bytes = encode_block_payload(&[]);
        bytes.push(0);
        assert_eq!(
            decode_block_payload(&bytes),
            Err(DecodeError::TrailingBytes)
        );
    }
}
